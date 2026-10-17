#!/usr/bin/env bash
#
# Exercise the setuid sudo-rs binaries on macOS, which the Docker-based test framework
# cannot do. This needs an account that can run Apple's sudo without a password, as on CI
# runners, and changes the system while it runs: only use it on a disposable machine.
#
# usage: util/test-macos-native.sh [directory with the sudo, su and visudo binaries]

set -u

bin=${1:-target/release}
dir=/private/var/sudo-rs-test
me=$(id -un)
groups=20
errors=$(mktemp) # the user's own, unlike anything in $dir

passed=0
failed=0
check() { # description expected observed
    if [ "$2" = "$3" ]; then
        passed=$((passed + 1))
        echo "PASS  $1"
    else
        failed=$((failed + 1))
        echo "FAIL  $1: expected [$2], observed [$3]"
    fi
}

cleanup() {
    rm -f "$errors"
    sudo rm -rf "$dir"
    sudo rm -f /etc/sudoers-rs
    for i in $(seq $groups); do
        sudo dseditgroup -o delete -n . "sudors$i" 2>/dev/null
    done
}
trap cleanup EXIT

# --- setup: the binaries, a policy, and fixtures that only root can change (`sudo` is Apple's)
sudo mkdir -p "$dir/bin" "$dir/edit"
sudo install -o root -g wheel -m 4755 "$bin/sudo" "$bin/su" "$dir/bin/"
sudo install -o root -g wheel -m 755 "$bin/visudo" "$dir/bin/"
sudo_rs=$dir/bin/sudo

printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$me" | sudo tee /etc/sudoers-rs >/dev/null
sudo chmod 440 /etc/sudoers-rs

# make the invoking user a member of more groups than a credential holds, each guarding a file
for i in $(seq $groups); do
    sudo dseditgroup -o create -n . -r "sudo-rs test" "sudors$i" >/dev/null
    sudo dseditgroup -o edit -n . -a "$me" -t user "sudors$i"
    printf 'ok\n' | sudo tee "$dir/group$i" >/dev/null
    sudo chown "root:sudors$i" "$dir/group$i"
    sudo chmod 640 "$dir/group$i"
done
dscacheutil -flushcache

# --- identities
check "runs a command as root" 0 "$("$sudo_rs" -n id -u)"
check "runs a command as another user, and switches back to root to do so" \
    nobody "$("$sudo_rs" -n -u nobody id -un)"
check "the user is in more groups than a credential caches" yes \
    "$([ $(($(id -G "$me" | wc -w))) -gt 16 ] && echo yes || echo no)"
check "an account keeps all of its groups, not just those that fit the credential" "$groups" \
    "$("$sudo_rs" -n -u "$me" sh -c "cat $dir/group* | grep -c ok")"
check "su -g/-G gives exactly the groups requested" "ok denied" \
    "$(sudo "$dir/bin/su" -g staff -G sudors1 -s /bin/sh "$me" -c \
        "cat $dir/group1; cat $dir/group2 2>/dev/null || echo denied" | tr '\n' ' ' | sed 's/ $//')"

# The PAM stack of su asks Open Directory about the account (pam_opendirectory, pam_launchd)
# right before the command process is forked, which then installs the account's groups. Should
# that look anything up again, it could hang, so repeat it under a watchdog.
hung=0 wrong=0
for _ in $(seq 50); do
    found=$(perl -e 'alarm shift; exec @ARGV or die' 20 \
        sudo "$dir/bin/su" -s /bin/sh "$me" -c "cat $dir/group* | grep -c ok")
    case $? in
        0) [ "$found" = "$groups" ] || wrong=$((wrong + 1)) ;;
        142) hung=$((hung + 1)) ;; # SIGALRM
        *) wrong=$((wrong + 1)) ;;
    esac
done
check "su installs all of an account's groups after PAM, 50 times without hanging" \
    "0 hung, 0 wrong" "$hung hung, $wrong wrong"

# --- the command's environment
exec 9</etc/hosts
check "descriptors beyond stdio are not inherited" isolated \
    "$("$sudo_rs" -n sh -c '[ -e /dev/fd/9 ] && echo leaked || echo isolated')"
exec 9<&-
check "the command runs in a pty of its own" /dev/ttys \
    "$(script -q /dev/null "$sudo_rs" -n tty </dev/null | grep -o '/dev/ttys' | head -1)"
"$sudo_rs" -n -b sh -c "echo ran > $dir/background"
for _ in $(seq 50); do [ -s "$dir/background" ] && break; sleep 0.1; done
check "runs a command in the background" ran "$(cat "$dir/background" 2>/dev/null)"

# --- sudoedit
editor=$dir/editor
# shellcheck disable=SC2016 # the editor overwrites the file it is given
printf '#!/bin/sh\necho edited > "$1"\n' | sudo tee "$editor" >/dev/null
sudo chmod 755 "$editor"
printf 'original\n' | sudo tee "$dir/edit/file" >/dev/null

SUDO_EDITOR=$editor "$sudo_rs" -n -e "$dir/edit/file" 2>/dev/null
check "sudoedit edits a file the user cannot change" edited "$(cat "$dir/edit/file")"

# sudoedit must refuse exactly the paths that the user could change. For each access control
# entry, compare what sudoedit does with what the kernel lets the user do: refuse if the probe
# succeeds as the user, edit the file otherwise.
acl=$dir/acl
acl_case() { # description object(dir|file|new file) entries probe kernel-answer(can|cannot)
    sudo rm -rf "$acl"
    sudo mkdir -m 755 "$acl"
    sudo touch "$acl/victim"
    [ "$2" = "new file" ] || printf 'original\n' | sudo tee "$acl/file" >/dev/null
    # chmod -E keeps the entries in the order given, which is the order the kernel checks them in
    case $2 in
        file) printf '%s\n' "$3" | sudo /bin/chmod -E "$acl/file" ;;
        *) printf '%s\n' "$3" | sudo /bin/chmod -E "$acl" ;;
    esac
    # created after the entry, so that it inherits what the entry passes on
    [ "$2" = "new file" ] && printf 'original\n' | sudo tee "$acl/file" >/dev/null

    SUDO_EDITOR=$editor "$sudo_rs" -n -e "$acl/file" 2>"$errors"
    status=$? content=$(cat "$acl/file")
    if [ $status -ne 0 ] && [ "$content" = original ] &&
        grep -q 'path writable by the user' "$errors"; then
        decision=refused
    elif [ $status -eq 0 ] && [ "$content" = edited ]; then
        decision=edited
    else
        decision="status $status, content $content: $(tr '\n' ' ' <"$errors")"
    fi

    # Only now does the user try the change, which may well succeed.
    sh -c "$4" >/dev/null 2>&1 && kernel=can || kernel=cannot
    [ "$5" = can ] && expected=refused || expected=edited
    check "sudoedit, $1" "$expected; the user $5 change it" "$decision; the user $kernel change it"
}
acl_case "directory entry add_file" dir "$me allow add_file" "touch $acl/probe" can
acl_case "directory entry add_subdirectory" dir "$me allow add_subdirectory" "mkdir $acl/probe" can
acl_case "directory entry delete_child" dir "$me allow delete_child" "rm -f $acl/victim" can
acl_case "directory entry writesecurity" dir "$me allow writesecurity" \
    "/bin/chmod +a '$me allow add_file' $acl" can
acl_case "directory entry chown" dir "$me allow chown" "chown $me $acl" can
acl_case "directory entries list, search, readattr" dir "$me allow list,search,readattr" \
    "touch $acl/probe" cannot
acl_case "directory entries deny add_file, then allow it" dir \
    "$me deny add_file"$'\n'"$me allow add_file" "touch $acl/probe" cannot
acl_case "directory entries allow add_file, then deny it" dir \
    "$me allow add_file"$'\n'"$me deny add_file" "touch $acl/probe" can
acl_case "directory entry add_file for new files only" dir "$me allow add_file,only_inherit" \
    "touch $acl/probe" cannot
acl_case "file entry write inherited from the directory" "new file" \
    "$me allow write,file_inherit,only_inherit" "printf x > $acl/file" can
acl_case "file entry write" file "$me allow write" "printf x > $acl/file" can
acl_case "file entry append" file "$me allow append" "printf x >> $acl/file" can
acl_case "file entry delete" file "$me allow delete" "rm -f $acl/file" can
acl_case "file entry writesecurity" file "$me allow writesecurity" \
    "/bin/chmod +a '$me allow write' $acl/file" can
acl_case "file entry chown" file "$me allow chown" "chown $me $acl/file" can
acl_case "file entries read, readattr, readsecurity" file "$me allow read,readattr,readsecurity" \
    "printf x > $acl/file" cannot

# --- the stock configuration
check "visudo accepts the sudoers file that macOS ships" 0 \
    "$(sudo "$dir/bin/visudo" -c -f /etc/sudoers >/dev/null 2>&1; echo $?)"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
