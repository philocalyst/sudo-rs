#!/bin/sh
# Only for an explicitly disposable macOS or NetBSD machine. Never installs globally.
set -eu
cases='P4 root and non-root real/effective IDs
P4 target cannot regain root
P4 explicit primary and supplementary groups
P4 account membership beyond sixteen groups
P1 low and high descriptors do not survive sudo exec
P3 sudoedit accepts a protected file
P3 sudoedit refuses symlinks and writable parents
P3 Darwin ACL modification rights compared with actual operations
P6 correct and incorrect passwords through system PAM
P2/P5 parent-scoped ticket reuse and sudo -k invalidation
P2/P7 command pty and initial window size
A2 unsupported NOEXEC foreground/background refusal
P7 exit status and signal forwarding
A3 stock sudoers parsing'
case ${1:-} in
    --list)
        echo 'Implemented: unprivileged watchdog exit/signal/deadline tests.'
        echo 'Planned privileged cases (execution disabled pending external VM teardown):'
        printf '%s\n' "$cases"
        exit 0
        ;;
    --disposable)
        echo 'privileged execution disabled: requires externally supervised disposable VM destruction' >&2
        exit 2
        ;;
    *) echo 'usage: run.sh --list | --disposable' >&2; exit 2 ;;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$root"
# Fail before any privileged mutation on the original experiment branch.
if ! grep -F 'option_env!("SUDO_RS_SUDOERS_PATH")' src/sudo/mod.rs >/dev/null; then
    echo 'requires upstream d856ce05 (compile-time SUDO_RS_SUDOERS_PATH); no setup performed' >&2
    exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo 'disposable-host execution requires root' >&2; exit 2; }
os=$(uname -s)
case $os in Darwin|NetBSD) ;; *) echo 'only Darwin and NetBSD are supported' >&2; exit 2 ;; esac
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/pkg/bin:/usr/pkg/sbin
export LC_ALL=C
export SUDO_RS_IS_UNSTABLE='I accept that my system may break unexpectedly'
cargo=${CARGO:-cargo}
command -v "$cargo" >/dev/null
umask 077
stage=$(mktemp -d /var/run/sudo-rs-native.XXXXXXXX)
stage=$(CDPATH= cd "$stage" && pwd -P)
users=''
groups=''
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    # Revoke privilege before cleaning any other resource, even after a test failure.
    if [ -d "$stage/bin" ]; then chmod -R u-s,g-s "$stage/bin" || result=1; fi
    for user in $users; do
        case $os in
            Darwin) dscl . -delete "/Users/$user" || result=1 ;;
            NetBSD) userdel "$user" || result=1 ;;
        esac
    done
    for group in $groups; do
        case $os in
            Darwin) dscl . -delete "/Groups/$group" || result=1 ;;
            NetBSD) groupdel "$group" || result=1 ;;
        esac
    done
    # Only this run's newly allocated account has timestamp files removed.
    if [ -n "${caller_uid:-}" ]; then
        rm -f "/var/run/sudo-rs/ts/$caller_uid" "/var/db/sudo-rs/ts/$caller_uid" || result=1
    fi
    rm -rf "$stage" || result=1
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir "$stage/bin" "$stage/policy" "$stage/edit"
chmod 755 "$stage" "$stage/bin" "$stage/policy" "$stage/edit"
export CARGO_TARGET_DIR="$stage/target"
export SUDO_RS_SUDOERS_PATH="$stage/policy"
"$cargo" build --bins
"$cargo" build --manifest-path test-framework/native-tests/Cargo.toml
install -m 755 "$stage/target/debug/sudo-native-probe" "$stage/bin/probe"
install -m 4755 "$stage/target/debug/sudo" "$stage/target/debug/su" "$stage/bin/"
install -m 755 "$stage/target/debug/visudo" "$stage/bin/"
probe=$stage/bin/probe
sudo_rs=$stage/bin/sudo
su_rs=$stage/bin/su
password=NativeTestPassword123
next_id=60000
free_id() {
    while :; do
        next_id=$((next_id + 1))
        if id -u "$next_id" >/dev/null 2>&1; then continue; fi
        if [ -e "/var/run/sudo-rs/ts/$next_id" ] || [ -e "/var/db/sudo-rs/ts/$next_id" ]; then continue; fi
        case $os in
            Darwin) test -z "$(dscl . -search /Groups PrimaryGroupID "$next_id")" || continue ;;
            NetBSD) if getent group "$next_id" >/dev/null 2>&1; then continue; fi ;;
        esac
        break
    done
}
new_group() {
    name=$1
    free_id
    group_id=$next_id
    case $os in
        Darwin)
            if dscl . -read "/Groups/$name" >/dev/null 2>&1; then exit 2; fi
            groups="$name $groups"
            dscl . -create "/Groups/$name"
            dscl . -create "/Groups/$name" PrimaryGroupID "$group_id"
            dscl . -create "/Groups/$name" GeneratedUID "$(uuidgen)"
            ;;
        NetBSD)
            if getent group "$name" >/dev/null 2>&1; then exit 2; fi
            groupadd -g "$group_id" "$name"
            groups="$name $groups"
            ;;
    esac
}
new_user() {
    name=$1
    free_id
    user_id=$next_id
    if id -u "$name" >/dev/null 2>&1; then exit 2; fi
    case $os in
        Darwin)
            users="$name $users"
            dscl . -create "/Users/$name"
            dscl . -create "/Users/$name" UniqueID "$user_id"
            dscl . -create "/Users/$name" PrimaryGroupID "$primary_gid"
            dscl . -create "/Users/$name" GeneratedUID "$(uuidgen)"
            dscl . -create "/Users/$name" NFSHomeDirectory "$stage"
            dscl . -create "/Users/$name" UserShell /bin/sh
            dscl . -passwd "/Users/$name" "$password"
            ;;
        NetBSD)
            hash=$(printf '%s\n' "$password" | pwhash)
            useradd -u "$user_id" -g "$primary_gid" -d "$stage" -s /bin/sh -p "$hash" "$name"
            users="$name $users"
            ;;
    esac
}
new_group "srnp$$"
primary_gid=$group_id
new_user "srnc$$"
caller=$name
caller_uid=$user_id
new_user "srnt$$"
target=$name
target_uid=$user_id
# Fixtures use a fresh account, never modify an existing user's memberships.
i=1
supp_names=''
while [ "$i" -le 20 ]; do
    new_group "srn$$g$i"
    case $os in
        Darwin) dscl . -append "/Groups/$name" GroupMembership "$target" ;;
        NetBSD) supp_names=${supp_names:+$supp_names,}$name ;;
    esac
    printf 'group-%s\n' "$i" > "$stage/group$i"
    chown "0:$group_id" "$stage/group$i"
    chmod 640 "$stage/group$i"
    if [ "$i" -eq 1 ]; then group_one=$name; gid_one=$group_id; fi
    if [ "$i" -eq 2 ]; then group_two=$name; gid_two=$group_id; fi
    i=$((i + 1))
done
if [ "$os" = NetBSD ]; then usermod -G "$supp_names" "$target"; fi
printf '#!/bin/sh\nprintf "edited\\n" > "$1"\n' > "$stage/editor"
chmod 755 "$stage/editor"
export SUDO_EDITOR=$stage/editor
policy() {
    printf 'Defaults !lecture, passwd_tries=1, timestamp_type=ppid\n%s ALL=(ALL:ALL) %s ALL\n' "$caller" "$1" > "$stage/policy/sudoers-rs"
    chmod 440 "$stage/policy/sudoers-rs"
}
policy NOPASSWD:
passed=0
failed=0
capture() {
    if "$@" > "$stage/out" 2> "$stage/err"; then status=0; else status=$?; fi
}
check() {
    label=$1 expected=$2 observed=$3
    if [ "$expected" = "$observed" ]; then
        passed=$((passed + 1)); printf 'PASS %s\n' "$label"
    else
        failed=$((failed + 1)); printf 'FAIL %s: expected [%s], got [%s]\n' "$label" "$expected" "$observed"
        cat "$stage/err" >&2
    fi
}
invoke() { "$probe" as "$caller_uid" "$primary_gid" 15 "$@"; }
capture invoke "$probe" ids
check 'control: invoking identity' "$caller_uid $caller_uid $primary_gid $primary_gid" "$(cat "$stage/out")"
capture invoke "$sudo_rs" -n "$probe" ids
check 'P4 command real/effective root IDs' '0 0 0 0' "$(cat "$stage/out")"
capture invoke "$sudo_rs" -n -u "$caller" "$probe" ids
check 'P4 command target IDs' "$caller_uid $caller_uid $primary_gid $primary_gid" "$(cat "$stage/out")"
capture invoke "$sudo_rs" -n -u "$caller" "$probe" no-root
check 'P4 target cannot recover saved root' 'cannot regain root' "$(cat "$stage/out")"
for fd in 9 1000; do
    capture invoke "$probe" plant-fds "$probe" fd "$fd"
    check "P1 control descriptor $fd inherited" open "$(cat "$stage/out")"
    capture invoke "$probe" plant-fds "$sudo_rs" -n "$probe" fd "$fd"
    check "P1 descriptor $fd closed by sudo" closed "$(cat "$stage/out")"
done
capture invoke "$sudo_rs" -n /bin/sh -c 'exit 42'
check 'P7 exit status forwarded' 42 "$status"
capture invoke "$sudo_rs" -n "$probe" signal
check 'P7 terminating signal forwarded' 143 "$status"
capture "$probe" pty "$caller_uid" "$primary_gid" 15 "$probe" tty
check 'control: native terminal dimensions' '24 80' "$(tr -d '\r' < "$stage/out")"
capture "$probe" pty "$caller_uid" "$primary_gid" 15 "$sudo_rs" -n "$probe" tty
check 'P2/P7 sudo command pty dimensions' '24 80' "$(tr -d '\r' < "$stage/out")"
# Read every group-protected file, not merely the truncated getgroups cache.
capture invoke "$sudo_rs" -n -u "$target" /bin/sh -c "cat '$stage'/group*"
case $os in
    Darwin) check 'P4 all twenty account groups authorize access' 20 "$(wc -l < "$stage/out" | tr -d ' ')" ;;
    NetBSD) check 'P4 oversized account credential refuses execution' 1 "$status" ;;
esac
capture "$probe" as 0 0 15 "$su_rs" -g "$group_one" -G "$group_two" -s /bin/sh "$target" -c "$probe groups"
check 'P4 explicit su group list is exact' "$gid_one $gid_two" "$(cat "$stage/out")"
printf 'original\n' > "$stage/edit/file"
chmod 444 "$stage/edit/file"
capture invoke "$sudo_rs" -n -e "$stage/edit/file"
check 'P3 protected file can be edited' edited "$(cat "$stage/edit/file")"
printf 'original\n' > "$stage/edit/file"
ln -s file "$stage/edit/link"
capture invoke "$sudo_rs" -n -e "$stage/edit/link"
check 'P3 symlink is refused' 1 "$status"
check 'P3 symlink target unchanged' original "$(cat "$stage/edit/file")"
chmod 777 "$stage/edit"
capture invoke "$sudo_rs" -n -e "$stage/edit/file"
check 'P3 writable ancestor is refused' 1 "$status"
check 'P3 refused edit target unchanged' original "$(cat "$stage/edit/file")"
chmod 755 "$stage/edit"
if [ "$os" = Darwin ]; then
    for right in write append delete writesecurity chown; do
        printf 'original\n' > "$stage/edit/file"
        chmod -N "$stage/edit/file"
        chmod 444 "$stage/edit/file"
        chmod +a "user:$caller allow $right" "$stage/edit/file"
        capture invoke "$sudo_rs" -n -e "$stage/edit/file"
        edit_status=$status
        unchanged=$(cat "$stage/edit/file")
        case $right in
            write) operation="printf oracle > '$stage/edit/file'" ;;
            append) operation="printf oracle >> '$stage/edit/file'" ;;
            delete) operation="rm '$stage/edit/file'" ;;
            writesecurity) operation="chmod 600 '$stage/edit/file'" ;;
            chown) operation="chown $caller_uid '$stage/edit/file'" ;;
        esac
        capture invoke /bin/sh -c "$operation"
        check "P3 kernel permits ACL $right control" 0 "$status"
        check "P3 sudoedit refuses ACL $right" 1 "$edit_status"
        check "P3 ACL $right refusal leaves contents unchanged" original "$unchanged"
        rm -f "$stage/edit/file"
    done
fi
policy PASSWD:
capture invoke "$sudo_rs" -k
capture invoke "$sudo_rs" -n /usr/bin/true
check 'P6 uncached noninteractive authentication refuses' 1 "$status"
# Each authentication input is a pipe, with the helper bounding the whole process group.
printf 'wrong-password\n' > "$stage/password"
capture invoke "$sudo_rs" -S -k /usr/bin/true < "$stage/password"
check 'P6 wrong password refuses' 1 "$status"
printf '%s\n' "$password" > "$stage/password"
capture invoke "$sudo_rs" -S -k /usr/bin/true < "$stage/password"
check 'P6 correct password authenticates' 0 "$status"
# Keep the same parent in one helper invocation for ppid-scoped timestamps.
capture invoke /bin/sh -c "printf '%s\\n' '$password' | '$sudo_rs' -S -k /usr/bin/true && '$sudo_rs' -n /usr/bin/true && '$sudo_rs' -k && ! '$sudo_rs' -n /usr/bin/true"
check 'P2/P5 same-parent ticket reused and invalidated' 0 "$status"
policy 'NOEXEC: NOPASSWD:'
for background in '' -b; do
    capture invoke "$sudo_rs" -n $background /usr/bin/true
    check "A2 unsupported NOEXEC $background refuses before command" 1 "$status"
done
# The stock policy check is deliberately separate from isolated test policy parsing.
case $os in Darwin) stock=/etc/sudoers ;; NetBSD) stock=/usr/pkg/etc/sudoers ;; esac
capture "$stage/bin/visudo" -c -f "$stock"
check 'A3 stock sudoers parses' 0 "$status"
printf '%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
