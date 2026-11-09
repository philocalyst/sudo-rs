#!/bin/bash
# Exercise the native setuid/PAM paths without replacing Apple's sudo or changing sudoers.
set -euo pipefail

if [[ $(uname -s) != Darwin || $(id -u) == 0 ]]; then
    echo "Run this script as a regular macOS administrator account." >&2
    exit 1
fi

project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
bin_dir=""
test_bin=""
non_interactive=false
while (($#)); do
    case "$1" in
        --bin-dir) bin_dir=$2; shift 2 ;;
        --test-bin) test_bin=$2; shift 2 ;;
        --non-interactive) non_interactive=true; shift ;;
        *) echo "Usage: $0 [--bin-dir DIR] [--test-bin FILE] [--non-interactive]" >&2; exit 2 ;;
    esac
done
if [[ -z $test_bin ]]; then
    test_bin=$(cd -- "$project_dir" && cargo test --offline --locked --lib --release --no-run --message-format=json | python3 -c '
import json, sys
for line in sys.stdin:
    item = json.loads(line)
    if item.get("reason") == "compiler-artifact" and item.get("profile", {}).get("test") and item.get("executable"):
        print(item["executable"])
')
fi
[[ -x $test_bin ]] || { echo "Missing native credential test binary: $test_bin" >&2; exit 1; }
if [[ -z $bin_dir ]]; then
    (cd -- "$project_dir" && cargo build --offline --locked --release --bins)
    bin_dir="${CARGO_TARGET_DIR:-target}"
    case "$bin_dir" in /*) ;; *) bin_dir="$project_dir/$bin_dir" ;; esac
    bin_dir="$bin_dir/release"
fi
bin_dir=$(cd -- "$bin_dir" && pwd -P)
for binary in sudo su visudo; do
    [[ -x $bin_dir/$binary ]] || { echo "Missing binary: $bin_dir/$binary" >&2; exit 1; }
done

native_sudo=/usr/bin/sudo
authenticate() {
    if $non_interactive; then "$1" -n -v; else "$1" -v; fi
}
printf 'Authenticate with Apple sudo to stage the native tests.\n'
authenticate "$native_sudo"
stage=$("$native_sudo" -n /usr/bin/mktemp -d /private/var/run/sudo-rs-native.XXXXXX)
scratch=$(mktemp -d)
cleanup() {
    rm -rf -- "$scratch"
    case "$stage" in
        /private/var/run/sudo-rs-native.*) "$native_sudo" -n /bin/rm -rf -- "$stage" ;;
    esac
}
trap cleanup EXIT
"$native_sudo" -n /bin/chmod 755 "$stage"
for binary in sudo su; do
    "$native_sudo" -n /usr/bin/install -o root -g wheel -m 4755 "$bin_dir/$binary" "$stage/$binary"
done
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 755 "$bin_dir/visudo" "$stage/visudo"
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 755 "$test_bin" "$stage/credential-tests"
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 755 "$project_dir/util/test-macos-pty.py" "$stage/pty-probe.py"
printf 'Staged binary SHA-256 fingerprints:\n'
/usr/bin/shasum -a 256 "$stage/sudo" "$stage/su" "$stage/visudo" "$stage/credential-tests"
"$native_sudo" -n /usr/bin/env SUDO_RS_TEST_USER="$(id -un)" "$stage/credential-tests" \
    --ignored --exact system::macos::tests::privileged_credentials_round_trip

cat > "$scratch/editor" <<'EDITOR'
#!/bin/sh
for file do printf '\nsudo-rs-native-edit\n' >> "$file"; done
EDITOR
printf 'original\n' > "$scratch/edit-target"
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 755 "$scratch/editor" "$stage/editor"
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 644 "$scratch/edit-target" "$stage/edit-target"

tested=$stage/sudo
invoking_user=$(id -un)
invoking_uid=$(id -u)
assert_equal() {
    if [[ $1 != "$2" ]]; then
        printf 'FAIL %s: expected <%s>, got <%s>\n' "$3" "$1" "$2" >&2
        exit 1
    fi
    printf 'PASS %s\n' "$3"
}

printf 'Authenticate again with sudo-rs through the installed PAM service.\n'
authenticate "$tested"
assert_equal 0 "$("$tested" -n /usr/bin/id -u)" 'execute as root'
assert_equal "$invoking_uid" "$("$tested" -n -u "$invoking_user" /usr/bin/id -u)" 'execute as named user'
assert_equal "$invoking_uid" "$("$tested" -n -g "$(id -gn)" /usr/bin/id -u)" 'group-only request retains the invoking user'
assert_equal "$(id -g)" "$("$tested" -n -u "$invoking_user" -g "$(id -gn)" /usr/bin/id -g)" 'explicit primary group'
assert_equal "$("$native_sudo" -n -u nobody /usr/bin/id -u)" "$("$tested" -n -u nobody /usr/bin/id -u)" 'execute as a different unprivileged account'
assert_equal 0 "$("$tested" -n -i /usr/bin/id -u)" 'login shell'
assert_equal "$invoking_uid" "$("$tested" -n /bin/sh -c 'printf %s "$SUDO_UID"')" 'invoking identity in command environment'
assert_equal native-value "$("$tested" -n SUDO_RS_NATIVE_VALUE=native-value /bin/sh -c 'printf %s "$SUDO_RS_NATIVE_VALUE"')" 'explicit command environment'
assert_equal unset "$(LD_PRELOAD=invalid "$tested" -n /bin/sh -c 'printf %s "${LD_PRELOAD-unset}"')" 'loader environment filtering'

normalize_groups() { tr ' ' '\n' | sort -nu | tr '\n' ' '; }
expected_groups=$("$native_sudo" -n -u "$invoking_user" /usr/bin/id -G | normalize_groups)
actual_groups=$("$tested" -n -u "$invoking_user" /usr/bin/id -G | normalize_groups)
assert_equal "$expected_groups" "$actual_groups" 'Open Directory supplementary groups'

assert_equal 'native-pipe' "$(printf 'native-pipe\n' | "$tested" -n /bin/cat | tr -d '\r')" 'pipe input and output'
status=0
"$tested" -n /bin/sh -c 'exit 37' || status=$?
assert_equal 37 "$status" 'command exit status'

"$tested" -n -b /bin/sh -c 'printf finished > "$1"' sh "$stage/background-result"
background_output=""
for ((attempt=0; attempt<50; attempt++)); do
    if [[ -f $stage/background-result ]]; then
        # The invoking umask may be 077; the root command's output then correctly
        # belongs only to root. Read it through the independently trusted sudo.
        background_output=$("$native_sudo" -n /bin/cat "$stage/background-result")
        [[ $background_output == finished ]] && break
    fi
    sleep 0.1
done
assert_equal finished "$background_output" 'background command'

SUDO_EDITOR="$stage/editor" "$tested" -n --edit "$stage/edit-target"
grep -q '^sudo-rs-native-edit$' "$stage/edit-target"
printf 'PASS sudoedit with an unprivileged editor\n'
"$native_sudo" -n /usr/bin/install -o nobody -g "$(id -gn nobody)" -m 644 "$scratch/edit-target" "$stage/foreign-edit-target"
SUDO_EDITOR="$stage/editor" "$tested" -n -u nobody --edit "$stage/foreign-edit-target"
grep -q '^sudo-rs-native-edit$' "$stage/foreign-edit-target"
printf 'PASS sudoedit as a different unprivileged target account\n'

assert_rejected_edit() {
    local path=$1 label=$2
    if SUDO_EDITOR="$stage/editor" "$tested" -n --edit "$path"; then
        printf 'FAIL %s: unsafe edit was accepted\n' "$label" >&2
        exit 1
    fi
    printf 'PASS %s\n' "$label"
}
"$native_sudo" -n /bin/ln -s "$stage/edit-target" "$stage/edit-link"
assert_rejected_edit "$stage/edit-link" 'sudoedit rejects symbolic links'
"$native_sudo" -n /bin/mkdir "$stage/writable-parent" "$stage/acl-parent"
"$native_sudo" -n /bin/chmod 777 "$stage/writable-parent"
"$native_sudo" -n /bin/chmod 755 "$stage/acl-parent"
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 644 "$scratch/edit-target" "$stage/writable-parent/target"
assert_rejected_edit "$stage/writable-parent/target" 'sudoedit rejects a writable parent'
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 644 "$scratch/edit-target" "$stage/acl-target"
"$native_sudo" -n /bin/chmod +a "user:$invoking_user allow write" "$stage/acl-target"
assert_rejected_edit "$stage/acl-target" 'sudoedit observes ACL write permission on a file'
"$native_sudo" -n /usr/bin/install -o root -g wheel -m 644 "$scratch/edit-target" "$stage/acl-parent/target"
"$native_sudo" -n /bin/chmod +a "user:$invoking_user allow add_file,delete_child" "$stage/acl-parent"
assert_rejected_edit "$stage/acl-parent/target" 'sudoedit observes ACL write permission on a parent'

for rights in append writesecurity chown; do
    acl_file="$stage/acl-$rights"
    "$native_sudo" -n /usr/bin/install -o root -g wheel -m 644 "$scratch/edit-target" "$acl_file"
    "$native_sudo" -n /bin/chmod +a "user:$invoking_user allow $rights" "$acl_file"
    assert_rejected_edit "$acl_file" "sudoedit observes ACL $rights permission"
done

assert_equal "$invoking_uid" "$("$native_sudo" -n "$stage/su" -s /bin/sh -c '/usr/bin/id -u' "$invoking_user")" 'su with native PAM'
assert_equal "$invoking_uid" "$("$native_sudo" -n "$stage/su" -g "$(id -gn)" -s /bin/sh -c '/usr/bin/id -u' "$invoking_user")" 'su with explicit groups'
# Apple's id and Python os.getgroups() expand directory memberships even when
# the process has an explicit kernel group list. Query libc getgroups directly.
explicit_groups=$("$native_sudo" -n "$stage/su" -g "$(id -gn)" -s /usr/bin/python3 -c '
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.getgroups.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
libc.getgroups.restype = ctypes.c_int
count = libc.getgroups(0, None)
assert count >= 0, ctypes.get_errno()
groups = (ctypes.c_uint32 * count)()
assert libc.getgroups(count, groups) == count, ctypes.get_errno()
print(" ".join(map(str, groups)))
' "$invoking_user")
assert_equal "$(id -g)" "$explicit_groups" 'su explicit kernel groups do not expand to directory groups'
# Verify actual filesystem authorization as well as the advisory group list.
"$native_sudo" -n /usr/bin/install -o root -g admin -m 640 "$scratch/edit-target" "$stage/admin-group-target"
assert_equal original "$("$native_sudo" -n "$stage/su" -s /bin/sh -c "/bin/cat '$stage/admin-group-target'" "$invoking_user")" 'su default directory groups authorize file access'
if "$native_sudo" -n "$stage/su" -g "$(id -gn)" -s /bin/sh -c "/bin/cat '$stage/admin-group-target'" "$invoking_user"; then
    printf 'FAIL su explicit groups retained directory-backed file access\n' >&2
    exit 1
fi
printf 'PASS su explicit groups restrict actual file access\n'

# Preserve a sparse descriptor through exec of sudo itself. Its command must
# receive only the standard streams, even when the descriptor was inheritable.
/usr/bin/python3 - "$tested" <<'PY'
import fcntl, os, subprocess, sys
with open('/dev/null') as source:
    fd = fcntl.fcntl(source.fileno(), fcntl.F_DUPFD, 200)
    try:
        os.set_inheritable(fd, True)
        control = f'test -e /dev/fd/{fd}'
        subprocess.run(['/bin/sh', '-c', control], pass_fds=(fd,), check=True)
        subprocess.run([sys.argv[1], '-n', '/bin/sh', '-c', f'test ! -e /dev/fd/{fd}'],
                       pass_fds=(fd,), check=True)
    finally:
        os.close(fd)
PY
printf 'PASS sparse inheritable descriptors are isolated by setuid sudo\n'
/usr/bin/python3 "$stage/pty-probe.py" "$tested"

"$tested" -n /bin/sleep 10 &
monitor_pid=$!
sleep 0.2
kill -TERM "$monitor_pid"
status=0
wait "$monitor_pid" || status=$?
if ((status < 128)); then
    echo "FAIL signal propagation: status $status" >&2
    exit 1
fi
printf 'PASS signal propagation\n'
"$tested" -n "$stage/visudo" --check
printf 'PASS visudo validates the installed policy\n'
"$tested" -k
if "$tested" -n -v > "$scratch/invalidation-output" 2>&1; then
    printf 'SKIP password-required timestamp check: installed policy permits noninteractive validation\n'
else
    /bin/cat "$scratch/invalidation-output"
    if ! /usr/bin/grep -Eqi 'interactive authentication is required|interaction is required|authentication required but not attempted' "$scratch/invalidation-output"; then
        printf 'FAIL timestamp invalidation: unexpected validation error\n' >&2
        exit 1
    fi
    printf 'PASS invalidated timestamp cannot authorize noninteractive validation\n'
fi
printf 'Native macOS integration checks passed.\n'
