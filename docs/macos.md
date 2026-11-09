# Native macOS port

The macOS implementation uses the same sudoers parser, policy engine, PAM
pipeline, command runner, sudoedit implementation, and timestamp format as the
Linux and FreeBSD implementations. Platform-specific process queries and vnode
permission checks live in `src/system/macos.rs`.

## Build and unit tests

Install Rust 1.85 or later and the Xcode command line tools. The SDK supplies
OpenPAM and libproc; no additional PAM package is required.

```sh
cargo build --locked --release --bins
cargo test --locked
cargo clippy --locked --all-targets -- --deny warnings
```

Apple Silicon and Intel use the same implementation. An Apple Silicon host can
also check the Intel code paths with the `x86_64-apple-darwin` Rust target.
With that target already installed, build an Intel release with:

```sh
cargo build --offline --locked --release --bins --target x86_64-apple-darwin
```

The native and Intel binaries can be combined with Apple's `lipo -create` and
ad-hoc signed locally with `codesign --sign - --timestamp=none`. Linking and
signature checks verify the artifact; execution of the Intel slice requires an
Intel Mac or Rosetta and must be recorded separately.

The optional `gettext` feature requires GNU libintl. Add its library directory to
the linker search path when building, for example:

```sh
RUSTFLAGS="-L native=/path/to/gettext/lib" cargo build --release --features gettext
```

## PAM and policy

The default build uses the installed `/etc/pam.d/sudo` and `/etc/pam.d/su`
services, including locally configured authentication modules. macOS has its own
OpenPAM bindings because its error constants differ from FreeBSD's. Enable
`pam-login` only when a `sudo-i` PAM service has also been configured.

The usual `/etc/sudoers-rs`, with fallback to `/etc/sudoers`, determines policy.
macOS normally grants administrator access through the `admin` group. Existing
sudoers behavior, environment filtering, command matching, login shells,
background execution, PTYs, signal forwarding, and sudoedit are shared with the
other ports.

Apple's `lecture_file` sudoers setting is accepted, like the existing `lecture`
setting. Neither setting displays a lecture in sudo-rs.

`su --login` starts with Darwin's `_PATH_DEFPATH` for ordinary users and
`_PATH_STDPATH` for root. Login shell startup files can then extend those paths.

## Groups, terminals, and timestamps

Named accounts use `initgroups`, allowing Open Directory to resolve memberships
beyond the kernel's sixteen-entry cache. Policy group matching also queries the
native membership service for nested memberships outside the advisory list.
Membership service failures stop authorization, including for negated group rules.
Explicit group lists, including `su -g`
and `su -G`, use `setgroups`; Darwin limits those explicit lists to sixteen
entries. Larger explicit lists produce an error instead of silently dropping
memberships. Account-based group lookup is restored after temporary credential
changes; supplementary groups that contain runtime-only memberships retain an
explicit list.

`PROC_PIDTBSDINFO` supplies the actual controlling terminal and process creation
time. Missing or inaccessible process information disables the affected
timestamp scope rather than substituting a zero identity. Timestamp timeouts use
Darwin's sleep-inclusive monotonic clock and records live in `/var/run/sudo-rs/ts`.

Descriptor isolation uses a growing `PROC_PIDLISTFDS` snapshot, with `/dev/fd` as
fallback. A full snapshot is retried, preventing descriptor leaks caused by a
fixed growth margin. Pipe descriptors use `FD_CLOEXEC` through `F_SETFD`.

Sudoedit checks `ATTR_CMN_USERACCESS` on opened descriptors as the invoking
user. Darwin can grant individual mutation rights without granting aggregate
`W_OK`, so it also evaluates the vnode's ordered native ACL and remaining POSIX
rights. This includes append-only files, partial directory grants, ACL or owner
changes, deny ordering, and inheritance-only entries without a new path lookup.
ACL and membership lookup failures reject the edit.

`NOEXEC` and AppArmor remain Linux-specific capabilities. The optional remote
sudoers feature verifies Unix socket peer identities with Darwin's `getpeereid`.
Unsupported `NOEXEC` requests fail before forking, including background requests,
so their callers receive a failure instead of a successful background exit.

## Shared hurdles with NetBSD

Most of what stands between sudo-rs and a build on macOS is not specific to
macOS. The `netbsd-experiment` branch picks commits from `macos-experiment` and
runs into the same gaps, so the code is gated on what an OS provides instead of
on which OS it is, where that is possible:

| Gap | macOS | NetBSD | Handled by |
|---|---|---|---|
| `close_range(CLOSE_RANGE_CLOEXEC)` | missing, `PROC_PIDLISTFDS` then `/dev/fd` | missing, `/dev/fd` | `mark_fds_as_cloexec` |
| `pipe2` | missing | present | `pipe_cloexec` |
| `faccessat` with `AT_EMPTY_PATH` | missing, vnode access query plus ACL walk | missing, not yet handled | `secure_open_for_sudoedit` |
| `POLLRDHUP` | missing | missing | `rpassword` |
| Process start time and tty | `proc_pidinfo` | `kinfo_proc2` via `sysctl` | `Process::starting_time`, `tty_device_id` |

Whether the `/dev/fd` fallback works on NetBSD is untested; it needs fdescfs to
be mounted. Changes that are not macOS-specific are good candidates to land in
`main` ahead of the rest of the port. The `SUDO_RS_IS_UNSTABLE` opt-in that
`sudo` already demands of development builds could cover targets that are not
supported yet; it is tied to the `dev` feature today.

## Native privilege integration tests

After building and reviewing the code, run from a regular administrator account:

```sh
./util/test-macos-native.sh
```

The script builds offline using cached dependencies. It asks Apple's
`/usr/bin/sudo` for administrator authentication, stages root-owned binaries in a
temporary directory under `/private/var/run`, and authenticates through the new
sudo's PAM service. It removes its staged files on exit. It uses the installed
policy and PAM configuration without rewriting them. Normal sudo-rs timestamp
records may be created or refreshed by the authentication checks.

Apple sudo and sudo-rs use separate authentication timestamps. Enter your
password at each Terminal prompt; authenticating the staging step does not
authenticate sudo-rs.

The checks cover temporary credential restoration, Open Directory membership,
explicit group restrictions, root and user execution, login shells, pipelines,
exit status, background commands, sudoedit, su, signals, and visudo. Of the Rust
unit tests, only the dedicated credential test runs as root; the full unit suite
runs unprivileged.
The native suite also checks explicit primary groups, command environment
filtering, descriptor inheritance through the setuid executable, PTY dimensions
and window-change forwarding, foreground job suspension/resumption, timestamp
invalidation, sudoedit with a foreign target UID, and sudoedit rejection of
symbolic links, writable parents, and ACL-based write access. It uses temporary
fixtures rather than changing the installed sudoers or PAM services.

Existing builds can be supplied with `--bin-dir DIR` and `--test-bin FILE`.
`--non-interactive` requires existing administrator authorization and a policy
that lets the tested sudo validate without prompting, as on a disposable CI
runner. A password or Touch ID check in a real login terminal remains part of
the release validation when those PAM modules are configured.

macOS privacy protection may reject descriptor-relative traversal through
Documents or Desktop even when a checkout itself can be opened. The secure-open
test should be run from a checkout in an accessible directory such as Downloads;
permission checks should not be relaxed to hide an operating-system denial.

The existing Docker compliance suite exercises a Linux guest when launched from
macOS. It is useful Linux regression coverage; the native script above exercises
Darwin privilege and PAM behavior directly.
