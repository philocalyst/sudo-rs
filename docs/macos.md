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

Named accounts use `initgroups`, which hands the kernel the account the group
list belongs to and so keeps Open Directory able to resolve memberships beyond
the sixteen entries a credential holds. `setgroups` instead pins the credential:
afterwards the kernel answers every membership question from those entries
alone. Policy group matching also queries the
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

`NOEXEC` and AppArmor confinement can only be enforced on Linux. A policy that
selects either of them is refused on macOS before the command runs: an
unsupported `NOEXEC` request fails before forking, including a background
request, so its caller receives the failure rather than a successful background
exit, and a selected `APPARMOR_PROFILE` or `apparmor_profile` default is refused
before authenticating. A profile named by a rule that this command did not match
is ignored, so a sudoers file shared with Linux hosts still works.

The optional remote sudoers feature verifies Unix socket peer identities with
Darwin's `getpeereid`.

## Native privilege integration tests

The Docker compliance suite runs a Linux guest, so it says nothing about Darwin
credentials, Open Directory groups, ACLs or the terminal. `tests/macos_native.rs`
covers those by running the freshly built `sudo`, `su` and `visudo` on the host.
The tests are `#[ignore]`d because they need an administrator. From a regular
administrator account, in a terminal:

```sh
cargo test --release --test macos_native -- --ignored --test-threads=1
```

Apple's `/usr/bin/sudo` copies the binaries into a root-owned directory under
`/private/var/run`, which is removed afterwards, and is also the reference for
expected output. The installed sudoers file and PAM services are used as they
are and never rewritten. Apple sudo and sudo-rs keep separate authentication
timestamps, so expect a password prompt for each unless the account has
passwordless sudo.

The tests cover execution as root and as other users, group handling (Open
Directory memberships, explicit primary groups and explicit kernel group lists),
the command environment (including `DYLD_*` filtering), pipes, exit status,
`-b`, signals, descriptor inheritance through the setuid executable, `visudo`,
timestamp invalidation, `sudoedit` (an unprivileged editor, a foreign target
user, and refusal of symbolic links, writable parents and ACL grants of write,
append, `writesecurity` and `chown`), `su`, and terminal behaviour (window-size
forwarding and job-control suspension). The terminal tests need a controlling
terminal; `script -q /dev/null cargo test ...` provides one.

Two environment variables help when developing:

- `SUDO_RS_NATIVE_NONINTERACTIVE=1` never prompts, and needs passwordless sudo.
- `SUDO_RS_NATIVE_SUDO=/usr/bin/sudo` runs the terminal tests against another
  `sudo`, which shows whether a test expects what the reference does.

The credential restoration test needs root and access to crate internals, so it
is a unit test, run through Cargo's runner:

```sh
host=$(rustc -vV | sed -n 's/^host: //p')
runner="CARGO_TARGET_$(echo "$host" | tr 'a-z-' 'A-Z_')_RUNNER"
env "$runner=sudo env SUDO_RS_TEST_USER=$(id -un)" \
    cargo test --release --lib -- --ignored --exact system::macos::tests::privileged_credentials_round_trip
```

macOS privacy protection may reject descriptor-relative traversal through
Documents or Desktop even when a checkout itself can be opened. The secure-open
test should be run from a checkout in an accessible directory such as Downloads;
permission checks should not be relaxed to hide an operating-system denial.

The existing Docker compliance suite exercises a Linux guest when launched from
macOS. It is useful Linux regression coverage; the native script above exercises
Darwin privilege and PAM behavior directly.
