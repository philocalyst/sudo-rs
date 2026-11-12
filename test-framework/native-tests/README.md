# Native port test design (privileged execution disabled)

This is an **incomplete, disabled scaffold**, not evidence that sudo-rs works
setuid on macOS or NetBSD. `run.sh --disposable` always exits 2 before setup.
The probe also refuses root invocation and its `as`/`pty` modes. There is
no environment variable or second argument that bypasses these checks.

The reason is process lifetime: sudo can create new sessions and process groups
for ptys. Killing the original process group cannot reliably terminate all of
its privileged descendants; polling a PID tree can miss reparented descendants.
A run needs a fresh VM owned by an external supervisor, with destruction enforced
outside the tested guest after success, failure, timeout and cancellation. The
current CI hooks do not establish that contract and remain disabled. An
unverifiable `DISPOSABLE=1` marker is insufficient.

Unprivileged checks are available now:

```sh
sh test-framework/native-tests/run.sh --list
sh -n test-framework/native-tests/run.sh
cargo test --manifest-path test-framework/native-tests/Cargo.toml
```

The tests cover the helper's exit/signal status, deadline, refusal before setup,
and draining buffered pty output after child exit. The helper's `watch` mode
runs an arbitrary command as the current user. **It is not a sandbox** and does
not claim to contain a command that daemonizes or invokes another setuid program.
Use it only with the controlled unprivileged fixtures in this directory. The same
restriction applies to `plant-fds`; arbitrary commands can invoke setuid programs.
The `no-root` probe deliberately attempts `seteuid(0)` and expects refusal.

The watchdog deadline does not bound a blocked stdout write. After its direct
child exits, descendants retaining a pty slave can survive a later drain timeout.
Neither process-group cleanup nor this helper guarantees descendant containment.
These are additional before-enable blockers, not properties validated by the
finite sleep and output fixtures.

## Proposed design

The shell draft below the unconditional refusal shows a shared case sequence
for both operating systems. Platform-specific account/group creation is isolated
in three functions. A small Rust probe supplies kernel identity/descriptor/pty
observations and direct-child execution without Python or Bash.

A full native backend for `sudo-test` would reuse more compliance cases but would
also inherit Docker/jail assumptions and need a carefully bounded environment.
Pure shell can describe fixtures clearly but cannot provide reliable process
supervision or pty operations. A standalone Rust harness can do both at the cost
of more setup code. The staged choice here is shell fixture description plus a
Rust probe, with eventual reuse by a VM-owned `sudo-test` backend. External VM
lifetime ownership is required whichever language is chosen.

If execution is enabled in a future reviewed change, the draft intends to:

- Require upstream d856ce05 (`SUDO_RS_SUDOERS_PATH`) before any mutation. Build
  against a unique root-owned `/var/run/sudo-rs-native.*` policy directory. Never
  replace system sudoers or install binaries globally.
- Create two new accounts and 21 new groups, rejecting existing names/IDs.
  Stage sudo/su as setuid only below that directory. Use a non-production test
  password and the existing system PAM policy; do not alter PAM service files.
- Revoke setuid bits before account/group and scratch cleanup. Remove only the
  new caller's timestamp files. Cleanup on catchable signals is best effort;
  mandatory external VM destruction covers uncatchable signals, interrupted
  setup, daemonized descendants and cleanup failures.
- Compare ACL access to actual kernel operations, not solely fixed expected
  values. Prove descriptor and pty fixtures work before checking sudo. Use exact
  error/status/content assertions rather than treating any failure as success.

These remain design intentions. The draft has not executed privileged setup or
any privileged case, and several negative assertions still need exact diagnostic
strengthening before enablement.

## Coverage still required

`--list` labels planned privileged cases, not passing tests. In addition to running
and correcting that draft, the following requirements are not implemented:

- P4 memberd-enabled and explicit-disabled caller credentials through sudoedit,
  exact internal restoration after success and error, nested override rejection,
  saved GID checks, default su groups, and post-PAM fork stress. The draft's `as`
  preparation uses setgroups, so it cannot model an enabled memberd caller.
- P2/P5 tty/session-scoped timestamp reuse, refusal from a different terminal or
  login session, suspend expiry, reboot invalidation and clock-step resistance.
- P3 directory ACL add_file/add_subdirectory/delete_child, read-only and ordered
  deny/allow controls, and native NetBSD ACL behavior. Negative cases need exact
  refusal messages as well as unchanged target contents.
- P6 missing-service fallback compared with the actual configured `other` policy,
  session open/close observability and environment transfer. NetBSD's stock
  `other` includes system authentication; absence of a service does not imply
  rejection. Real correct/wrong-password cases are drafted but never run.
- P7 dynamic window-size propagation and suspend/resume job control, plus prompt
  return from successful background execution. Static initial pty size is drafted.
- Differential execution against original sudo with equivalent isolated policy.
  Apple sudo's fixed policy path prevents using the scratch sudoers transparently;
  do not modify system sudoers to manufacture a comparison.

Until those cases and lifecycle guarantees are reviewed and run, this directory
must not be cited as privileged validation of the port or used to declare support.
