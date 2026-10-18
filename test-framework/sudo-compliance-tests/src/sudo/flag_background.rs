use sudo_test::{Command, Env, TextFile};

use crate::SUDOERS_ALL_ALL_NOPASSWD;

#[test]
fn runs_in_background() {
    let env = Env(SUDOERS_ALL_ALL_NOPASSWD).build();

    Command::new("sudo")
        .args([
            "-b",
            "sh",
            "-c",
            "touch /tmp/barrier1; until [ -f /tmp/barrier2 ]; do sleep 0.1; done; touch /tmp/barrier3",
        ])
        .output(&env)
        .assert_success();

    Command::new("sh")
        .args([
            "-c",
            "until [ -f /tmp/barrier1 ]; do sleep 0.1; done
             touch /tmp/barrier2
             until [ -f /tmp/barrier3 ]; do sleep 0.1; done",
        ])
        .output(&env)
        .assert_success();
}

const UNEXECUTABLE: &str = "/tmp/bad-interpreter";

/// A command whose interpreter does not exist, so that executing it fails.
fn env_with_unexecutable_command(sudoers: impl Into<TextFile>) -> Env {
    Env(sudoers)
        .file(
            UNEXECUTABLE,
            TextFile("#!/nonexistent/interpreter").chmod("755"),
        )
        .build()
}

#[test]
fn reports_command_that_cannot_be_executed() {
    let env = env_with_unexecutable_command(SUDOERS_ALL_ALL_NOPASSWD);

    let output = Command::new("sudo").args(["-b", UNEXECUTABLE]).output(&env);

    if sudo_test::is_original_sudo() {
        // Original sudo exits successfully as soon as it has forked.
        output.assert_success();
    } else {
        output.assert_exit_code(1);
        assert_contains!(output.stderr(), "cannot execute '/tmp/bad-interpreter'");
    }
}

#[test]
fn reports_command_that_cannot_be_executed_in_pty() {
    let env = env_with_unexecutable_command([SUDOERS_ALL_ALL_NOPASSWD, "Defaults use_pty"]);

    let output = Command::new("bash")
        .args([
            "-c",
            &format!("sudo -b {UNEXECUTABLE}; a=$?; sleep .1; exit $a"),
        ])
        .tty(true)
        .output(&env);

    if sudo_test::is_original_sudo() {
        // Original sudo exits successfully as soon as it has forked.
        output.assert_success();
    } else {
        output.assert_exit_code(1);
        assert_contains!(
            output.stdout_unchecked(),
            "cannot execute '/tmp/bad-interpreter'"
        );
    }
}

#[test]
fn stdin_pipe() {
    if sudo_test::sudo_version() < sudo_test::ogsudo("1.9.18") {
        return;
    }

    let env = Env([SUDOERS_ALL_ALL_NOPASSWD, "Defaults use_pty"]).build();

    // Everything is put in a single command with separators to keep the pts numbers predictable
    Command::new("sh")
        .args([
            "-c",
            "ls -l /proc/self/fd > /tmp/output; echo @@@@ >> /tmp/output; sudo -b sh -c 'ls -l /proc/self/fd && cat /dev/stdin && touch /tmp/barrier' >> /tmp/output",
        ])
        .tty(true)
        .output(&env)
        .assert_success();

    let stdout = Command::new("sh")
        .args([
            "-c",
            "until [ -f /tmp/barrier ]; do sleep 0.1; done; cat /tmp/output",
        ])
        .output(&env)
        .stdout();

    dbg!(&stdout);

    let (term_in, term_background) = stdout.split_once("@@@@").unwrap();
    assert_contains!(term_in, " 0 -> /dev/pts/0");
    assert_contains!(term_in, " 1 -> /tmp/output");
    assert_contains!(term_in, " 2 -> /dev/pts/0");
    // Background mode makes stdin a half-open pipe and handles stdout and stderr like normal.
    assert_contains!(term_background, " 0 -> pipe:");
    assert_contains!(term_background, " 1 -> /tmp/output");
    assert_contains!(term_background, " 2 -> /dev/pts/0");
}
