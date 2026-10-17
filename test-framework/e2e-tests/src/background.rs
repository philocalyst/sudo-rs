use sudo_test::{Command, Env, TextFile};

#[test]
fn background_reports_exec_failure_in_both_terminal_modes() {
    for use_pty in ["use_pty", "!use_pty"] {
        let env = Env(format!(
            "Defaults {use_pty}\nALL ALL=(ALL:ALL) NOPASSWD: ALL"
        ))
        .file(
            "/bin/bad-interpreter",
            TextFile("#!/interpreter/does/not/exist\n").chmod("755"),
        )
        .build();
        // Fast failures exercise both errno-pipe/SIGCHLD callback orderings.
        for _ in 0..24 {
            Command::new("sudo")
                .args(["-n", "-b", "/bin/bad-interpreter"])
                .tty(true)
                .output(&env)
                .assert_exit_code(1);
        }
        // Successful launch is distinct from the eventual command exit status.
        Command::new("sudo")
            .args(["-n", "-b", "/bin/sh", "-c", "exit 42"])
            .tty(true)
            .output(&env)
            .assert_success();
    }
}

#[test]
fn failed_background_launch_is_reported_once() {
    let env = Env("Defaults !use_pty\nALL ALL=(ALL:ALL) NOPASSWD: ALL")
        .file(
            "/bin/bad-interpreter",
            TextFile("#!/interpreter/does/not/exist\n").chmod("755"),
        )
        .build();
    let output = Command::new("sudo")
        .args(["-n", "-b", "/bin/bad-interpreter"])
        .output(&env);
    output.assert_exit_code(1);
    assert_eq!(output.stderr().matches("cannot execute").count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn background_reports_unavailable_seccomp_without_panicking() {
    // Use prctl to install an outer filter that makes seccomp() unavailable.
    // This exercises the runtime failure on a modern kernel without changing
    // sudo-rs or needing a particular Docker seccomp configuration.
    const NO_SECCOMP: &str = r#"
#include <errno.h>
#include <stddef.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_seccomp, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {4, filter};
    if (argc < 2 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == -1) return 125;
    execvp(argv[1], argv + 1);
    return 126;
}
"#;
    for use_pty in ["use_pty", "!use_pty"] {
        let env = Env(format!(
            "Defaults {use_pty}\nALL ALL=(ALL:ALL) NOPASSWD: NOEXEC: ALL"
        ))
        .file("/tmp/no-seccomp.c", NO_SECCOMP)
        .build();
        Command::new("gcc")
            .args(["/tmp/no-seccomp.c", "-o", "/tmp/no-seccomp"])
            .output(&env)
            .assert_success();
        Command::new("/tmp/no-seccomp")
            .arg("true")
            .output(&env)
            .assert_success();
        for mode in [vec!["-n"], vec!["-n", "-b"]] {
            let mut args = vec!["sudo"];
            args.extend(mode);
            args.extend(["/bin/sh", "-c", "echo ran > /tmp/command-ran"]);
            let output = Command::new("/tmp/no-seccomp")
                .args(args)
                .tty(true)
                .output(&env);
            output.assert_exit_code(1);
            assert!(!output.stderr().contains("panicked"));
            Command::new("test")
                .args(["!", "-e", "/tmp/command-ran"])
                .output(&env)
                .assert_success();
        }
    }
}
