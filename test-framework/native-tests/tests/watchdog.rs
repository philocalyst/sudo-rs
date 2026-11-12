use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn watchdog_preserves_exit_and_signal_status() {
    let probe = env!("CARGO_BIN_EXE_sudo-native-probe");
    let exit = Command::new(probe)
        .args(["watch", "5", "/bin/sh", "-c", "exit 42"])
        .status()
        .unwrap();
    assert_eq!(exit.code(), Some(42));
    let signal = Command::new(probe)
        .args(["watch", "5", probe, "signal"])
        .status()
        .unwrap();
    assert_eq!(signal.code(), Some(143));
}

#[test]
fn watchdog_bounds_a_command_that_never_finishes() {
    let before = Instant::now();
    let status = Command::new(env!("CARGO_BIN_EXE_sudo-native-probe"))
        .args(["watch", "1", "/bin/sleep", "30"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(124));
    assert!(before.elapsed() < Duration::from_secs(5));
}

#[test]
fn privileged_entry_point_refuses_before_setup() {
    let output = Command::new("/bin/sh")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh"))
        .arg("--disposable")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "privileged execution disabled: requires externally supervised disposable VM destruction\n"
    );
}

#[test]
fn pty_output_is_drained_after_child_exit() {
    let output = Command::new(env!("CARGO_BIN_EXE_sudo-native-probe"))
        .args(["watch-pty", "5", "/bin/sh", "-c", "printf '%06000d\\n' 0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let bytes: Vec<_> = output
        .stdout
        .into_iter()
        .filter(|byte| *byte != b'\r')
        .collect();
    assert_eq!(bytes.len(), 6001);
    assert!(bytes[..6000].iter().all(|byte| *byte == b'0'));
    assert_eq!(bytes[6000], b'\n');
}
