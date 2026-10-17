use sudo_test::{Command, Env, TextFile};

#[cfg(not(all(feature = "apparmor", target_os = "linux")))]
#[test]
fn selected_profile_is_rejected_before_authentication_on_unsupported_builds() {
    let env = Env("foo ALL=(ALL:ALL) APPARMOR_PROFILE=confined ALL")
        .user("foo")
        .build();
    let output = Command::new("sudo")
        .args(["-n", "true"])
        .as_user("foo")
        .output(&env);
    output.assert_exit_code(1);
    assert_contains!(output.stderr(), "unable to change AppArmor profile");
    assert!(
        !output
            .stderr()
            .contains("interactive authentication is required")
    );
}

#[test]
fn sudoedit_never_runs_an_editor_without_the_requested_profile() {
    let env = Env("Defaults editor=/bin/probe-editor\nALL ALL=(ALL:ALL) NOPASSWD: APPARMOR_PROFILE=unconfined sudoedit")
        .file("/bin/probe-editor", TextFile("#!/bin/sh\necho ran > /tmp/editor-ran\necho edited >> \"$1\"\n").chmod("755"))
        .file("/etc/edit-target", "original")
        .build();
    let output = Command::new("sudo")
        .args(["-n", "-e", "/etc/edit-target"])
        .output(&env);
    output.assert_exit_code(1);
    assert_contains!(output.stderr(), "unable to change AppArmor profile");
    Command::new("test")
        .args(["!", "-e", "/tmp/editor-ran"])
        .output(&env)
        .assert_success();
    assert_eq!(
        Command::new("cat")
            .arg("/etc/edit-target")
            .output(&env)
            .stdout(),
        "original"
    );
}
