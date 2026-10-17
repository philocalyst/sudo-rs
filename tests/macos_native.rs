//! End-to-end checks of the setuid macOS binaries.
//!
//! The Docker-based compliance suite exercises a Linux guest, so it cannot say
//! anything about Darwin credentials, Open Directory groups, ACLs or the
//! terminal. These tests run the freshly built `sudo`, `su` and `visudo`
//! against the host instead.
//!
//! They need a real administrator, so they are `#[ignore]`d. Run them from a
//! regular administrator account in a terminal, one at a time:
//!
//! ```sh
//! cargo test --release --test macos_native -- --ignored --test-threads=1
//! ```
//!
//! Binaries are copied into a root-owned directory under `/private/var/run`
//! (using Apple's `/usr/bin/sudo`, which is also the reference for expected
//! output) and removed again afterwards. The installed sudoers file and PAM
//! services are used as they are and never rewritten.
//!
//! Environment:
//! - `SUDO_RS_NATIVE_NONINTERACTIVE`: never prompt; requires passwordless
//!   `sudo` for the invoking account, as on a CI runner.
//! - `SUDO_RS_NATIVE_SUDO`: run the terminal tests against this `sudo` instead
//!   of a staged copy, e.g. Apple's, to check what a test expects.
#![cfg(target_os = "macos")]

use std::{
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

const APPLE_SUDO: &str = "/usr/bin/sudo";
const STAGE_TEMPLATE: &str = "/private/var/run/sudo-rs-native.XXXXXX";

/// The terminal and the Open Directory are shared by every test.
static EXCLUSIVE: Mutex<()> = Mutex::new(());
static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    EXCLUSIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn noninteractive() -> bool {
    std::env::var_os("SUDO_RS_NATIVE_NONINTERACTIVE").is_some()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn run(command: &mut Command) -> Output {
    command
        .output()
        .unwrap_or_else(|err| panic!("cannot run {command:?}: {err}"))
}

/// Run `args` as root through Apple's sudo; it has to succeed.
fn apple<S: AsRef<OsStr>>(args: impl IntoIterator<Item = S>) -> Output {
    let mut command = Command::new(APPLE_SUDO);
    command.arg("-n").args(args);
    let output = run(&mut command);
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Let `sudo -v` prompt on the terminal unless that is not wanted.
fn authenticate(sudo: &Path) {
    let mut command = Command::new(sudo);
    if noninteractive() {
        command.arg("-n");
    }
    let status = command.arg("-v").status().expect("cannot run sudo -v");
    assert!(status.success(), "{sudo:?} -v did not authenticate");
}

struct Account {
    name: String,
    uid: String,
    group: String,
    gid: String,
}

impl Account {
    fn invoking() -> Self {
        let id = |flag: &str| stdout_of(&run(Command::new("/usr/bin/id").arg(flag)));
        Self {
            name: id("-un"),
            uid: id("-u"),
            group: id("-gn"),
            gid: id("-g"),
        }
    }
}

/// A root-owned directory holding the binaries under test and its fixtures.
struct Stage {
    dir: PathBuf,
    scratch: PathBuf,
    me: Account,
}

impl Stage {
    fn new() -> Self {
        authenticate(Path::new(APPLE_SUDO));
        let me = Account::invoking();
        let scratch = std::env::temp_dir().join(format!(
            "sudo-rs-native-{}-{}",
            std::process::id(),
            SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let dir = PathBuf::from(stdout_of(&apple(["/usr/bin/mktemp", "-d", STAGE_TEMPLATE])));
        // From here on, `Drop` removes both directories even if setup panics.
        let stage = Self { dir, scratch, me };
        fs::create_dir(&stage.scratch).unwrap();
        apple([
            OsStr::new("/bin/chmod"),
            "755".as_ref(),
            stage.dir.as_os_str(),
        ]);
        stage.install(env!("CARGO_BIN_EXE_sudo"), "sudo", "4755");
        stage.install(env!("CARGO_BIN_EXE_su"), "su", "4755");
        stage.install(env!("CARGO_BIN_EXE_visudo"), "visudo", "755");
        stage.install(std::env::current_exe().unwrap(), "native-tests", "755");
        authenticate(&stage.path("sudo"));
        stage
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Install `source` as `name`, owned by root and `group`.
    fn install_as(
        &self,
        source: impl AsRef<Path>,
        name: &str,
        mode: &str,
        owner: &str,
        group: &str,
    ) -> PathBuf {
        let target = self.path(name);
        apple([
            OsStr::new("/usr/bin/install"),
            "-o".as_ref(),
            owner.as_ref(),
            "-g".as_ref(),
            group.as_ref(),
            "-m".as_ref(),
            mode.as_ref(),
            source.as_ref().as_os_str(),
            target.as_os_str(),
        ]);
        target
    }

    fn install(&self, source: impl AsRef<Path>, name: &str, mode: &str) -> PathBuf {
        self.install_as(source, name, mode, "root", "wheel")
    }

    /// A fixture with the given contents.
    fn fixture(&self, name: &str, contents: &str, mode: &str, owner: &str, group: &str) -> PathBuf {
        // The source is flat even when `name` names a file inside a staged directory.
        let source = self.scratch.join(name.replace('/', "_"));
        fs::write(&source, contents).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        self.install_as(source, name, mode, owner, group)
    }

    /// The staged `sudo` (or the one named by `SUDO_RS_NATIVE_SUDO`), non-interactive.
    fn sudo(&self) -> Command {
        let mut command = Command::new(self.path("sudo"));
        command.arg("-n");
        command
    }

    fn su(&self) -> Command {
        let mut command = Command::new(APPLE_SUDO);
        command.arg("-n").arg(self.path("su"));
        command
    }

    /// Standard output of `command`, which has to succeed.
    fn stdout(&self, command: &mut Command) -> String {
        let output = run(command);
        assert!(
            output.status.success(),
            "{command:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout_of(&output)
    }

    /// The contents of a (possibly root-only) file.
    fn read(&self, path: &Path) -> Vec<u8> {
        apple([OsStr::new("/bin/cat"), path.as_os_str()]).stdout
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
        if self.dir.starts_with("/private/var/run") {
            let removed = Command::new(APPLE_SUDO)
                .args(["-n", "/bin/rm", "-rf"])
                .arg(&self.dir)
                .status();
            if !removed.is_ok_and(|status| status.success()) {
                // A setuid copy of sudo-rs must not be left behind unnoticed.
                eprintln!(
                    "WARNING: could not remove {}; delete it as root",
                    self.dir.display()
                );
            }
        }
    }
}

fn sorted_ids(text: &str) -> Vec<u32> {
    let mut ids: Vec<u32> = text
        .split_whitespace()
        .map(|id| id.parse().unwrap())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn commands_run_as_the_requested_identity() {
    let _guard = exclusive();
    let s = Stage::new();
    let me = &s.me;
    let id = "/usr/bin/id";
    let check = |expected: &str, args: &[&str], label: &str| {
        assert_eq!(expected, s.stdout(s.sudo().args(args)), "{label}");
    };

    check("0", &[id, "-u"], "root by default");
    check(&me.uid, &["-u", &me.name, id, "-u"], "a named user");
    check(
        &me.uid,
        &["-g", &me.group, id, "-u"],
        "a group alone keeps the invoking user",
    );
    check(
        &me.gid,
        &["-u", &me.name, "-g", &me.group, id, "-g"],
        "an explicit primary group",
    );
    check("0", &["-i", id, "-u"], "a login shell");

    let nobody = stdout_of(&apple(["-u", "nobody", id, "-u"]));
    check(
        &nobody,
        &["-u", "nobody", id, "-u"],
        "another unprivileged account",
    );

    // The directory service decides supplementary groups, as it does for Apple's sudo.
    let reference = stdout_of(&apple(["-u", &me.name, id, "-G"]));
    let ours = s.stdout(s.sudo().args(["-u", &me.name, id, "-G"]));
    assert_eq!(
        sorted_ids(&reference),
        sorted_ids(&ours),
        "Open Directory groups"
    );
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn command_environment_is_explicit_and_filtered() {
    let _guard = exclusive();
    let s = Stage::new();
    let printf = |name: &str| format!("printf %s \"${{{name}-unset}}\"");

    assert_eq!(
        s.me.uid,
        s.stdout(s.sudo().args(["/bin/sh", "-c", &printf("SUDO_UID")]))
    );
    assert_eq!(
        "native-value",
        s.stdout(
            s.sudo()
                .args(["SUDO_RS_NATIVE_VALUE=native-value", "/bin/sh", "-c"])
                .arg(printf("SUDO_RS_NATIVE_VALUE"))
        )
    );
    // dyld honours DYLD_*, not LD_PRELOAD. Platform binaries such as /bin/sh have
    // DYLD_* stripped by dyld whatever sudo does, so read it from this test
    // binary, with a control that shows the variable is visible without sudo.
    const LOADER_VARIABLE: &str = "DYLD_LIBRARY_PATH";
    let probe = |command: &mut Command| {
        let output = command
            .env(LOADER_VARIABLE, "/nonexistent")
            .env("SUDO_RS_NATIVE_PROBE", "1")
            .args(["--ignored", "--exact", "probe_environment", "--nocapture"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("environment: ").map(str::to_string))
            .unwrap_or_else(|| panic!("the probe printed no result: {output:?}"))
    };
    assert_eq!(
        "/nonexistent",
        probe(&mut Command::new(s.path("native-tests"))),
        "control: the variable must reach a non-platform binary"
    );
    assert_eq!(
        "unset",
        probe(s.sudo().arg(s.path("native-tests"))),
        "loader environment filtering"
    );
}

/// Re-executed under `sudo` by [`command_environment_is_explicit_and_filtered`].
#[test]
#[ignore = "helper for command_environment_is_explicit_and_filtered"]
fn probe_environment() {
    if std::env::var_os("SUDO_RS_NATIVE_PROBE").is_some() {
        let value = std::env::var("DYLD_LIBRARY_PATH").unwrap_or_else(|_| "unset".into());
        println!("environment: {value}");
    }
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn input_output_and_exit_status_pass_through() {
    let _guard = exclusive();
    let s = Stage::new();

    let mut child = s
        .sudo()
        .arg("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"native-pipe\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!("native-pipe", stdout_of(&output).replace('\r', ""));

    let status = s
        .sudo()
        .args(["/bin/sh", "-c", "exit 37"])
        .status()
        .unwrap();
    assert_eq!(Some(37), status.code());
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn background_commands_outlive_sudo() {
    let _guard = exclusive();
    let s = Stage::new();
    let result = s.path("background-result");
    let read_result = || {
        Command::new(APPLE_SUDO)
            .args(["-n", "/bin/cat"])
            .arg(&result)
            .output()
            .unwrap()
            .stdout
    };

    // Detach sudo's streams: otherwise `output()` would wait for the background
    // command to close the pipe and hide whether sudo returned early.
    let started = Instant::now();
    let status = s
        .sudo()
        .args([
            "-b",
            "/bin/sh",
            "-c",
            "sleep 2; printf finished > \"$1\"",
            "sh",
        ])
        .arg(&result)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "sudo -b waited for the command"
    );
    assert!(read_result().is_empty(), "the command had already finished");

    // The command runs as root with the invoking umask, so only root may read it.
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_result() != b"finished" {
        assert!(
            Instant::now() < deadline,
            "the background command never finished"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn termination_is_propagated_to_the_command() {
    let _guard = exclusive();
    let s = Stage::new();
    let marker = s.path("received-term");
    let script = "trap 'printf term > \"$1\"; exit 0' TERM; echo ready; sleep 10 & wait";
    let mut child = s
        .sudo()
        .args(["/bin/sh", "-c", script, "sh"])
        .arg(&marker)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pending = Vec::new();
    assert_eq!(
        "ready",
        read_line(
            &mut child,
            &mut pending,
            Instant::now() + Duration::from_secs(10)
        )
    );
    // SAFETY: `child` is a live process we spawned.
    assert_eq!(0, unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM)
    });
    let status = child.wait().unwrap();
    assert_eq!(
        b"term".as_slice(),
        s.read(&marker),
        "the command never received SIGTERM ({status:?})"
    );
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn visudo_accepts_the_installed_policy() {
    let _guard = exclusive();
    let s = Stage::new();
    s.stdout(s.sudo().arg(s.path("visudo")).arg("--check"));
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn invalidated_timestamps_do_not_authorize() {
    let _guard = exclusive();
    let s = Stage::new();
    s.stdout(s.sudo().arg("-k"));
    let output = run(s.sudo().arg("-v"));
    if output.status.success() {
        eprintln!("SKIP: the installed policy lets sudo validate without a password");
        return;
    }
    let message = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        [
            "interactive authentication is required",
            "interaction is required",
            "authentication required but not attempted"
        ]
        .iter()
        .any(|expected| message.contains(expected)),
        "unexpected validation error: {message}"
    );
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn descriptors_are_not_inherited_through_the_setuid_executable() {
    let _guard = exclusive();
    let s = Stage::new();
    const FD: libc::c_int = 200;
    let probe = |command: &mut Command| {
        // SAFETY: only async-signal-safe `dup2` runs between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::dup2(0, FD) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.status().unwrap().success()
    };
    let present = format!("test -e /dev/fd/{FD}");
    let absent = format!("test ! -e /dev/fd/{FD}");
    // Control: without sudo the sparse descriptor really is inherited.
    assert!(
        probe(Command::new("/bin/sh").args(["-c", &present])),
        "the control did not inherit it"
    );
    assert!(
        probe(s.sudo().args(["/bin/sh", "-c", &absent])),
        "the command inherited descriptor {FD}"
    );
}

const EDITOR: &str =
    "#!/bin/sh\nfor file do printf '\\nsudo-rs-native-edit\\n' >> \"$file\"; done\n";
const EDIT_MARKER: &[u8] = b"\nsudo-rs-native-edit\n";
const NOT_WRITABLE: &str = "cannot open a file in a path writable by the user";
const NOT_A_LINK: &str = "editing symbolic links is not permitted";

impl Stage {
    fn edit(&self, user: Option<&str>, path: &Path) -> Output {
        let mut command = self.sudo();
        command.env("SUDO_EDITOR", self.path("editor"));
        if let Some(user) = user {
            command.args(["-u", user]);
        }
        run(command.arg("--edit").arg(path))
    }

    /// Editing `path` has to fail with `expected`, leaving the file as it was.
    fn assert_edit_refused(&self, path: &Path, expected: &str, label: &str) {
        let before = self.read(path);
        let output = self.edit(None, path);
        assert!(
            !output.status.success(),
            "{label}: the unsafe edit was accepted"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "{label}: expected <{expected}>, got <{stderr}>"
        );
        assert_eq!(
            before,
            self.read(path),
            "{label}: the refused edit changed the file"
        );
    }
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn sudoedit_edits_with_an_unprivileged_editor() {
    let _guard = exclusive();
    let s = Stage::new();
    s.fixture("editor", EDITOR, "755", "root", "wheel");

    let own = s.fixture("edit-target", "original\n", "644", "root", "wheel");
    assert!(s.edit(None, &own).status.success());
    assert!(s.read(&own).ends_with(EDIT_MARKER));

    let nobody_group = stdout_of(&run(Command::new("/usr/bin/id").args(["-gn", "nobody"])));
    let foreign = s.fixture(
        "foreign-edit-target",
        "original\n",
        "644",
        "nobody",
        &nobody_group,
    );
    assert!(s.edit(Some("nobody"), &foreign).status.success());
    assert!(s.read(&foreign).ends_with(EDIT_MARKER));
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn sudoedit_refuses_paths_the_user_could_redirect() {
    let _guard = exclusive();
    let s = Stage::new();
    let me = s.me.name.clone();
    s.fixture("editor", EDITOR, "755", "root", "wheel");
    let chmod_acl = |acl: String, path: &Path| {
        apple([
            OsStr::new("/bin/chmod"),
            "+a".as_ref(),
            acl.as_ref(),
            path.as_os_str(),
        ]);
    };

    let target = s.fixture("edit-target", "original\n", "644", "root", "wheel");
    let link = s.path("edit-link");
    apple([
        OsStr::new("/bin/ln"),
        "-s".as_ref(),
        target.as_os_str(),
        link.as_os_str(),
    ]);
    s.assert_edit_refused(&link, NOT_A_LINK, "a symbolic link");

    let writable = s.path("writable-parent");
    apple([OsStr::new("/bin/mkdir"), writable.as_os_str()]);
    apple([
        OsStr::new("/bin/chmod"),
        "777".as_ref(),
        writable.as_os_str(),
    ]);
    let inside = s.fixture(
        "writable-parent/target",
        "original\n",
        "644",
        "root",
        "wheel",
    );
    s.assert_edit_refused(&inside, NOT_WRITABLE, "a world-writable parent");

    let acl_file = s.fixture("acl-target", "original\n", "644", "root", "wheel");
    chmod_acl(format!("user:{me} allow write"), &acl_file);
    s.assert_edit_refused(&acl_file, NOT_WRITABLE, "an ACL granting write on the file");

    let acl_parent = s.path("acl-parent");
    apple([OsStr::new("/bin/mkdir"), acl_parent.as_os_str()]);
    apple([
        OsStr::new("/bin/chmod"),
        "755".as_ref(),
        acl_parent.as_os_str(),
    ]);
    let child = s.fixture("acl-parent/target", "original\n", "644", "root", "wheel");
    chmod_acl(
        format!("user:{me} allow add_file,delete_child"),
        &acl_parent,
    );
    s.assert_edit_refused(
        &child,
        NOT_WRITABLE,
        "an ACL granting changes to the parent",
    );

    // Rights that do not read as "write" but still let the user take the file over.
    for right in ["append", "writesecurity", "chown"] {
        let file = s.fixture(
            &format!("acl-{right}"),
            "original\n",
            "644",
            "root",
            "wheel",
        );
        chmod_acl(format!("user:{me} allow {right}"), &file);
        s.assert_edit_refused(&file, NOT_WRITABLE, &format!("an ACL granting {right}"));
    }
}

/// Re-executed under `su` by [`su_keeps_an_explicit_kernel_group_list`]: Apple's
/// `id` and `getgroups(3)` wrappers expand directory memberships, so ask the
/// kernel's own list.
#[test]
#[ignore = "helper for su_keeps_an_explicit_kernel_group_list"]
fn probe_kernel_groups() {
    if std::env::var_os("SUDO_RS_NATIVE_PROBE").is_none() {
        return;
    }
    // SAFETY: a null buffer with length 0 only asks for the number of groups.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(count >= 0, "{}", io::Error::last_os_error());
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: `groups` has room for `count` entries.
    assert_eq!(count, unsafe {
        libc::getgroups(count, groups.as_mut_ptr())
    });
    let list: Vec<String> = groups.iter().map(ToString::to_string).collect();
    println!("kernel-groups: {}", list.join(" "));
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn su_honours_native_pam_and_explicit_groups() {
    let _guard = exclusive();
    let s = Stage::new();
    let me = &s.me;
    let shell_id = |s: &Stage, groups: &[&str]| {
        s.stdout(
            s.su()
                .args(groups)
                .args(["-s", "/bin/sh", "-c", "/usr/bin/id -u", &me.name]),
        )
    };

    assert_eq!(me.uid, shell_id(&s, &[]), "su with native PAM");
    assert_eq!(
        me.uid,
        shell_id(&s, &["-g", &me.group]),
        "su with explicit groups"
    );

    let probe = format!(
        "SUDO_RS_NATIVE_PROBE=1 exec {} --ignored --exact probe_kernel_groups --nocapture",
        s.path("native-tests").display()
    );
    let reported = s.stdout(
        s.su()
            .args(["-g", &me.group, "-s", "/bin/sh", "-c", &probe, &me.name]),
    );
    let kernel_groups = reported
        .lines()
        .find_map(|line| line.strip_prefix("kernel-groups: "))
        .unwrap_or_else(|| panic!("the probe printed no group list: {reported}"));
    assert_eq!(
        me.gid, kernel_groups,
        "explicit groups must not expand to directory groups"
    );

    // The advisory list is not enough: actual file access has to follow it too.
    let target = s.fixture("admin-group-target", "original\n", "640", "root", "admin");
    let cat = format!("/bin/cat '{}'", target.display());
    let by_default = s.stdout(s.su().args(["-s", "/bin/sh", "-c", &cat, &me.name]));
    assert_eq!(
        "original", by_default,
        "directory groups authorize access by default"
    );
    let restricted = run(s
        .su()
        .args(["-g", &me.group, "-s", "/bin/sh", "-c", &cat, &me.name]));
    assert!(
        !restricted.status.success()
            && String::from_utf8_lossy(&restricted.stderr).contains("Permission denied"),
        "explicit groups kept directory-backed file access: {restricted:?}"
    );
}

/// The controlling terminal of the test run; the tests need a real one because
/// tickets, window changes and job control are all per-terminal.
struct Terminal(OwnedFd);

impl Terminal {
    fn open() -> Self {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .expect(
                "these tests need a controlling terminal (in CI, wrap them in /usr/bin/script)",
            );
        Self(file.into())
    }

    fn size(&self) -> libc::winsize {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ writes a `winsize` through the pointer.
        assert_eq!(0, unsafe {
            libc::ioctl(self.0.as_raw_fd(), libc::TIOCGWINSZ, &mut size)
        });
        size
    }

    fn set_size(&self, size: &libc::winsize) {
        // SAFETY: TIOCSWINSZ only reads the `winsize` behind the pointer.
        assert_eq!(0, unsafe {
            libc::ioctl(self.0.as_raw_fd(), libc::TIOCSWINSZ, size)
        });
    }
}

/// Read one line from `child`'s standard output, waiting at most until `deadline`.
fn read_line(child: &mut Child, pending: &mut Vec<u8>, deadline: Instant) -> String {
    let stdout = child.stdout.as_mut().expect("standard output is piped");
    loop {
        if let Some(end) = pending.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            return String::from_utf8_lossy(&line).trim().to_string();
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut poll = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: `poll` is one valid pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
        if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        assert!(ready > 0, "timed out waiting for the command's output");
        let mut chunk = [0u8; 256];
        let count = stdout.read(&mut chunk).unwrap();
        assert!(count != 0, "the command exited before reporting");
        pending.extend_from_slice(&chunk[..count]);
    }
}

fn kill_and_reap(child: &mut Child) {
    // A child that was already reaped has a pid that may belong to someone else.
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    let pid = child.id() as libc::pid_t;
    // SAFETY: signalling a child we own. SIGTERM is relayed by sudo to its
    // command, which SIGKILL could not be; a stopped child needs SIGCONT first.
    unsafe {
        libc::kill(pid, libc::SIGCONT);
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if matches!(child.try_wait(), Ok(None)) {
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
    }
}

/// The `sudo` the terminal tests run: `SUDO_RS_NATIVE_SUDO`, or a staged copy.
fn terminal_sudo() -> (Option<Stage>, PathBuf) {
    match std::env::var_os("SUDO_RS_NATIVE_SUDO") {
        Some(path) => (None, PathBuf::from(path)),
        None => {
            let stage = Stage::new();
            let path = stage.path("sudo");
            (Some(stage), path)
        }
    }
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn window_size_changes_are_forwarded_to_the_command() {
    let _guard = exclusive();
    let (_stage, sudo) = terminal_sudo();
    let terminal = Terminal::open();
    let original = terminal.size();
    let mut changed = original;
    changed.ws_row = if original.ws_row < u16::MAX {
        original.ws_row + 1
    } else {
        original.ws_row - 1
    };
    changed.ws_col = if original.ws_col < u16::MAX - 1 {
        original.ws_col + 2
    } else {
        original.ws_col - 2
    };

    // `stty size` reads the terminal the command was given; sleeping in short
    // steps lets the shell run its WINCH trap promptly. The loop is bounded.
    let script = "report() { stty size; }; trap report WINCH; report; \
                  i=0; while [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done";
    let mut child = Command::new(sudo)
        .args(["-n", "/bin/sh", "-c", script])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pending = Vec::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let expected = |size: &libc::winsize| format!("{} {}", size.ws_row, size.ws_col);
        let initial = read_line(
            &mut child,
            &mut pending,
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(expected(&original), initial, "initial dimensions");
        terminal.set_size(&changed);
        let deadline = Instant::now() + Duration::from_secs(10);
        while read_line(&mut child, &mut pending, deadline) != expected(&changed) {}
    }));
    terminal.set_size(&original);
    kill_and_reap(&mut child);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[ignore = "needs administrator authentication; see tests/macos_native.rs"]
fn a_suspended_command_suspends_sudo_and_resumes_with_it() {
    let _guard = exclusive();
    let (_stage, sudo) = terminal_sudo();
    let terminal = Terminal::open();
    // SAFETY: querying the foreground group has no memory effects.
    let foreground = unsafe { libc::tcgetpgrp(terminal.0.as_raw_fd()) };
    // Setting the foreground group from a background group raises SIGTTOU.
    // SAFETY: changing a disposition to SIG_IGN and back is sound.
    let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };

    let tty = terminal.0.as_raw_fd();
    let mut command = Command::new(sudo);
    command
        .args([
            "-n",
            "/bin/sh",
            "-c",
            "echo job-started; kill -STOP $$; echo job-resumed",
        ])
        .stdout(Stdio::piped());
    // SAFETY: only async-signal-safe calls run between fork and exec. The
    // command gets its own process group and the foreground, so this process
    // stays outside it and can observe and resume the stopped job.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) == -1 || libc::tcsetpgrp(tty, libc::getpgrp()) == -1 {
                return Err(io::Error::last_os_error());
            }
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap_or_else(|err| {
        // The child may have moved the foreground before its exec failed.
        // SAFETY: handing the terminal back and restoring the disposition.
        unsafe {
            libc::tcsetpgrp(tty, foreground);
            libc::signal(libc::SIGTTOU, previous);
        }
        panic!("cannot run the job-control command: {err}");
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pending = Vec::new();
        let seconds = |n| Instant::now() + Duration::from_secs(n);
        assert_eq!(
            "job-started",
            read_line(&mut child, &mut pending, seconds(10))
        );

        let deadline = seconds(10);
        loop {
            let mut status = 0;
            // SAFETY: `status` is a valid out-pointer; WNOHANG never blocks.
            let pid = unsafe {
                libc::waitpid(
                    child.id() as libc::pid_t,
                    &mut status,
                    libc::WNOHANG | libc::WUNTRACED,
                )
            };
            if pid != 0 {
                assert!(
                    libc::WIFSTOPPED(status),
                    "sudo did not suspend with its command: {status:#x}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "sudo did not report the command's suspension"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: resuming the process group we created.
        assert_eq!(0, unsafe {
            libc::killpg(child.id() as libc::pid_t, libc::SIGCONT)
        });
        assert_eq!(
            "job-resumed",
            read_line(&mut child, &mut pending, seconds(10))
        );
        assert!(child.wait().unwrap().success());
    }));

    // SAFETY: handing the terminal back and restoring the disposition.
    unsafe {
        libc::tcsetpgrp(tty, foreground);
        libc::signal(libc::SIGTTOU, previous);
    }
    kill_and_reap(&mut child);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
