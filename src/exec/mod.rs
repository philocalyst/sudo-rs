mod background;
mod event;
mod io_util;
mod no_pty;
#[cfg(target_os = "linux")]
mod noexec;
mod use_pty;

use std::{
    borrow::Cow,
    convert::Infallible,
    env,
    ffi::{OsStr, OsString, c_int},
    io,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{self, Command},
    time::Duration,
};

use crate::{
    common::{
        HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1, HARDENED_ENUM_VALUE_2, bin_serde::BinPipe,
    },
    exec::no_pty::exec_no_pty,
    log::{dev_info, dev_warn, user_error},
    system::{
        _exit, Group, User,
        interface::{GroupId, ProcessId},
        kill, killpg, mark_fds_as_cloexec, set_target_user,
        signal::{SignalNumber, SignalSet, SignalsState, consts::*, exit_with_signal, signal_name},
        term::UserTerm,
        wait::{Wait, WaitError, WaitOptions},
    },
};

use self::{
    background::Background,
    event::{EventHandle, EventRegistry, PollEvent, Process},
    io_util::{retry_while_interrupted, was_interrupted},
    use_pty::{SIGCONT_BG, SIGCONT_FG, exec_pty},
};

#[cfg(target_os = "linux")]
use self::noexec::SpawnNoexecHandler;
#[cfg(not(target_os = "linux"))]
enum SpawnNoexecHandler {}
#[cfg(not(target_os = "linux"))]
impl SpawnNoexecHandler {
    fn spawn(self) {}
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(u32)]
pub enum Umask {
    /// Keep the umask of the parent process.
    Preserve = HARDENED_ENUM_VALUE_0,
    /// Mask out more of the permission bits in the new umask.
    Extend(libc::mode_t) = HARDENED_ENUM_VALUE_1,
    /// Override the umask of the parent process entirely with the given umask.
    Override(libc::mode_t) = HARDENED_ENUM_VALUE_2,
}

pub struct RunOptions<'a> {
    pub command: &'a Path,
    pub arguments: &'a [OsString],
    pub arg0: Option<&'a Path>,
    pub chdir: Option<PathBuf>,
    pub is_login: bool,
    pub user: &'a User,
    pub group: &'a Group,
    /// Supplementary groups to use instead of those of `user`.
    pub groups: Option<&'a [GroupId]>,
    pub umask: Umask,

    pub background: bool,
    pub use_pty: bool,
    pub noexec: bool,
}

/// Based on `ogsudo`s `exec_pty` function.
///
/// Returns the [`ExitReason`] of the command and a function that restores the default handler for
/// signals once its called.
pub fn run_command(
    options: RunOptions<'_>,
    env: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
) -> io::Result<ExitReason> {
    // FIXME: should we pipe the stdio streams?
    let qualified_path = options.command;
    let mut command = Command::new(qualified_path);
    // reset env and set filtered environment
    command.args(options.arguments).env_clear().envs(env);
    // set the arg0 to the requested string
    // TODO: this mechanism could perhaps also be used to set the arg0 for login shells, as below
    if let Some(arg0) = options.arg0 {
        command.arg0(arg0);
    }

    if options.is_login {
        // signal to the operating system that the command is a login shell by prefixing "-"
        let mut process_name = qualified_path
            .file_name()
            .map(|osstr| osstr.as_bytes().to_vec())
            .unwrap_or_default();
        process_name.insert(0, b'-');
        command.arg0(OsStr::from_bytes(&process_name));
    }

    let spawn_noexec_handler = if options.noexec {
        #[cfg(not(target_os = "linux"))]
        return Err(io::Error::other(
            "NOEXEC is currently only supported on Linux",
        ));

        #[cfg(target_os = "linux")]
        Some(noexec::add_noexec_filter(&mut command)?)
    } else {
        None
    };

    // Decide if the pwd should be changed. `--chdir` takes precedence over `-i`.
    let path = options
        .chdir
        .as_ref()
        .map(|chdir| chdir.to_owned())
        .or_else(|| options.is_login.then(|| options.user.home.clone().into()))
        .clone();

    // set target user and groups
    set_target_user(
        &mut command,
        options.user.clone(),
        options.group.clone(),
        options.groups,
    );

    // change current directory if necessary.
    if let Some(path) = path {
        let is_chdir = options.chdir.is_some();

        // SAFETY: Chdir as used internally by set_current_dir is async-signal-safe. The logger we
        // use is also async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if let Err(err) = env::set_current_dir(&path) {
                    user_error!(
                        "unable to change directory to {path}: {error}",
                        path = path.display(),
                        error = err
                    );
                    if is_chdir {
                        return Err(err);
                    }
                }

                Ok(())
            });
        }
    }

    // SAFETY: Umask is async-signal-safe.
    unsafe {
        let umask = options.umask;

        command.pre_exec(move || {
            match umask {
                Umask::Preserve => {}
                Umask::Extend(umask) => {
                    // The only options to get the existing umask are overwriting it or
                    // parsing a /proc file. Given that this is a single-threaded context,
                    // overwrite it with a safe value is fine and the simpler option.
                    let existing_umask = libc::umask(0o777);
                    libc::umask(existing_umask | umask);
                }
                Umask::Override(umask) => {
                    libc::umask(umask);
                }
            }

            Ok(())
        });
    }

    // Detach only now, so that an error in preparing the command is reported before anything runs
    // in the background.
    let background = if options.background {
        Some(background::detach()?)
    } else {
        None
    };

    let sudo_pid = ProcessId::new(std::process::id() as i32);

    if options.use_pty {
        match UserTerm::open() {
            Ok(user_tty) => exec_pty(
                sudo_pid,
                spawn_noexec_handler,
                command,
                user_tty,
                options.user,
                background,
            ),
            Err(err) => {
                dev_info!("Could not open user's terminal, not allocating a pty: {err}");
                exec_no_pty(sudo_pid, spawn_noexec_handler, command, background)
            }
        }
    } else {
        exec_no_pty(sudo_pid, spawn_noexec_handler, command, background)
    }
}

/// Exit reason for the command executed by sudo.
#[derive(Debug)]
pub enum ExitReason {
    Code(i32),
    Signal(i32),
}

impl ExitReason {
    pub(crate) fn exit_process(self) -> Result<Infallible, crate::common::Error> {
        match self {
            ExitReason::Code(code) => process::exit(code),
            ExitReason::Signal(signal) => exit_with_signal(signal),
        }
    }
}

fn exec_command(
    mut command: Command,
    original_set: Option<SignalSet>,
    mut original_signal: SignalsState,
    mut errpipe_tx: BinPipe<i32>,
) -> ! {
    // Restore the signal handlers of modified signals
    if let Err(err) = original_signal.restore() {
        dev_warn!("cannot restore signal states: {err}");
    }

    // Restore the signal mask now that the handlers have been setup.
    if let Some(set) = original_set {
        if let Err(err) = set.set_mask() {
            dev_warn!("cannot restore signal mask: {err}");
        }
    }

    if let Err(err) = mark_fds_as_cloexec() {
        dev_warn!("failed to close the universe: {err}");
        // Send the error to the monitor using the pipe.
        if let Some(error_code) = err.raw_os_error() {
            errpipe_tx.write(&error_code).ok();
        }

        // We call `_exit` instead of `exit` to avoid flushing the parent's IO streams by accident.
        _exit(1);
    }

    let err = command.exec();

    dev_warn!("failed to execute command: {err}");
    // If `exec` returns, it means that executing the command failed. Send the error to the
    // monitor using the pipe.
    if let Some(error_code) = err.raw_os_error() {
        errpipe_tx.write(&error_code).ok();
    }

    // We call `_exit` instead of `exit` to avoid flushing the parent's IO streams by accident.
    _exit(1);
}

/// The receiving end of the pipe that [`exec_command`] reports to.
///
/// The command process sends the error that kept it from executing the command. Otherwise, as its
/// end of the pipe is close-on-exec and the supervisor keeps no copy of it, the pipe reaches its
/// end once the command is executed (or once the command process is gone). Original sudo reads
/// its error pipe the same way, see `errpipe_cb` in
/// <https://github.com/sudo-project/sudo/blob/84e7ca6752a2d3a32452adee177d1f57421dd814/src/exec_nopty.c#L74-L116>.
struct ErrPipe {
    /// `None` once the command process has reported.
    rx: Option<BinPipe<i32>>,
    event: EventHandle,
    error: Option<io::Error>,
    /// Passes on that the command was executed when running in the background.
    background: Option<Background>,
}

impl ErrPipe {
    /// Poll the pipe, producing `event` when the command process has reported.
    fn new<T: Process>(
        rx: BinPipe<i32>,
        background: Option<Background>,
        registry: &mut EventRegistry<T>,
        event: T::Event,
    ) -> Self {
        let event = registry.register_event(&rx, PollEvent::Readable, move |_| event);

        Self {
            rx: Some(rx),
            event,
            error: None,
            background,
        }
    }

    /// Read the report of the command process, waiting for it if it has not arrived yet.
    fn read<T: Process>(&mut self, registry: &mut EventRegistry<T>) -> io::Result<()> {
        let Some(rx) = &mut self.rx else {
            return Ok(());
        };

        match rx.read() {
            Ok(error_code) => self.error = Some(io::Error::from_raw_os_error(error_code)),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                if let Some(background) = self.background.take() {
                    background.report_executed();
                }
            }
            Err(err) => return Err(err),
        }

        // A pipe at its end remains readable, so stop polling it.
        self.event.ignore(registry);
        self.rx = None;
        Ok(())
    }

    /// Stop the event loop now that the command process has terminated with `status`.
    ///
    /// If the command process reported that it could not execute the command, its exit status
    /// only follows from that, so the loop stops with the reported error instead. Reading the
    /// report cannot block anymore: the command process held the only other end of the pipe. This
    /// way it does not matter which of the two the event loop learns of first, as in
    /// `handle_sigchld_nopty` of original sudo:
    /// <https://github.com/sudo-project/sudo/blob/84e7ca6752a2d3a32452adee177d1f57421dd814/src/exec_nopty.c#L807-L811>.
    fn command_terminated<T: Process<Break = io::Error>>(
        &mut self,
        status: T::Exit,
        registry: &mut EventRegistry<T>,
    ) {
        if let Err(err) = retry_while_interrupted(|| self.read(registry)) {
            return registry.set_break(err);
        }

        match self.error.take() {
            Some(err) => registry.set_break(err),
            None => registry.set_exit(status),
        }
    }
}

// Kill the process with increasing urgency.
//
// Based on `terminate_command`.
fn terminate_process(pid: ProcessId, use_killpg: bool) {
    let kill_fn = if use_killpg { killpg } else { kill };
    kill_fn(pid, SIGHUP).ok();
    kill_fn(pid, SIGTERM).ok();
    std::thread::sleep(Duration::from_secs(2));
    kill_fn(pid, SIGKILL).ok();
}

trait HandleSigchld: Process {
    const OPTIONS: WaitOptions;

    fn on_exit(&mut self, exit_code: c_int, registry: &mut EventRegistry<Self>);
    fn on_term(&mut self, signal: SignalNumber, registry: &mut EventRegistry<Self>);
    fn on_stop(&mut self, signal: SignalNumber, registry: &mut EventRegistry<Self>);
}

fn handle_sigchld<T: HandleSigchld>(
    handler: &mut T,
    registry: &mut EventRegistry<T>,
    child_name: &'static str,
    child_pid: ProcessId,
) {
    let status = loop {
        match child_pid.wait(T::OPTIONS) {
            Err(WaitError::Io(err)) if was_interrupted(&err) => {}
            // This only happens if we receive `SIGCHLD` but there's no status update from the
            // monitor.
            Err(WaitError::Io(err)) => {
                return dev_info!("cannot wait for {child_pid} ({child_name}): {err}");
            }
            // This only happens if the monitor exited and any process already waited for the
            // monitor.
            Err(WaitError::NotReady) => {
                return dev_info!("{child_pid} ({child_name}) has no status report");
            }
            Ok((_pid, status)) => break status,
        }
    };
    if let Some(exit_code) = status.exit_status() {
        dev_info!("{child_pid} ({child_name}) exited with status code {exit_code}");
        handler.on_exit(exit_code, registry)
    } else if let Some(signal) = status.stop_signal() {
        dev_info!(
            "{child_pid} ({child_name}) was stopped by {}",
            signal_fmt(signal),
        );
        handler.on_stop(signal, registry)
    } else if let Some(signal) = status.term_signal() {
        dev_info!(
            "{child_pid} ({child_name}) was terminated by {}",
            signal_fmt(signal),
        );
        handler.on_term(signal, registry)
    } else if status.did_continue() {
        dev_info!("{child_pid} ({child_name}) continued execution");
    } else {
        dev_warn!("unexpected wait status for {child_pid} ({child_name})")
    }
}

fn signal_fmt(signal: SignalNumber) -> Cow<'static, str> {
    match signal_name(signal) {
        name @ Cow::Owned(_) => match signal {
            SIGCONT_BG => "SIGCONT_BG".into(),
            SIGCONT_FG => "SIGCONT_FG".into(),
            _ => name,
        },
        name => name,
    }
}

const fn cond_fmt<'a>(cond: bool, true_s: &'a str, false_s: &'a str) -> &'a str {
    if cond { true_s } else { false_s }
}

const fn opt_fmt(cond: bool, s: &str) -> &str {
    cond_fmt(cond, s, "")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Read, Write},
        os::unix::net::UnixStream,
        path::Path,
    };

    use super::{
        ErrPipe, RunOptions, Umask,
        background::Background,
        event::{EventRegistry, Process, StopReason},
        run_command,
    };
    use crate::{
        common::bin_serde::BinPipe,
        system::{
            _exit, User, fork_for_test,
            wait::{Wait, WaitOptions},
        },
    };

    /// A supervisor that only waits for the command process to terminate.
    struct Supervisor;

    impl Process for Supervisor {
        type Event = ();
        type Break = io::Error;
        type Exit = i32;

        fn on_event(&mut self, (): (), _registry: &mut EventRegistry<Self>) {
            panic!("the error pipe is still being polled")
        }
    }

    /// Supervise a command process that sends `report` over its error pipe and exits with status
    /// 1, reading the pipe before learning of the exit or not. Returns how the event loop stops,
    /// and whether the invoking process of `sudo -b` is told that the command was executed.
    fn supervise(report: Option<i32>, read_first: bool) -> (StopReason<Supervisor>, bool) {
        let (background, mut invoking) = Background::pair().unwrap();
        let (mut tx, rx) = BinPipe::pair().unwrap();
        let mut registry = EventRegistry::new();
        let mut errpipe = ErrPipe::new(rx, Some(background), &mut registry, ());

        if let Some(error_code) = report {
            tx.write(&error_code).unwrap();
        }
        drop(tx);

        if read_first {
            errpipe.read(&mut registry).unwrap();
        }
        errpipe.command_terminated(1, &mut registry);

        // The supervisor never closes its end, so reading anything but a report would block.
        invoking.set_nonblocking(true).unwrap();
        let executed = invoking.read(&mut [0]).is_ok_and(|len| len == 1);

        (registry.event_loop(&mut Supervisor), executed)
    }

    #[test]
    fn exec_error_outranks_exit_status() {
        for read_first in [true, false] {
            let (StopReason::Break(err), false) = supervise(Some(libc::ENOENT), read_first) else {
                panic!("the exec error was lost (read first: {read_first})");
            };
            assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
        }
    }

    #[test]
    fn executed_command_exits_with_its_status() {
        for read_first in [true, false] {
            let (StopReason::Exit(1), true) = supervise(None, read_first) else {
                panic!("the command was not reported as executed (read first: {read_first})");
            };
        }
    }

    /// Run `command` in the background from a child process, which stands in for the invoking
    /// process. Returns how that exits, and whether run_command failed where it returned: in the
    /// background sudo, or in the invoking process if it did not detach, which then exits with 42.
    fn run_in_background(command: &Path, noexec: bool) -> (Option<i32>, bool) {
        let user = User::real().unwrap().unwrap();
        let group = user.primary_group().unwrap();
        let (mut rx, mut tx) = UnixStream::pair().unwrap();

        // SAFETY: Not really safe, but this is test only code.
        let invoking = unsafe {
            fork_for_test(|| {
                let result = run_command(
                    RunOptions {
                        command,
                        arguments: &[],
                        arg0: None,
                        chdir: None,
                        is_login: false,
                        user: &user,
                        group: &group,
                        umask: Umask::Preserve,
                        background: true,
                        use_pty: false,
                        noexec,
                        groups: None,
                    },
                    std::iter::empty::<(&str, &str)>(),
                );
                tx.write_all(&[u8::from(result.is_err())]).unwrap();
                _exit(42)
            })
        };
        drop(tx);

        let (_, status) = invoking.wait(WaitOptions::new()).unwrap();
        let mut failed = [0];
        rx.read_exact(&mut failed)
            .expect("run_command did not return");
        (status.exit_status(), failed == [1])
    }

    #[test]
    fn background_command_that_cannot_be_executed_fails() {
        // The command does not exist, and without privileges setting its groups already fails.
        let (status, failed) = run_in_background(Path::new("/nonexistent/command"), false);
        assert!(failed, "the background sudo executed the command");
        assert_eq!(status, Some(1));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_noexec_is_refused_before_backgrounding() {
        let (status, failed) = run_in_background(Path::new("/usr/bin/true"), true);
        assert!(failed);
        assert_eq!(
            status,
            Some(42),
            "only the background sudo refused the command"
        );
    }
}
