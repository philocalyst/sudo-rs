//! Running the command in the background, as `sudo -b` does.

use std::{
    ffi::c_int,
    io::{self, Read},
    mem::ManuallyDrop,
    os::{fd::AsRawFd, unix::net::UnixStream},
    process,
};

use crate::{
    log::dev_warn,
    system::{
        _exit, ForkResult, fork,
        interface::ProcessId,
        setpgid,
        wait::{Wait, WaitError, WaitOptions},
    },
};

use super::io_util::{retry_while_interrupted, was_interrupted};

/// Continue in the background, from where the returned [`Background`] reports that the command
/// was executed.
///
/// The invoking process waits for that report, but not for the command to finish. It exits with
/// status 0 once the command has been executed, or with status 1 if it could not be, after sudo
/// has reported why. Original sudo exits successfully as soon as it has forked instead, so there
/// `sudo -b` appears to succeed even when the command never runs.
///
/// Like original sudo, the supervisor cannot tell a command that was executed from a command
/// process that was killed before it got to execute it, so that also counts as executed. While it
/// waits, the invoking process handles signals as usual, so it can still be interrupted; the
/// command runs regardless.
pub(super) fn detach() -> io::Result<Background> {
    let (report_tx, mut report_rx) = UnixStream::pair()?;

    // SAFETY: There should be no other threads at this point.
    let ForkResult::Parent(child_pid) = unsafe { fork() }? else {
        drop(report_rx);

        // Fork once more and exit right away, so that the command runs in an orphaned process
        // group, as it does with original sudo, whose invoking process exits right after forking.
        // A process group is orphaned once none of its members has a parent in another process
        // group of the same session, so a child of the waiting invoking process would keep it
        // from being orphaned, see
        // <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap03.html#tag_03_247>.
        // SAFETY: There should be no other threads at this point.
        match unsafe { fork() } {
            Ok(ForkResult::Parent(_)) => _exit(0),
            Ok(ForkResult::Child) => {}
            // The invoking process takes the exit status for the error number.
            Err(err) => _exit(err.raw_os_error().unwrap_or(libc::EIO)),
        }

        // From here on, the invoking process waits for this process to exit if anything fails.
        let background = Background(ManuallyDrop::new(report_tx));

        // Child continues in an orphaned process group.
        // Reads from the terminal fail with EIO.
        // Writes succeed unless tostop is set on the terminal.
        // See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap11.html#tag_11_01_04>.
        setpgid(ProcessId::new(0), ProcessId::new(0))?;

        return Ok(background);
    };
    drop(report_tx);

    if let Some(error_code) = fork_error(child_pid) {
        return Err(io::Error::from_raw_os_error(error_code));
    }

    let mut executed = [0];
    match retry_while_interrupted(|| report_rx.read(&mut executed)) {
        Ok(1) => process::exit(0),
        // Every process of the background sudo has exited without the command being executed.
        _ => process::exit(1),
    }
}

/// The error number that the child exits with if it could not fork the background sudo.
fn fork_error(child_pid: ProcessId) -> Option<c_int> {
    loop {
        match child_pid.wait(WaitOptions::new()) {
            Err(WaitError::Io(err)) if was_interrupted(&err) => {}
            Ok((_, status)) => return status.exit_status().filter(|&code| code != 0),
            // Assume that the child did fork, so that the background sudo gets to report.
            Err(_) => return None,
        }
    }
}

/// Reports to the invoking process of `sudo -b` that the command was executed.
///
/// Every process of the background sudo keeps this open until it exits, or until it executes the
/// command, as it is close-on-exec. So the invoking process stops waiting for a report only once
/// all of them have exited, after they have reported why the command could not be executed.
pub(super) struct Background(ManuallyDrop<UnixStream>);

impl Background {
    /// Tell the invoking process that the command was executed.
    pub(super) fn report_executed(self) {
        let report = [1u8];
        // MSG_NOSIGNAL: should the invoking process be gone, fail with EPIPE rather than raise
        // SIGPIPE.
        // SAFETY: A valid socket and a valid buffer of the given length are passed in.
        let sent = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                report.as_ptr().cast(),
                report.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent == -1 {
            let err = io::Error::last_os_error();
            dev_warn!("cannot report to the invoking process that the command was executed: {err}");
        }
    }
}

#[cfg(test)]
impl Background {
    /// A report stream, and the end of it that the invoking process reads from.
    pub(super) fn pair() -> io::Result<(Self, UnixStream)> {
        let (report_tx, report_rx) = UnixStream::pair()?;
        Ok((Self(ManuallyDrop::new(report_tx)), report_rx))
    }
}
