//! A background caller succeeds only after its supervisor confirms exec.
use std::{io, process};

use crate::{
    common::bin_serde::BinPipe,
    system::{ForkResult, fork, interface::ProcessId, setpgid},
};

use super::io_util::retry_while_interrupted;

#[derive(Default)]
pub(super) struct BackgroundStatus(Option<BinPipe<i32>>);

impl BackgroundStatus {
    pub(super) fn start(background: bool) -> io::Result<Self> {
        if !background {
            return Ok(Self::default());
        }
        let (tx, mut rx) = BinPipe::pair()?;
        // SAFETY: The caller has not started any other threads yet.
        match unsafe { fork() }? {
            ForkResult::Parent(_) => {
                drop(tx);
                // The worker owns PAM session cleanup and diagnostics, including
                // on failure. Returning here would run both a second time.
                let code = match retry_while_interrupted(|| rx.read()) {
                    Ok(0) => 0,
                    Ok(_) => 1,
                    Err(err) => {
                        crate::log::user_error!(
                            "background command did not confirm execution: {error}",
                            error = err,
                        );
                        1
                    }
                };
                process::exit(code)
            }
            ForkResult::Child => {
                drop(rx);
                let status = Self(Some(tx));
                // Keep the existing background process-group semantics.
                setpgid(ProcessId::new(0), ProcessId::new(0))?;
                Ok(status)
            }
        }
    }

    pub(super) fn started(&mut self) -> io::Result<()> {
        if let Some(mut tx) = self.0.take() {
            retry_while_interrupted(|| tx.write(&0))?;
        }
        Ok(())
    }

    pub(super) fn failed(&mut self, err: &io::Error) {
        if let Some(mut tx) = self.0.take() {
            let errno = err.raw_os_error().unwrap_or(libc::EIO);
            let _ = retry_while_interrupted(|| tx.write(&errno));
        }
    }

    /// Discard a copy inherited by a different supervisor after fork.
    pub(super) fn disarm(mut self) {
        self.0.take();
    }
}

impl Drop for BackgroundStatus {
    fn drop(&mut self) {
        // Early setup failures must never be mistaken for a launch acknowledgement.
        self.failed(&io::Error::from_raw_os_error(libc::EIO));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_an_explicit_launch_acknowledgement() {
        let (tx, mut rx) = BinPipe::pair().unwrap();
        let mut status = BackgroundStatus(Some(tx));
        status.started().unwrap();
        assert_eq!(rx.read().unwrap(), 0);

        let (tx, mut rx) = BinPipe::pair().unwrap();
        drop(BackgroundStatus(Some(tx)));
        assert_eq!(rx.read().unwrap(), libc::EIO);

        let (tx, mut rx) = BinPipe::pair().unwrap();
        let mut status = BackgroundStatus(Some(tx));
        status.failed(&io::Error::from_raw_os_error(libc::ENOSYS));
        assert_eq!(rx.read().unwrap(), libc::ENOSYS);

        let (tx, mut rx) = BinPipe::pair().unwrap();
        BackgroundStatus(Some(tx)).disarm();
        assert_eq!(rx.read().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
