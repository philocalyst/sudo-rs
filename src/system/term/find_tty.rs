use std::{
    ffi::OsString,
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};

use crate::system::{DeviceId, Process, WithProcess, term::Terminal};

pub(super) fn ttyname_from_dev() -> io::Result<Option<OsString>> {
    let Ok(Some(tty_dev)) = Process::tty_device_id(WithProcess::Current) else {
        return Ok(None);
    };

    let tty_name = dev_check(Path::new("/dev/console"), tty_dev)
        .or_else(|| ttyname_from_stdioe(tty_dev))
        .or_else(|| find_tty_in_dir(Path::new("/dev/pts"), tty_dev))
        .or_else(|| find_tty_in_dir(Path::new("/dev"), tty_dev));

    if tty_name.is_some() {
        Ok(tty_name)
    } else {
        Err(io::ErrorKind::NotFound.into())
    }
}

#[allow(clippy::unnecessary_cast)] // dev_t is signed on Darwin and unsigned on Linux/FreeBSD.
fn is_our_tty(metadata: fs::Metadata, tty_dev: DeviceId) -> bool {
    // Compare in the native dev_t type: Darwin's signed device ids are exposed
    // as sign-extended u64 values by MetadataExt.
    metadata.file_type().is_char_device() && metadata.rdev() as libc::dev_t == tty_dev.inner()
}

fn ttyname_from_stdioe(tty_dev: DeviceId) -> Option<OsString> {
    [
        io::stdin().ttyname(),
        io::stdout().ttyname(),
        io::stderr().ttyname(),
    ]
    .iter()
    .flatten()
    .find_map(|ttyname| dev_check(ttyname.as_ref(), tty_dev))
}

fn dev_check(path: &Path, tty_dev: DeviceId) -> Option<OsString> {
    let metadata = fs::metadata(path).ok()?;

    is_our_tty(metadata, tty_dev).then(|| path.into())
}

fn find_tty_in_dir(dir: &Path, tty_dev: DeviceId) -> Option<OsString> {
    for entry in fs::read_dir(dir).ok()?.filter_map(|entry| entry.ok()) {
        if let Ok(metadata) = entry.metadata() {
            if is_our_tty(metadata, tty_dev) {
                return Some(entry.path().into());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{
        fork_for_test, setsid,
        term::Pty,
        wait::{Wait, WaitOptions},
    };

    #[test]
    fn finds_the_actual_controlling_terminal() {
        // SAFETY: the test helper contains any panic and only the child changes session.
        let child = unsafe {
            fork_for_test(|| {
                setsid().unwrap();
                let pty = Pty::open().unwrap();
                pty.follower.make_controlling_terminal().unwrap();
                let found = ttyname_from_dev().unwrap().unwrap();
                let expected = pty.follower.ttyname().unwrap();
                assert_eq!(
                    fs::metadata(&found).unwrap().rdev(),
                    fs::metadata(&expected).unwrap().rdev()
                );
                crate::system::_exit(0);
            })
        };
        let (_, status) = child.wait(WaitOptions::new()).unwrap();
        assert_eq!(status.exit_status(), Some(0), "{status:?}");
    }
}
