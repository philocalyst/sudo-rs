//! Darwin process queries. Keep the platform ABI details out of the execution pipeline.

use std::{
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd, BorrowedFd},
};

use super::{Process, WithProcess, set_cloexec};

/// Ask the kernel about access to the opened vnode as the invoking user.
/// A path-based access check would introduce a rename race.
///
/// `user` must be the account this process really runs as. sudo-rs is
/// installed set-user-ID but not set-group-ID, so the effective group and the
/// supplementary groups are already the invoking user's and only the effective
/// user id has to be swapped for the kernel's own check below.
pub(super) fn real_user_can_write(fd: BorrowedFd<'_>, user: &super::User) -> io::Result<bool> {
    // SAFETY: getuid cannot fail or cause memory unsafety.
    debug_assert_eq!(unsafe { libc::getuid() }, user.uid.inner());
    kernel_real_user_can_write(fd)
}

fn kernel_real_user_can_write(fd: BorrowedFd<'_>) -> io::Result<bool> {
    struct RestoreEuid(libc::uid_t);
    impl Drop for RestoreEuid {
        fn drop(&mut self) {
            // SAFETY: seteuid does not access memory and restores the saved identity.
            crate::cutils::cerr(unsafe { libc::seteuid(self.0) })
                .expect("could not restore effective user id");
        }
    }
    // SAFETY: these credential queries cannot fail or cause memory unsafety.
    let (real, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
    let _restore = if real != effective {
        // SAFETY: only the effective identity changes; saved root is preserved.
        crate::cutils::cerr(unsafe { libc::seteuid(real) })?;
        Some(RestoreEuid(effective))
    } else {
        None
    };
    // getattrlist(2): ATTR_CMN_USERACCESS reports "the effective permissions
    // of the current user", so the swap above is what makes this the invoking
    // user's answer rather than root's.
    let mut attrs = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_USERACCESS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    #[repr(C)]
    struct Access {
        length: u32,
        returned: libc::attribute_set_t,
        access: u32,
    }
    let mut access = MaybeUninit::<Access>::uninit();
    // SAFETY: fgetattrlist receives valid attribute masks and a correctly sized,
    // aligned output buffer containing only integer fields.
    crate::cutils::cerr(unsafe {
        libc::fgetattrlist(
            fd.as_raw_fd(),
            (&mut attrs as *mut libc::attrlist).cast(),
            access.as_mut_ptr().cast(),
            size_of::<Access>(),
            0,
        )
    })?;
    // Only read the leading length until the kernel confirms the whole buffer.
    // SAFETY: a successful fgetattrlist always writes the initial u32 length.
    let length = unsafe { access.as_ptr().cast::<u32>().read() };
    if length as usize != size_of::<Access>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete file access attributes",
        ));
    }
    // SAFETY: the kernel returned all bytes of Access.
    let access = unsafe { access.assume_init() };
    if access.returned.commonattr & libc::ATTR_CMN_USERACCESS == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file access attributes unavailable",
        ));
    }
    Ok(access.access & libc::W_OK as u32 != 0)
}

/// Query one process' BSD info.
///
/// `proc_pidinfo` reports the number of bytes it wrote, and reports failure as
/// zero with `errno` set rather than as -1, so a short or empty answer is never
/// mistaken for a zeroed identity.
pub(super) fn process_info(process: WithProcess) -> io::Result<libc::proc_bsdinfo> {
    let pid = match process {
        WithProcess::Current => Process::process_id().inner(),
        WithProcess::Other(pid) => pid.inner(),
    };
    if pid <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: PROC_PIDTBSDINFO writes at most size bytes to a correctly aligned buffer.
    let filled = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if filled <= 0 {
        return Err(io::Error::last_os_error());
    }
    if filled != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete process information",
        ));
    }
    // SAFETY: the successful query initialized the entire proc_bsdinfo.
    Ok(unsafe { info.assume_init() })
}

/// Collect this process' open descriptors.
///
/// `query` reports bytes written, and a buffer it filled completely may be a
/// truncated snapshot: descriptors can be opened between two calls, so the
/// buffer grows and the query runs again instead of trusting a fixed margin.
fn list_fds(
    mut query: impl FnMut(&mut [libc::proc_fdinfo]) -> io::Result<usize>,
) -> io::Result<Vec<libc::proc_fdinfo>> {
    let entry_size = size_of::<libc::proc_fdinfo>();
    let max_entries = i32::MAX as usize / entry_size;
    let mut buffer = vec![
        libc::proc_fdinfo {
            proc_fd: -1,
            proc_fdtype: 0
        };
        32
    ];
    loop {
        let bytes = query(&mut buffer)?;
        if bytes > buffer.len() * entry_size || bytes % entry_size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid descriptor list size",
            ));
        }
        if bytes < buffer.len() * entry_size {
            buffer.truncate(bytes / entry_size);
            return Ok(buffer);
        }
        // A full buffer may be a truncated snapshot. Grow and query again instead
        // of assuming a fixed amount of spare space covers newly opened fds.
        let next = (buffer.len() * 2).min(max_entries);
        if next == buffer.len() {
            return Err(io::Error::other("descriptor list is too large"));
        }
        buffer
            .try_reserve_exact(next - buffer.len())
            .map_err(io::Error::other)?;
        buffer.resize(
            next,
            libc::proc_fdinfo {
                proc_fd: -1,
                proc_fdtype: 0,
            },
        );
    }
}

/// Mark every descriptor at or above `lowfd` close-on-exec.
///
/// Returns `Ok(false)` when the descriptor list could not be obtained at all,
/// which tells the caller to fall back to walking `/dev/fd`. A descriptor that
/// is listed but then fails to be marked is an error: leaving it open across
/// the exec is exactly what this is here to prevent.
pub(super) fn mark_fds_as_cloexec(lowfd: i32) -> io::Result<bool> {
    let pid = Process::process_id().inner();
    let fds = list_fds(|buffer| {
        let bytes = (size_of_val(buffer)) as i32;
        // SAFETY: the buffer is initialized, aligned, and exactly bytes long.
        let filled = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buffer.as_mut_ptr().cast(),
                bytes,
            )
        };
        if filled <= 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(filled as usize)
        }
    });
    let Ok(fds) = fds else {
        return Ok(false);
    };
    for info in fds {
        if info.proc_fd >= lowfd {
            set_cloexec(info.proc_fd)?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnode_access_follows_the_real_user() {
        use std::{
            fs::{self, File},
            os::{fd::AsFd, unix::fs::PermissionsExt},
        };
        let user = super::super::User::real().unwrap().unwrap();
        let dir = super::super::file::create_temporary_dir().unwrap();
        let path = dir.join("vnode-access");
        let file = File::create(&path).unwrap();
        // SAFETY: geteuid is always safe to call.
        let effective = unsafe { libc::geteuid() };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(real_user_can_write(file.as_fd(), &user).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        if user.uid != super::super::UserId::ROOT {
            assert!(!real_user_can_write(file.as_fd(), &user).unwrap());
        }
        // SAFETY: geteuid is always safe to call.
        assert_eq!(unsafe { libc::geteuid() }, effective);
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn process_identity_and_controlling_terminal_are_real() {
        use super::super::{
            _exit as exit, DeviceId,
            WithProcess::*,
            fork_for_test,
            interface::ProcessId,
            setsid,
            term::{Pty, Terminal},
            wait::{Wait, WaitOptions},
        };
        use std::os::fd::AsFd;
        // SAFETY: test-only fork helper contains any panic in the child.
        let child = unsafe {
            fork_for_test(|| {
                let original = Process::starting_time(Current).unwrap();
                assert_eq!(
                    original,
                    Process::starting_time(Other(Process::process_id())).unwrap()
                );
                let info = process_info(Current).unwrap();
                assert!(info.pbi_start_tvsec > 0);
                setsid().unwrap();
                assert_eq!(Process::tty_device_id(Current).unwrap(), None);
                let pty = Pty::open().unwrap();
                pty.follower.make_controlling_terminal().unwrap();
                let fd = pty.follower.as_fd();
                let mut stat = MaybeUninit::<libc::stat>::uninit();
                // SAFETY: valid descriptor and correctly sized stat buffer.
                crate::cutils::cerr(libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr())).unwrap();
                // SAFETY: fstat succeeded and initialized the stat struct.
                let expected = DeviceId::new(stat.assume_init().st_rdev);
                assert_eq!(Process::tty_device_id(Current).unwrap(), Some(expected));
                assert_eq!(
                    Process::tty_device_id(Other(ProcessId::new(std::process::id() as i32)))
                        .unwrap(),
                    Some(expected)
                );
                assert_eq!(Process::starting_time(Current).unwrap(), original);
                exit(0);
            })
        };
        let (_, status) = child.wait(WaitOptions::new()).unwrap();
        assert_eq!(status.exit_status(), Some(0));
    }

    #[test]
    fn descriptor_list_retries_truncated_and_growing_snapshots() {
        let mut calls = 0;
        let fds = list_fds(|buffer| {
            calls += 1;
            // The process opens more than the old four-entry margin between calls.
            let count = if calls == 1 { 40 } else { 100 };
            let filled = count.min(buffer.len());
            for (i, entry) in buffer[..filled].iter_mut().enumerate() {
                entry.proc_fd = i as i32;
            }
            Ok(filled * size_of::<libc::proc_fdinfo>())
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(fds.len(), 100);
        assert_eq!(fds.last().unwrap().proc_fd, 99);
    }

    #[test]
    fn descriptor_list_rejects_partial_entries_and_errors() {
        assert!(list_fds(|_| Ok(1)).is_err());
        assert!(list_fds(|buffer| Ok(size_of_val(buffer) + 8)).is_err());
        assert!(list_fds(|_| Err(io::Error::from_raw_os_error(libc::EPERM))).is_err());
    }

    #[test]
    fn process_queries_reject_invalid_pids() {
        use super::super::interface::ProcessId;
        for pid in [0, -1, i32::MAX] {
            assert!(process_info(WithProcess::Other(ProcessId::new(pid))).is_err());
        }
    }
}
