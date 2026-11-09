//! Darwin process queries. Keep the platform ABI details out of the execution pipeline.

use std::{io, mem::MaybeUninit};

use super::{GroupId, Process, UserId, WithProcess, set_cloexec};

/// membership.h includes nested Open Directory memberships that need not appear
/// in getgroups/getgrouplist's advisory group list. These APIs return errno
/// values directly, rather than setting errno and returning -1.
pub(super) fn is_group_member(uid: UserId, gid: GroupId) -> io::Result<bool> {
    unsafe extern "C" {
        fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
        fn mbr_gid_to_uuid(gid: libc::gid_t, uuid: *mut u8) -> libc::c_int;
        fn mbr_check_membership(
            user: *const u8,
            group: *const u8,
            member: *mut libc::c_int,
        ) -> libc::c_int;
    }
    let (mut user, mut group) = ([0u8; 16], [0u8; 16]);
    // SAFETY: both UUID buffers have the sixteen bytes required by uuid_t.
    let result = unsafe { mbr_uid_to_uuid(uid.inner(), user.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    // SAFETY: group points to sixteen initialized writable bytes.
    let result = unsafe { mbr_gid_to_uuid(gid.inner(), group.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    let mut member = 0;
    // SAFETY: both UUIDs are initialized, and member is a valid output pointer.
    let result = unsafe { mbr_check_membership(user.as_ptr(), group.as_ptr(), &mut member) };
    match result {
        0 => Ok(member != 0),
        // Synthesized UUIDs can denote accounts/groups that no longer exist.
        libc::ENOENT => Ok(false),
        _ => Err(io::Error::from_raw_os_error(result)),
    }
}

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

/// Return false if enumeration fails, so the caller can fall back to /dev/fd.
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
    let Ok(fds) = fds else { return Ok(false) };
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
    fn directory_membership_recognizes_the_primary_group() {
        let user = super::super::User::real().unwrap().unwrap();
        assert!(is_group_member(user.uid, user.gid).unwrap());
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
        use std::os::fd::{AsFd, AsRawFd};
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
