//! The parts of the system interface that macOS provides in its own way.

use std::{
    ffi::{CStr, c_int, c_uint},
    io,
    mem::MaybeUninit,
};

use crate::cutils::cerr;

use super::{DeviceId, GroupId, Process, ProcessCreateTime, UserId, WithProcess, set_errno};

/// The clock that counts the time since boot, including time spent asleep. Unlike on Linux,
/// this is what macOS calls CLOCK_MONOTONIC, see clock_gettime(3).
pub(super) const BOOTTIME: libc::clockid_t = libc::CLOCK_MONOTONIC;

/// Mark the file descriptors from `lowfd` onwards as CLOEXEC.
pub(super) fn close_range_cloexec(_lowfd: c_int) -> io::Result<()> {
    // macOS has no close_range
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// List the open file descriptors of the current process.
pub(super) fn open_fds() -> io::Result<Vec<c_int>> {
    use libc::{PROC_PIDLISTFDS, proc_fdinfo, proc_pidinfo};

    let pid = Process::process_id().inner();
    let entry_size = size_of::<proc_fdinfo>();

    // Without a buffer, proc_pidinfo reports how much room the descriptor table needs. One
    // more entry than that tells a complete list apart from one that was cut short.
    // SAFETY: a null buffer with a size of zero only asks for the required size.
    let needed = proc_pidinfo_bytes(|| unsafe {
        proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    })?;
    let mut capacity = needed / entry_size + 1;

    loop {
        let mut entries = Vec::<proc_fdinfo>::with_capacity(capacity);
        let size = c_int::try_from(capacity * entry_size)
            .map_err(|_| io::Error::other("too many open file descriptors"))?;
        // SAFETY: the buffer has room for `size` bytes.
        let filled = proc_pidinfo_bytes(|| unsafe {
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, entries.as_mut_ptr().cast(), size)
        })? / entry_size;

        if filled < capacity {
            // SAFETY: proc_pidinfo initialized the first `filled` entries.
            unsafe { entries.set_len(filled) };
            return Ok(entries.iter().map(|entry| entry.proc_fd).collect());
        }

        // The table grew since it was measured, and proc_pidinfo silently truncates,
        // see https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/proc_info.c#L514-L549
        capacity *= 2;
    }
}

/// Returns the device identifier of the TTY device that is currently
/// attached to the given process
pub(super) fn tty_device_id(pid: WithProcess) -> std::io::Result<Option<DeviceId>> {
    let info = bsd_info(pid)?;

    // e_tdev holds the bits of a dev_t, which is signed on macOS; without a controlling
    // terminal, it is NODEV (-1), see https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/proc_info.c#L818-L826
    match info.e_tdev as libc::dev_t {
        -1 => Ok(None),
        tty_device => Ok(Some(DeviceId::new(tty_device))),
    }
}

/// Get the process starting time of a specific process
pub(super) fn starting_time(pid: WithProcess) -> io::Result<ProcessCreateTime> {
    let info = bsd_info(pid)?;

    Ok(ProcessCreateTime::new(
        info.pbi_start_tvsec as i64,
        info.pbi_start_tvusec as i64 * 1000,
    ))
}

/// The BSD-level information about a process, which is where macOS records its terminal and
/// start time.
fn bsd_info(pid: WithProcess) -> io::Result<libc::proc_bsdinfo> {
    let pid = match pid {
        WithProcess::Current => Process::process_id(),
        WithProcess::Other(pid) => pid,
    };

    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = size_of::<libc::proc_bsdinfo>();
    // SAFETY: the buffer has room for `size` bytes.
    let written = proc_pidinfo_bytes(|| unsafe {
        libc::proc_pidinfo(
            pid.inner(),
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as c_int,
        )
    })?;

    if written != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc_pidinfo returned an incomplete proc_bsdinfo",
        ));
    }

    // SAFETY: proc_pidinfo initialized the whole structure.
    Ok(unsafe { info.assume_init() })
}

/// Run a proc_pidinfo query, returning the number of bytes it wrote.
///
/// proc_pidinfo reports failure by returning 0 and setting errno, which is not otherwise
/// distinguishable from a successful query with nothing to report, see
/// https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/libsyscall/wrappers/libproc/libproc.c#L101-L110
fn proc_pidinfo_bytes(query: impl FnOnce() -> c_int) -> io::Result<usize> {
    set_errno(0);
    let written = query();
    let error = io::Error::last_os_error();
    match usize::try_from(written) {
        Ok(0) if error.raw_os_error() != Some(0) => Err(error),
        Ok(written) => Ok(written),
        Err(_) => Err(error),
    }
}

/// The number of groups that a credential caches, see
/// https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/sys/syslimits.h#L104
const NGROUPS: usize = 16;

unsafe extern "C" {
    /// The system call that initgroups(3) ends in: it gives the current process the
    /// `gidsetsize` groups at `gidset`, and lets the kernel ask Open Directory about the other
    /// groups of the account `gmuid` when it checks membership. It is private to the system, but
    /// libsystem_kernel exports it for initgroups in Libinfo, see
    /// https://github.com/apple-oss-distributions/Libinfo/blob/Libinfo-600/lookup.subproj/libinfo.c#L894-L939
    /// and https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_prot.c#L1402-L1435
    fn __initgroups(gidsetsize: c_uint, gidset: *const libc::gid_t, gmuid: c_int) -> c_int;
}

/// The groups that initgroups(3) has the credential cache for the account `name` with the
/// primary group `primary`: that group first, then as many others of the account as fit.
pub(super) fn cached_groups(name: &CStr, primary: GroupId) -> Vec<GroupId> {
    let mut groups = vec![primary; NGROUPS];
    let mut len = NGROUPS as c_int;
    // Like initgroups, ignore that the account may be in more groups than fit.
    // SAFETY: `groups` has room for `len` groups, and a GroupId is a gid_t, which getgrouplist
    // takes as an int.
    unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary.inner() as c_int,
            groups.as_mut_ptr().cast(),
            &mut len,
        )
    };
    groups.truncate(len as usize);
    groups
}

/// Give the current process the `cached` groups of the account `member`, like initgroups(3)
/// does after looking them up. Unlike that lookup, this only makes a system call, so it is
/// async-signal-safe.
pub(super) fn set_cached_groups(cached: &[GroupId], member: UserId) -> io::Result<()> {
    // SAFETY: `cached` holds as many groups as its length says, and a GroupId is a gid_t.
    cerr(unsafe {
        __initgroups(
            cached.len() as c_uint,
            cached.as_ptr().cast(),
            member.inner() as c_int,
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NGROUPS, cached_groups};
    use crate::system::User;

    #[test]
    fn caches_what_initgroups_does() {
        let user = User::real().unwrap().unwrap();

        // The groups of a User come from getgrouplist with room for all of them, which initgroups
        // asks with room for no more than a credential caches.
        let cached = cached_groups(user.name.as_cstr(), user.gid);
        assert_eq!(cached, user.groups[..user.groups.len().min(NGROUPS)]);
        assert_eq!(cached[0], user.gid);
    }
}
