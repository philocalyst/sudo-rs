//! The parts of the system interface that macOS provides in its own way.

use std::{ffi::c_int, io, mem::MaybeUninit};

use super::{DeviceId, Process, ProcessCreateTime, WithProcess, set_errno};

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
