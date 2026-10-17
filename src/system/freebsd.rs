//! The parts of the system interface that FreeBSD provides in its own way.

use std::{
    ffi::{c_int, c_uint},
    io,
};

use super::{DeviceId, ProcessCreateTime, WithProcess, cerr};

/// The clock that counts the time since boot, including time spent asleep.
pub(super) const BOOTTIME: libc::clockid_t = libc::CLOCK_BOOTTIME;

/// Mark the file descriptors from `lowfd` onwards as CLOEXEC.
pub(super) fn close_range_cloexec(lowfd: c_int) -> io::Result<()> {
    // SAFETY: this function is safe to call:
    // - any errors while closing a specific fd will be effectively ignored
    cerr(unsafe {
        libc::close_range(
            lowfd as c_uint,
            c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as c_int,
        )
    })?;

    Ok(())
}

/// List the open file descriptors of the current process.
pub(super) fn open_fds() -> io::Result<Vec<c_int>> {
    super::fds_listed_in("/proc/self/fd")
}

fn get_proc_info(pid: WithProcess) -> std::io::Result<libc::kinfo_proc> {
    use std::ffi::c_void;
    use std::ptr;

    let mut ki_proc: Vec<libc::kinfo_proc> = Vec::with_capacity(1);

    let pid = match pid {
        WithProcess::Current => std::process::id() as i32,
        WithProcess::Other(pid) => pid.inner(),
    };

    loop {
        let mut size = ki_proc.capacity() * size_of::<libc::kinfo_proc>();
        // SAFETY: KERN_PROC_PID only reads data into the ki_proc list. It
        // does not write more than `size` bytes to the pointer.
        match cerr(unsafe {
            libc::sysctl(
                [
                    libc::CTL_KERN,
                    libc::KERN_PROC,
                    libc::KERN_PROC_PID,
                    pid,
                    size_of::<libc::kinfo_proc>() as i32,
                    1,
                ]
                .as_ptr(),
                4,
                ki_proc.as_mut_ptr().cast::<c_void>(),
                &mut size,
                ptr::null(),
                0,
            )
        }) {
            Ok(_) => {
                assert!(size >= size_of::<libc::kinfo_proc>());
                // SAFETY: The above sysctl has initialized at least `size` bytes. We have
                // asserted that this is at least a single element.
                unsafe {
                    ki_proc.set_len(1);
                }
                break;
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                // Vector not big enough. Grow it by 10% and try again.
                ki_proc.reserve(ki_proc.capacity() + (ki_proc.capacity() + 9) / 10);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(ki_proc[0])
}

/// Returns the device identifier of the TTY device that is currently
/// attached to the given process
pub(super) fn tty_device_id(pid: WithProcess) -> std::io::Result<Option<DeviceId>> {
    let ki_proc = get_proc_info(pid)?;

    if ki_proc.ki_tdev == !0 {
        Ok(None)
    } else {
        Ok(Some(DeviceId::new(ki_proc.ki_tdev)))
    }
}

/// Get the process starting time of a specific process
pub(super) fn starting_time(pid: WithProcess) -> io::Result<ProcessCreateTime> {
    let ki_proc = get_proc_info(pid)?;

    let ki_start = ki_proc.ki_start;
    #[allow(clippy::useless_conversion)]
    Ok(ProcessCreateTime::new(
        i64::from(ki_start.tv_sec),
        i64::from(ki_start.tv_usec) * 1000,
    ))
}
