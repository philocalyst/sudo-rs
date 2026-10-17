//! The parts of the system interface that macOS provides in its own way.

use std::{ffi::c_int, io};

use super::{DeviceId, ProcessCreateTime, WithProcess};

/// The clock that counts the time since boot, including time spent asleep. Unlike on Linux,
/// this is what macOS calls CLOCK_MONOTONIC.
pub(super) const BOOTTIME: libc::clockid_t = libc::CLOCK_MONOTONIC;

/// Mark the file descriptors from `lowfd` onwards as CLOEXEC.
pub(super) fn close_range_cloexec(_lowfd: c_int) -> io::Result<()> {
    // macOS has no close_range
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// List the open file descriptors of the current process.
pub(super) fn open_fds() -> io::Result<Vec<c_int>> {
    super::fds_listed_in("/dev/fd")
}

/// Returns the device identifier of the TTY device that is currently
/// attached to the given process
pub(super) fn tty_device_id(pid: WithProcess) -> std::io::Result<Option<DeviceId>> {
    Ok(None)
}

/// Get the process starting time of a specific process
pub(super) fn starting_time(pid: WithProcess) -> io::Result<ProcessCreateTime> {
    Ok(ProcessCreateTime::new(0, 0))
}
