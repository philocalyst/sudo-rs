//! The parts of the system interface that Linux provides in its own way, mostly through
//! /proc.

use std::{
    ffi::{c_int, c_uint},
    io,
    path::PathBuf,
    str::FromStr,
};

use super::{DeviceId, ProcessCreateTime, WithProcess, cerr};

/// The clock that counts the time since boot, including time spent asleep.
pub(super) const BOOTTIME: libc::clockid_t = libc::CLOCK_BOOTTIME;

/// Mark the file descriptors from `lowfd` onwards as CLOEXEC.
pub(super) fn close_range_cloexec(lowfd: c_int) -> io::Result<()> {
    // close_range was only added in glibc 2.34, and is not
    // part of musl, so we go perform a straight syscall instead
    // SAFETY: this function is safe to call:
    // - any errors while closing a specific fd will be effectively ignored
    cerr(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            lowfd as c_uint,
            c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as c_uint,
        )
    })?;

    Ok(())
}

/// List the open file descriptors of the current process.
pub(super) fn open_fds() -> io::Result<Vec<c_int>> {
    super::fds_listed_in("/proc/self/fd")
}

/// Returns the device identifier of the TTY device that is currently
/// attached to the given process
pub(super) fn tty_device_id(pid: WithProcess) -> std::io::Result<Option<DeviceId>> {
    // device id of tty is displayed as a signed integer of 32 bits
    let data: i32 = read_proc_stat(pid, 6 /* tty_nr */)?;
    if data == 0 {
        Ok(None)
    } else {
        // While the integer was displayed as signed in the proc stat file,
        // we actually need to interpret the bits of that integer as an unsigned
        // int. We convert via u32 because a direct conversion to DeviceId
        // would use sign extension, which would result in a different bit
        // representation
        Ok(Some(DeviceId::new(data as u64)))
    }
}

/// Get the process starting time of a specific process
pub(super) fn starting_time(pid: WithProcess) -> io::Result<ProcessCreateTime> {
    let process_start: u64 = read_proc_stat(pid, 21 /* start_time */)?;

    // the startime field is stored in ticks since the system start, so we need to know how many
    // ticks go into a second
    let ticks_per_second = crate::cutils::sysconf(libc::_SC_CLK_TCK).ok_or_else(|| {
        io::Error::other("Could not retrieve system config variable for ticks per second")
    })? as u64;

    // finally compute the system time at which the process was started
    Ok(ProcessCreateTime::new(
        (process_start / ticks_per_second) as i64,
        ((process_start % ticks_per_second) * (1_000_000_000 / ticks_per_second)) as i64,
    ))
}

impl WithProcess {
    fn to_proc_string(&self) -> String {
        match self {
            WithProcess::Current => "self".into(),
            WithProcess::Other(pid) => pid.to_string(),
        }
    }
}

/// Read the n-th field (with 0-based indexing) from `/proc/<pid>/self`.
///
/// See ["Table 1-4: Contents of the stat fields" of "The /proc
/// Filesystem"][proc_stat_fields] in the Linux docs for all available fields.
///
/// IMPORTANT: the first two fields are not accessible with this routine.
///
/// [proc_stat_fields]: https://www.kernel.org/doc/html/latest/filesystems/proc.html#id10
fn read_proc_stat<T: FromStr>(pid: WithProcess, field_idx: isize) -> io::Result<T> {
    // the first two fields are skipped by the code below, and we never need them,
    // so no point in implementing code for it in this private function.
    debug_assert!(field_idx >= 2);

    // read from a specific pid file, or use `self` to refer to our own process
    let pidref = pid.to_proc_string();

    // read the data from the stat file for the process with the given pid
    let path = PathBuf::from_iter(&["/proc", &pidref, "stat"]);
    let proc_stat = std::fs::read(path)?;

    // first get the part of the stat file past the second argument, we then reverse
    // search for a ')' character and start the search for the starttime field from there on
    let skip_past_second_arg = proc_stat.iter().rposition(|b| *b == b')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Could not find position of 'comm' field in process stat",
        )
    })?;
    let mut stat = &proc_stat[skip_past_second_arg..];

    // we've now passed the first two fields, so we are at index 1, now we skip over
    // fields until we arrive at the field we are searching for
    let mut curr_field = 1;
    while curr_field < field_idx && !stat.is_empty() {
        if stat[0] == b' ' {
            curr_field += 1;
        }
        stat = &stat[1..];
    }

    // The expected field cannot be in the file anymore when we are at EOF
    if stat.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Stat file was not of the expected format",
        ));
    }

    // we've now arrived at the field we are looking for, we now check how
    // long this field is by finding where the next space is
    let mut idx = 0;
    while stat[idx] != b' ' && idx < stat.len() {
        idx += 1;
    }
    let field = &stat[0..idx];

    // we first convert the data to a string slice, this should not fail with a normal /proc filesystem
    let fielddata = std::str::from_utf8(field).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Could not interpret byte slice as string",
        )
    })?;

    // then we convert the string slice to whatever the requested type was
    fielddata.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Could not interpret string as number",
        )
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn proc_stat_test() {
        use super::super::{Process, WithProcess::Current, interface::ProcessId};
        use super::read_proc_stat;
        // The process can be '(uninterruptible) sleeping' or 'running': it looks like the state
        // field of /proc/pid/stat will show the state for the main thread of the process rather
        // than for the process as a whole.
        let state = read_proc_stat::<char>(Current, 2).unwrap();
        assert!("SDR".contains(state), "{state} is not S, D or R");
        let parent = Process::parent_id().unwrap();
        // field 3 is always the parent process
        assert_eq!(
            parent,
            ProcessId::new(read_proc_stat::<i32>(Current, 3).unwrap())
        );
        // this next field should always be 0 (which precedes an important bit of info for us!)
        assert_eq!(0, read_proc_stat::<i32>(Current, 20).unwrap());
    }
}
