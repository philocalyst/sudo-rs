//! Darwin process queries. Keep the platform ABI details out of the execution pipeline.

use std::io;

use super::{Process, set_cloexec};

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
}
