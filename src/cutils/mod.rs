use std::{
    ffi::{CStr, OsStr, OsString, c_char, c_int, c_long},
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::OsStrExt,
    },
};

pub fn cerr<Int: Copy + TryInto<c_long>>(res: Int) -> std::io::Result<Int> {
    match res.try_into() {
        Ok(-1) => Err(std::io::Error::last_os_error()),
        _ => Ok(res),
    }
}

unsafe extern "C" {
    #[cfg_attr(
        any(target_os = "macos", target_os = "ios", target_os = "freebsd"),
        link_name = "__error"
    )]
    #[cfg_attr(
        any(target_os = "openbsd", target_os = "netbsd", target_os = "android"),
        link_name = "__errno"
    )]
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    safe fn errno_location() -> *mut c_int;
}

pub fn set_errno(no: c_int) {
    // SAFETY: errno_location is a thread-local pointer to an integer, so we are the only writers
    unsafe { *errno_location() = no };
}

pub fn sysconf(name: c_int) -> Option<c_long> {
    set_errno(0);
    // SAFETY: sysconf will always respond with 0 or -1 for every input
    cerr(unsafe { libc::sysconf(name) }).ok()
}

/// Create a Rust string copy from a C string pointer
/// WARNING: This uses `to_string_lossy` so should not be used for data where
/// information loss is unacceptable (use `os_string_from_ptr` instead)
///
/// # Safety
/// This function assumes that the pointer is either a null pointer or that
/// it points to a valid NUL-terminated C string.
pub unsafe fn string_from_ptr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the function contract says that CStr::from_ptr is safe
        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_string_lossy().to_string()
    }
}

/// Create an `OsString` copy from a C string pointer.
///
/// # Safety
/// This function assumes that the pointer is either a null pointer or that
/// it points to a valid NUL-terminated C string.
pub unsafe fn os_string_from_ptr(ptr: *const c_char) -> OsString {
    if ptr.is_null() {
        OsString::new()
    } else {
        // SAFETY: the function contract says that CStr::from_ptr is safe
        let cstr = unsafe { CStr::from_ptr(ptr) };
        OsStr::from_bytes(cstr.to_bytes()).to_owned()
    }
}

fn fstat_mode_any<const MASK: libc::mode_t>(fildes: &BorrowedFd) -> bool {
    const {
        assert!(MASK & libc::S_IFMT == MASK);
    }

    // The Rust standard library doesn't have FileTypeExt on Std{in,out,err}, so we
    // can't just use FileTypeExt::is_char_device and have to resort to libc::fstat.
    let mut maybe_stat = std::mem::MaybeUninit::<libc::stat>::uninit();

    // SAFETY: we are passing fstat a pointer to valid memory
    if unsafe { libc::fstat(fildes.as_raw_fd(), maybe_stat.as_mut_ptr()) } == 0 {
        // SAFETY: if `fstat` returned 0, maybe_stat will be initialized
        let mode = unsafe { maybe_stat.assume_init() }.st_mode;

        // To complicate matters further, the S_ISCHR macro isn't in libc as well.
        (mode & MASK) != 0
    } else {
        false
    }
}

/// Rust's standard library IsTerminal just directly calls isatty, which
/// we don't want since this performs IOCTL calls on them and file descriptors are under
/// the control of the user; so this checks if they are a character device first.
pub fn safe_isatty(fildes: BorrowedFd) -> bool {
    let is_char_device = fstat_mode_any::<{ libc::S_IFCHR }>(&fildes);

    if is_char_device {
        // SAFETY: isatty will return 0 or 1
        unsafe { libc::isatty(fildes.as_raw_fd()) != 0 }
    } else {
        false
    }
}

/// Check whether the file descriptor is a pipe or socket
pub fn is_fifo_or_sock(fildes: BorrowedFd) -> bool {
    fstat_mode_any::<{ libc::S_IFIFO | libc::S_IFSOCK }>(&fildes)
}

/// Dynamically obtain the correct buffer size (within bounds)
pub fn dynamic_fill<T: Default + Copy, E>(
    range: std::ops::Range<usize>,
    mut fill: impl FnMut(&mut [T]) -> Result<Option<usize>, E>,
) -> Result<Option<Vec<T>>, E> {
    let mut buffer = vec![T::default(); range.start];
    loop {
        match fill(&mut buffer)? {
            Some(len) => {
                buffer.resize_with(len, || {
                    panic!("closure returned a buffer size that was larger than the input, this should not happen")
                });

                return Ok(Some(buffer));
            }

            None => {
                if buffer.len() >= range.end {
                    return Ok(None);
                } else {
                    buffer.resize_with(std::cmp::min(buffer.len() * 2, range.end), T::default)
                }
            }
        }
    }
}

/// Create a pipe whose two ends are closed on exec.
pub fn pipe() -> std::io::Result<[OwnedFd; 2]> {
    let mut pipes = [-1; 2];
    // SAFETY: both calls initialize exactly two descriptors on success.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
    cerr(unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: pipes has room for both descriptors.
    #[cfg(target_os = "macos")]
    cerr(unsafe { libc::pipe(pipes.as_mut_ptr()) })?;

    let pipes = pipes.map(|fd| {
        // SAFETY: pipe/pipe2 returned two new, owned descriptors.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    #[cfg(target_os = "macos")]
    for fd in &pipes {
        use std::os::fd::AsRawFd;
        // macOS has no pipe2. FD_CLOEXEC is a descriptor flag (F_SETFD),
        // not a file status flag (F_SETFL). OwnedFd closes both on failure.
        // This is not atomic with a concurrent fork/exec.
        // SAFETY: F_SETFD takes an integer flag, not a pointer.
        cerr(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
    }
    Ok(pipes)
}

#[allow(clippy::undocumented_unsafe_blocks)]
#[cfg(test)]
mod test {

    use super::{dynamic_fill, os_string_from_ptr, string_from_ptr};

    #[test]
    fn pipe_ends_are_cloexec_and_carry_data() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let [read, write] = super::pipe().unwrap();
        for pipe in [&read, &write] {
            assert_eq!(
                unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFD) },
                libc::FD_CLOEXEC
            );
        }
        let mut write = std::fs::File::from(write);
        write.write_all(b"pipe").unwrap();
        drop(write);
        let mut contents = [0; 4];
        std::fs::File::from(read).read_exact(&mut contents).unwrap();
        assert_eq!(&contents, b"pipe");
    }

    #[test]
    fn miri_test_str_to_ptr() {
        let strp = |ptr| unsafe { string_from_ptr(ptr) };
        assert_eq!(strp(std::ptr::null()), "");
        assert_eq!(strp(c"".as_ptr()), "");
        assert_eq!(strp(c"hello".as_ptr()), "hello");
    }

    #[test]
    fn miri_test_os_str_to_ptr() {
        let strp = |ptr| unsafe { os_string_from_ptr(ptr) };
        assert_eq!(strp(std::ptr::null()), "");
        assert_eq!(strp(c"".as_ptr()), "");
        assert_eq!(strp(c"hello".as_ptr()), "hello");
    }

    #[test]
    fn test_tty() {
        use crate::system::term::Pty;
        use std::fs::File;
        use std::os::fd::{AsFd, BorrowedFd};
        assert!(!super::safe_isatty(File::open("/bin/sh").unwrap().as_fd()));
        assert!(!super::safe_isatty(unsafe {
            BorrowedFd::borrow_raw(-837492)
        }));
        let pty = Pty::open().unwrap();
        assert!(super::safe_isatty(pty.leader.as_fd()));
        assert!(super::safe_isatty(pty.follower.as_fd()));
    }

    #[test]
    fn test_dynamic_fill() {
        assert_eq!(
            dynamic_fill(1..50, |buf: &mut [u8]| Ok::<_, ()>({
                assert!(buf.len() < 50);
                (buf.len() >= 23).then_some(23)
            }))
            .unwrap()
            .unwrap()
            .len(),
            23
        );

        assert_eq!(
            dynamic_fill(1..50, |buf: &mut [u8]| Ok::<_, ()>({
                assert!(buf.len() <= 50);
                (buf.len() >= 50).then_some(23)
            }))
            .unwrap()
            .unwrap()
            .len(),
            23
        );

        assert!(
            dynamic_fill(1..50, |buf: &mut [u8]| Ok::<_, ()>({
                assert!(buf.len() <= 50);
                None
            }))
            .unwrap()
            .is_none()
        );

        assert!(
            dynamic_fill(1..50, |buf: &mut [u8]| {
                assert!(buf.len() == 1);
                Err(())
            })
            .is_err()
        );
    }
}
