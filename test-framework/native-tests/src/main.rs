//! Native test support. This binary is never installed setuid.
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

fn syscall(value: libc::c_int) -> io::Result<()> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct ChildGuard(Option<std::process::Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            // SAFETY: this unreaped child has its own process group.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(args: &[String], pty: bool, credentials: bool) -> io::Result<i32> {
    if credentials {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "credential-changing probe modes disabled pending external VM teardown",
        ));
    }
    if args.len() < 4 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let number = |n: usize| {
        args[n]
            .parse::<u32>()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    };
    let (uid, gid, timeout) = (number(0)?, number(1)?, number(2)?);
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only sets a lock-free atomic flag.
        unsafe {
            libc::signal(signal, interrupted as *const () as libc::sighandler_t);
        }
    }
    let mut cmd = Command::new(&args[3]);
    cmd.args(&args[4..]);
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/pkg/bin")
        .env("LC_ALL", "C")
        .env("HOME", "/")
        .env(
            "SUDO_RS_IS_UNSTABLE",
            "I accept that my system may break unexpectedly",
        );
    // Explicitly allow only the editor path from the test fixture.
    if let Some(editor) = std::env::var_os("SUDO_EDITOR") {
        cmd.env("SUDO_EDITOR", editor);
    }
    let mut master = -1;
    let mut follower = -1;
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if pty {
        // SAFETY: output pointers and winsize are valid, other optional pointers are null.
        syscall(unsafe {
            libc::openpty(
                &mut master,
                &mut follower,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut size,
            )
        })?;
    }
    // SAFETY: this closure performs only async-signal-safe system calls before exec.
    unsafe {
        cmd.pre_exec(move || {
            syscall(libc::setsid())?;
            if pty {
                syscall(libc::ioctl(follower, libc::TIOCSCTTY as _, 0))?;
                for fd in 0..3 {
                    syscall(libc::dup2(follower, fd))?;
                }
                libc::close(master);
                if follower > 2 {
                    libc::close(follower);
                }
            }
            if credentials {
                syscall(libc::setgroups(1, &gid))?;
                syscall(libc::setgid(gid))?;
                syscall(libc::setuid(uid))?;
            }
            Ok(())
        });
    }
    let child = cmd.spawn();
    if pty {
        // SAFETY: only the parent copy of the live follower descriptor is closed.
        unsafe {
            libc::close(follower);
        }
    }
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            if pty {
                // SAFETY: close the owned descriptor on spawn failure.
                unsafe {
                    libc::close(master);
                }
            }
            return Err(error);
        }
    };
    let mut guard = ChildGuard(Some(child));
    let deadline = Instant::now() + Duration::from_secs(timeout.into());
    let mut terminal = if pty {
        // SAFETY: openpty returned this owned descriptor; it has not been closed.
        Some(unsafe { std::fs::File::from_raw_fd(master) })
    } else {
        None
    };
    let mut completed = None;
    let mut eof = false;
    loop {
        if let Some(terminal) = terminal.as_mut() {
            let mut pfd = libc::pollfd {
                fd: terminal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd; a short timeout also bounds child-status latency.
            let ready = unsafe { libc::poll(&mut pfd, 1, 10) };
            if ready < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(io::Error::last_os_error());
            }
            if ready > 0 && pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut bytes = [0; 4096];
                match terminal.read(&mut bytes) {
                    Ok(0) => eof = true,
                    Ok(n) => io::stdout().write_all(&bytes[..n])?,
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => eof = true,
                    Err(error) => return Err(error),
                }
            }
        }
        if let Some(child) = guard.0.as_mut() {
            if let Some(status) = child.try_wait()? {
                completed = Some(
                    status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
                );
                guard.0.take();
            }
        }
        // A child's exit does not imply the pty output buffer is drained.
        if let Some(code) = completed {
            if terminal.is_none() || eof {
                return Ok(code);
            }
        }
        if INTERRUPTED.load(Ordering::Relaxed) {
            return Ok(130);
        }
        if Instant::now() >= deadline {
            // ChildGuard kills and reaps the group before returning.
            eprintln!("native test command exceeded {timeout}s");
            return Ok(124);
        }
        std::thread::yield_now();
    }
}

fn main() -> ExitCode {
    // SAFETY: querying effective uid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("privileged probe execution disabled pending external VM teardown");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: io::Result<i32> = (|| {
        match args.first().map(String::as_str) {
            Some("as") => run(&args[1..], false, true),
            Some("pty") => run(&args[1..], true, true),
            Some("watch" | "watch-pty") => {
                let mut command = vec!["0".to_owned(), "0".to_owned()];
                command.extend_from_slice(&args[1..]);
                run(&command, args[0] == "watch-pty", false)
            }
            Some("ids") => {
                // SAFETY: identity queries have no preconditions.
                unsafe {
                    println!(
                        "{} {} {} {}",
                        libc::getuid(),
                        libc::geteuid(),
                        libc::getgid(),
                        libc::getegid()
                    );
                }
                Ok(0)
            }
            Some("groups") => {
                // SAFETY: zero-length getgroups query writes no memory.
                let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
                syscall(count)?;
                let mut groups = vec![0; count as usize];
                // SAFETY: storage has count gid_t entries.
                syscall(unsafe { libc::getgroups(count, groups.as_mut_ptr()) })?;
                groups.sort_unstable();
                groups.dedup();
                println!(
                    "{}",
                    groups
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                Ok(0)
            }
            Some("fd") => {
                let fd: i32 = args
                    .get(1)
                    .ok_or(io::ErrorKind::InvalidInput)?
                    .parse()
                    .map_err(|_| io::ErrorKind::InvalidInput)?;
                // SAFETY: fcntl accepts any integer descriptor and reports EBADF if absent.
                let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if result >= 0 {
                    println!("open");
                } else if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                    println!("closed");
                } else {
                    return Err(io::Error::last_os_error());
                }
                Ok(0)
            }
            Some("plant-fds") => {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: limit is valid writable storage.
                syscall(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) })?;
                if limit.rlim_cur <= 1000 {
                    if limit.rlim_max <= 1000 {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "hard descriptor limit prevents fd 1000 fixture",
                        ));
                    }
                    limit.rlim_cur = 1001;
                    // SAFETY: raises only this process's soft limit, below its hard limit.
                    syscall(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) })?;
                }
                let mut cmd = Command::new(args.get(1).ok_or(io::ErrorKind::InvalidInput)?);
                cmd.args(&args[2..]);
                // SAFETY: pre_exec only opens, duplicates, and closes descriptors.
                unsafe {
                    cmd.pre_exec(|| {
                        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
                        syscall(fd)?;
                        syscall(libc::dup2(fd, 9))?;
                        syscall(libc::dup2(fd, 1000))?;
                        if fd != 9 && fd != 1000 {
                            libc::close(fd);
                        }
                        Ok(())
                    });
                }
                Err(cmd.exec())
            }
            Some("tty") => {
                let mut size = libc::winsize {
                    ws_row: 0,
                    ws_col: 0,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                // SAFETY: size is valid output storage for TIOCGWINSZ.
                syscall(unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut size) })?;
                println!("{} {}", size.ws_row, size.ws_col);
                Ok(0)
            }
            Some("no-root") => {
                // SAFETY: attempts a credential change in this expendable command process.
                let result = unsafe { libc::seteuid(0) };
                if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                    println!("cannot regain root");
                    Ok(0)
                } else {
                    Ok(1)
                }
            }
            Some("signal") => {
                // SAFETY: reset and raise a signal in this expendable command process.
                unsafe {
                    libc::signal(libc::SIGTERM, libc::SIG_DFL);
                    libc::raise(libc::SIGTERM);
                }
                Ok(1)
            }
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    })();
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("native probe: {error}");
            ExitCode::FAILURE
        }
    }
}
