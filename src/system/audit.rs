#![cfg_attr(not(feature = "unstable-remote-sudoers"), allow(unused_imports))]
use std::collections::HashSet;
use std::ffi::{CStr, CString, c_int, c_uint};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, BufReader, Error, ErrorKind};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    net::UnixStream,
    prelude::OpenOptionsExt,
};
use std::path::{Component, Path};

use super::{
    Group, GroupId, User, UserId, cerr, inject_group, interface::UnixUser, set_supplementary_groups,
};
use crate::common::resolve::CurrentUser;

#[cfg(target_os = "linux")]
pub(crate) fn no_new_privs_enabled() -> io::Result<bool> {
    // SAFETY: prctl(PR_GET_NO_NEW_PRIVS) can never cause UB
    let no_new_privs = cerr(unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) })?;
    Ok(no_new_privs != 0)
}

/// Temporary change privileges --- essentially a 'mini sudo'
/// This is only used for sudoedit.
pub(crate) fn sudo_call<T>(
    target_user: &User,
    target_group: &Group,
    operation: impl FnOnce() -> T,
) -> io::Result<T> {
    const KEEP_GID: libc::gid_t = -1i32 as libc::gid_t;

    // SAFETY: these libc functions are always safe to call
    let (cur_user_id, cur_group_id) =
        unsafe { (UserId::new(libc::geteuid()), GroupId::new(libc::getegid())) };

    let cur_groups = {
        // SAFETY: calling with size 0 does not modify through the pointer, and is
        // a documented way of getting the length needed.
        let len = cerr(unsafe { libc::getgroups(0, std::ptr::null_mut()) })?;

        let mut buf: Vec<GroupId> = vec![GroupId::new(KEEP_GID); len as usize];
        // SAFETY: we pass a correct pointer to a slice of the given length
        cerr(unsafe {
            // We can cast to gid_t because `GroupId` is marked as transparent
            libc::getgroups(len, buf.as_mut_ptr().cast::<libc::gid_t>())
        })?;

        buf
    };

    let mut target_groups = target_user.groups.clone();
    inject_group(target_group.gid, &mut target_groups);

    if cfg!(test)
        && target_user.uid == cur_user_id
        && target_group.gid == cur_group_id
        && target_groups.iter().collect::<HashSet<_>>() == cur_groups.iter().collect::<HashSet<_>>()
    {
        // we are not actually switching users, simply run the closure
        // (this would also be safe in production mode, but it is a needless check)
        return Ok(operation());
    }

    struct ResetUserGuard(UserId, GroupId, Vec<GroupId>);

    // Historical remark: On Linux with glibc, seteuid/setegid has changed in semantics; before
    // glibc 2.1, setresuid(-1, id, -1) would have to be used instead of seteuid(id). However,
    // that glibc was released in 1999.
    //
    // In modern Linux and FreeBSD, seteuid(id) = setresuid(-1, id, -1); on NetBSD/MacOS the
    // setresuid() call does not even exist.

    impl Drop for ResetUserGuard {
        fn drop(&mut self) {
            // restore privileges in reverse order
            (|| {
                // SAFETY: this function is always safe to call
                cerr(unsafe { libc::seteuid(UserId::inner(&self.0)) })?;
                // SAFETY: as above
                cerr(unsafe { libc::setegid(GroupId::inner(&self.1)) })?;
                set_supplementary_groups(&self.2)
            })()
            .expect("could not restore to saved user id");
        }
    }

    let guard = ResetUserGuard(cur_user_id, cur_group_id, cur_groups);

    set_supplementary_groups(&target_groups)?;
    // SAFETY: this function is always safe to call
    cerr(unsafe { libc::setegid(GroupId::inner(&target_group.gid)) })?;
    // SAFETY: as above
    cerr(unsafe { libc::seteuid(UserId::inner(&target_user.uid)) })?;

    let result = operation();

    std::mem::drop(guard);
    Ok(result)
}

#[cfg(feature = "unstable-remote-sudoers")]
/// Get the credentials of the peer at the other side of the socket
fn get_peer_credentials(stream: &UnixStream) -> io::Result<libc::ucred> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut ucred_size = size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: An out pointer for the correct type and length are passed.
    // FIXME use UnixStream::peer_cred() once stable in our MSRV.
    unsafe {
        cerr(libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut ucred_size,
        ))?;
    }

    Ok(ucred)
}

/// Drop root privileges by setting effective user id equal to the real user id.
/// This routine will panic if the process is not privileged.
pub fn irrevocably_drop_privileges() {
    // SAFETY:
    // - getuid() and geteuid() are always safe to call
    // - setuid() does not change any memory and only affects OS state.
    unsafe {
        let real_uid = libc::getuid();
        let effective_uid = libc::geteuid();
        // we never use setuid/setgid/setgroups except in the pre_exec hook before exec'ing,
        // or in sudo_call (which always resets the user state after the closure finishes).
        // this extra check is here to punish programming mistakes due to sloppiness.
        assert_eq!(effective_uid, UserId::ROOT.inner(), "setuid violation");

        cerr(libc::setuid(real_uid)).expect("setuid violation");
    }
}

// of course we can also write "file & 0o040 != 0", but this makes the intent explicit
enum Op {
    Read = 4,
    Write = 2,
    Exec = 1,
}
enum Category {
    Owner = 2,
    Group = 1,
    World = 0,
}

fn mode(who: Category, what: Op) -> u32 {
    (what as u32) << (3 * who as u32)
}

/// Open sudo configuration using various security checks
pub fn secure_open_sudoers(path: impl AsRef<Path>) -> io::Result<File> {
    let mut open_options = OpenOptions::new();
    open_options.read(true);

    secure_open_impl(path.as_ref(), &mut open_options, false)
}

#[cfg(feature = "unstable-remote-sudoers")]
pub fn secure_open_remote_sudoers(
    path: impl AsRef<Path>,
    user: UserId,
    group: Option<GroupId>,
) -> io::Result<BufReader<UnixStream>> {
    secure_open_socket_impl(path.as_ref(), user, group)
}

/// Open a timestamp cookie file using various security checks
pub fn secure_open_cookie_file(path: impl AsRef<Path>) -> io::Result<File> {
    let mut open_options = OpenOptions::new();
    open_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(mode(Category::Owner, Op::Write) | mode(Category::Owner, Op::Read));

    secure_open_impl(path.as_ref(), &mut open_options, true)
}

/// Return the system zoneinfo path after validating that it is safe
pub fn zoneinfo_path() -> Option<&'static str> {
    let paths = [
        "/usr/share/zoneinfo",
        "/usr/share/lib/zoneinfo",
        "/usr/lib/zoneinfo",
    ];

    paths.into_iter().find(|p| {
        let path = Path::new(p);
        path.metadata().and_then(|meta| checks(path, meta)).is_ok()
    })
}

fn checks(path: &Path, meta: Metadata) -> io::Result<()> {
    let error = |msg| Error::new(ErrorKind::PermissionDenied, msg);

    let path_mode = meta.permissions().mode();
    if meta.uid() != 0 {
        Err(error(xlat!(
            "{path} must be owned by root",
            path = path.display()
        )))
    } else if meta.gid() != 0 && (path_mode & mode(Category::Group, Op::Write) != 0) {
        Err(error(xlat!(
            "{path} cannot be group-writable",
            path = path.display()
        )))
    } else if path_mode & mode(Category::World, Op::Write) != 0 {
        Err(error(xlat!(
            "{path} cannot be world-writable",
            path = path.display()
        )))
    } else {
        Ok(())
    }
}

// Open `path` with options `open_options`, provided that it is "secure".
// "Secure" means that it passes the `checks` function above.
// If `check_parent_dir` is set, also check that the parent directory is "secure" also.
// If `create_parent_dirs` is set, create the path to the file if it does not already exist.
fn secure_open_impl(
    path: &Path,
    open_options: &mut OpenOptions,
    create_parent_dirs: bool,
) -> io::Result<File> {
    let error = |msg| Error::new(ErrorKind::PermissionDenied, msg);
    if let Some(parent_dir) = path.parent() {
        // if we should create parent dirs and it does not yet exist, create it
        if create_parent_dirs && !parent_dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(
                    mode(Category::Owner, Op::Write)
                        | mode(Category::Owner, Op::Read)
                        | mode(Category::Owner, Op::Exec)
                        | mode(Category::Group, Op::Exec)
                        | mode(Category::World, Op::Exec),
                )
                .create(parent_dir)?;
        }

        let parent_meta = std::fs::metadata(parent_dir)?;
        checks(parent_dir, parent_meta)?;
    } else {
        return Err(error(xlat!(
            "{path} has no valid parent directory",
            path = path.display()
        )));
    }

    let file = open_options.open(path)?;
    let meta = file.metadata()?;
    checks(path, meta)?;

    Ok(file)
}

#[cfg(feature = "unstable-remote-sudoers")]
fn check_peer<Id>(peer_identity: Id, expected: Id, class: &str) -> io::Result<()>
where
    Id: std::fmt::Display + PartialEq,
{
    if peer_identity == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer process must run as {class} {expected} but runs as {peer_identity}"),
        ))
    }
}

// Open the socket at path, provided that it is "secure".
// "Secure" means that it passes the `checks` function above.
#[cfg(feature = "unstable-remote-sudoers")]
fn secure_open_socket_impl(
    path: &Path,
    user: UserId,
    group: Option<GroupId>,
) -> io::Result<BufReader<UnixStream>> {
    // Check the metadata on the filesystem as extra security,
    // even knowing that it produces a TOCTOU.
    let meta = fs::metadata(path)?;
    checks(path, meta)?;
    if let Some(parent_dir) = path.parent() {
        let parent_meta = std::fs::metadata(parent_dir)?;
        checks(parent_dir, parent_meta)?;
    } else {
        let error = |msg| Error::new(ErrorKind::PermissionDenied, msg);

        return Err(error(xlat!(
            "{path} has no valid parent directory",
            path = path.display()
        )));
    }

    let stream = UnixStream::connect(path)?;

    // Check the peer's credentials to avoid the TOCTOU.
    let peer_creds = get_peer_credentials(&stream)?;

    // If there is an error in these checks, the function returns immediately
    // leaving `stream` out of scope and forcing the closing of the socket.
    check_peer(UserId::new(peer_creds.uid), user, "user")?;
    if let Some(group) = group {
        check_peer(GroupId::new(peer_creds.gid), group, "group")?;
    }

    stream.shutdown(Shutdown::Write)?;
    let reader = BufReader::new(stream);

    Ok(reader)
}

fn open_at(parent: BorrowedFd, file_name: &CStr, create: bool) -> io::Result<OwnedFd> {
    let flags = if create {
        libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CREAT
    } else {
        libc::O_NOFOLLOW | libc::O_RDONLY
    };

    // the mode for files that are created is hardcoded, as it is in ogsudo
    let mode = libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IROTH;

    // SAFETY: by design, a correct CStr pointer is passed to openat; only if this call succeeds
    // is the file descriptor it returns (which is then necessarily valid) passed to from_raw_fd
    unsafe {
        let fd = cerr(libc::openat(
            parent.as_raw_fd(),
            file_name.as_ptr(),
            flags,
            c_uint::from(mode),
        ))?;

        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[cfg(any(not(test), target_os = "netbsd", target_os = "macos"))]
fn faccess_at(parent: BorrowedFd, path: &CStr, mode: c_int, flags: c_int) -> io::Result<()> {
    // SAFETY: by design, a correct CStr pointer is passed to faccessat
    cerr(unsafe { libc::faccessat(parent.as_raw_fd(), path.as_ptr(), mode, flags) }).map(|_| ())
}

// On platforms without AT_EMPTY_PATH, directories can be queried through ".".
// Final files are queried relative to the already checked, non-writable parent.
#[cfg(any(target_os = "netbsd", target_os = "macos"))]
fn user_can_modify_at(parent: BorrowedFd, path: &CStr) -> io::Result<bool> {
    #[cfg(target_os = "netbsd")]
    const RIGHTS: &[c_int] = &[libc::W_OK];
    // Darwin W_OK combines add_file and add_subdirectory for a directory;
    // an ACL may grant just one. Ask separately for each modification right.
    // Public sys/unistd.h values, translated by access1 in:
    // https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/bsd/vfs/vfs_syscalls.c
    #[cfg(target_os = "macos")]
    const RIGHTS: &[c_int] = &[
        1 << 10, // _WRITE_OK: write data / add file
        1 << 12, // _DELETE_OK: delete this object
        1 << 13, // _APPEND_OK: append data / add subdirectory
        1 << 14, // _RMFILE_OK: delete child
        1 << 20, // _WPERM_OK: change permissions
        1 << 21, // _CHOWN_OK: change ownership
    ];
    for &right in RIGHTS {
        if access_allowed(faccess_at(parent, path, right, libc::AT_SYMLINK_NOFOLLOW))? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(target_os = "netbsd", target_os = "macos"))]
fn access_allowed(result: io::Result<()>) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::EPERM | libc::EROFS)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// This opens a file for sudoedit, performing security checks (see below) and
/// opening with reduced privileges.
pub fn secure_open_for_sudoedit(
    path: impl AsRef<Path>,
    current_user: &CurrentUser,
    target_user: &User,
    target_group: &Group,
) -> io::Result<File> {
    if current_user.is_root() {
        sudo_call(target_user, target_group, || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
        })?
    } else {
        traversed_secure_open(path, current_user, target_user, target_group)
    }
}

/// This opens a file making sure that
/// - no directory leading up to the file is editable by the user
/// - no components are a symbolic link
fn traversed_secure_open(
    path: impl AsRef<Path>,
    #[cfg(not(test))] forbidden_user: &CurrentUser,
    #[cfg(test)] forbidden_user: &User,
    target_user: &User,
    target_group: &Group,
) -> io::Result<File> {
    let path = path.as_ref();

    let Some(file_name) = path.file_name() else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            xlat!("invalid path"),
        ));
    };

    let mut components = path.parent().unwrap_or(Path::new("")).components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            xlat!("path must be absolute"),
        ));
    }

    let user_cannot_write = |file: &File, _parent: BorrowedFd, _name: &CStr| -> io::Result<()> {
        let meta = file.metadata()?;
        let perms = meta.permissions().mode();

        if meta.uid() == forbidden_user.uid.inner() {
            // Owner can change file permissions
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                xlat!("cannot open a file in a path writable by the user"),
            ));
        }

        let user_has_write_perms = {
            #[cfg(not(test))]
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            // Only works when forbidden_user is current user. This is enforced
            // by accepting CurrentUser outside of test mode.
            // We don't pass AT_EACCESS to faccessat to make it check using the
            // real user id rather than the effective user id.
            let writable = faccess_at(file.as_fd(), c"", libc::W_OK, libc::AT_EMPTY_PATH).is_ok();

            #[cfg(all(not(test), any(target_os = "netbsd", target_os = "macos")))]
            let writable = if meta.is_dir() {
                user_can_modify_at(file.as_fd(), c".")?
            } else {
                // The invoking user cannot rename entries in any ancestor: each
                // has already passed the descriptor-based directory check.
                user_can_modify_at(_parent, _name)?
            };

            #[cfg(test)]
            let writable = false;

            // During testing we do a less comprehensive check as we don't have
            // permission to set the real user id to arbitrary users, but faccessat
            // looks at the real user id.
            // Keep the mode-bit check conservative even when the kernel denies access.
            writable
                || perms & mode(Category::World, Op::Write) != 0
                || (perms & mode(Category::Group, Op::Write) != 0)
                    && forbidden_user.in_group_by_gid(GroupId::new(meta.gid()))
                || (perms & mode(Category::Owner, Op::Write) != 0)
                    && forbidden_user.uid.inner() == meta.uid()
        };

        if user_has_write_perms {
            Err(io::Error::new(
                ErrorKind::PermissionDenied,
                xlat!("cannot open a file in a path writable by the user"),
            ))
        } else {
            Ok(())
        }
    };

    let mut cur = File::open("/")?;
    user_cannot_write(&cur, cur.as_fd(), c".")?;

    for component in components {
        let dir: CString = match component {
            Component::Normal(dir) => CString::new(dir.as_bytes())?,
            Component::CurDir => c".".to_owned(),
            Component::ParentDir => c"..".to_owned(),
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    xlat!("error in provided path"),
                ));
            }
        };

        sudo_call(target_user, target_group, || {
            cur = open_at(cur.as_fd(), &dir, false)?.into();
            io::Result::Ok(())
        })??;
        user_cannot_write(&cur, cur.as_fd(), c".")?;
    }
    let name = CString::new(file_name.as_bytes())?;
    let file: File = sudo_call(target_user, target_group, || {
        open_at(cur.as_fd(), &name, true).map(File::from)
    })??;
    user_cannot_write(&file, cur.as_fd(), &name)?;

    Ok(file)
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(any(target_os = "netbsd", target_os = "macos"))]
    #[test]
    fn access_errors_do_not_become_permission_denials() {
        assert!(access_allowed(Ok(())).unwrap());
        for code in [libc::EACCES, libc::EPERM, libc::EROFS] {
            assert!(!access_allowed(Err(Error::from_raw_os_error(code))).unwrap());
        }
        for code in [libc::ENOENT, libc::EBADF, libc::EINVAL, libc::EIO] {
            assert_eq!(
                access_allowed(Err(Error::from_raw_os_error(code)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(code)
            );
        }
        let root = File::open("/").unwrap();
        // A missing component is an operational error, never proof of safety.
        assert_eq!(
            user_can_modify_at(root.as_fd(), c"/dev/null/not-a-directory")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTDIR)
        );
    }

    #[cfg(any(target_os = "netbsd", target_os = "macos"))]
    #[test]
    fn kernel_access_check_observes_mode_changes() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sudo-rs-access-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let _cleanup = Cleanup(path.clone());
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let parent = File::open("/").unwrap();
        assert!(access_allowed(faccess_at(parent.as_fd(), &name, libc::W_OK, 0)).unwrap());
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .unwrap();
        assert_eq!(
            faccess_at(parent.as_fd(), &name, libc::W_OK, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        // The query is descriptor-relative for directories and does not need AT_EMPTY_PATH.
        assert!(
            user_can_modify_at(File::open(path.parent().unwrap()).unwrap().as_fd(), c".").unwrap()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_append_acl_is_not_equivalent_to_write_access() {
        let path = std::env::temp_dir().join(format!(
            "sudo-rs-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .unwrap();
        let _cleanup = Cleanup(path.clone());
        let parent = File::open(path.parent().unwrap()).unwrap();
        let name = CString::new(path.file_name().unwrap().as_bytes()).unwrap();
        assert_eq!(
            faccess_at(parent.as_fd(), &name, libc::W_OK, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let user = User::from_uid(UserId::new(file.metadata().unwrap().uid()))
            .unwrap()
            .unwrap();
        let acl = format!("user:{} allow append", user.name);
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", &acl])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        // A normal W_OK query still denies, but the kernel permits append.
        assert_eq!(
            faccess_at(parent.as_fd(), &name, libc::W_OK, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert!(user_can_modify_at(parent.as_fd(), &name).unwrap());
        use std::io::Write;
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"append")
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"append");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_dot_query_observes_directory_delete_acl() {
        let path = std::env::temp_dir().join(format!(
            "sudo-rs-delete-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(path.clone());
        let child = path.join("child");
        fs::create_dir(&child).unwrap();
        let dir = File::open(&child).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o500)).unwrap();
        const DELETE: c_int = 1 << 12;
        assert_eq!(
            faccess_at(dir.as_fd(), c".", DELETE, libc::AT_SYMLINK_NOFOLLOW)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            fs::remove_dir(&child).unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        let user = User::real().unwrap().unwrap();
        let acl = format!("user:{} allow delete", user.name);
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", &acl])
                .arg(&child)
                .status()
                .unwrap()
                .success()
        );
        // Deleting is granted on the object even though its parent is not writable.
        // The descriptor-relative dot query must observe that object ACL.
        faccess_at(dir.as_fd(), c".", DELETE, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        fs::remove_dir(&child).unwrap();
        assert!(!child.exists());
    }

    #[test]
    fn secure_open_is_predictable() {
        // /etc/hosts should be readable and "secure" (if this test fails, you have been compromised)
        assert!(std::fs::File::open("/etc/hosts").is_ok());
        assert!(secure_open_sudoers("/etc/hosts").is_ok());

        // /tmp should be readable, but not secure (writable by group other than root)
        assert!(std::fs::File::open("/tmp").is_ok());
        assert!(secure_open_sudoers("/tmp").is_err());

        #[cfg(target_os = "linux")]
        {
            // /var/log/wtmp should be readable, but not secure (writable by group other than root)
            // It doesn't exist on many non-Linux systems however.
            if std::fs::File::open("/var/log/wtmp").is_ok() {
                assert!(secure_open_sudoers("/var/log/wtmp").is_err());
            }
        }

        // /etc/shadow should not be readable
        assert!(std::fs::File::open("/etc/shadow").is_err());
        assert!(secure_open_sudoers("/etc/shadow").is_err());
    }

    #[test]
    fn test_secure_open_cookie_file() {
        assert!(secure_open_cookie_file("/etc/hosts").is_err());
    }

    #[test]
    fn test_traverse_secure_open_negative() {
        use crate::common::resolve::CurrentUser;

        let root = User::from_name(c"root").unwrap().unwrap();
        let user = CurrentUser::resolve().unwrap();

        // not allowed -- invalid
        assert!(traversed_secure_open("/", &root, &user, &user.group()).is_err());
        // not allowed since the path is not absolute
        assert!(traversed_secure_open("./hello.txt", &root, &user, &user.group()).is_err());
        // not allowed since root can write to "/"
        assert!(traversed_secure_open("/hello.txt", &root, &user, &user.group()).is_err());
        // not allowed since "/tmp" is a directory
        assert!(traversed_secure_open("/tmp", &user, &user, &user.group()).is_err());
        // not allowed since anybody can write to "/tmp"
        assert!(traversed_secure_open("/tmp/foo/hello.txt", &user, &user, &user.group()).is_err());
        // not allowed since "/bin" is a symlink
        assert!(traversed_secure_open("/bin/hello.txt", &user, &user, &user.group()).is_err());
    }

    #[test]
    fn test_traverse_secure_open_positive() {
        use crate::common::resolve::CurrentUser;
        use crate::system::{GroupId, UserId};

        let user = CurrentUser::resolve().unwrap();
        let other_user = CurrentUser::fake(User {
            uid: UserId::new(1042),
            gid: GroupId::new(1042),

            name: "test".into(),
            home: "/home/test".into(),
            shell: "/bin/sh".into(),
            groups: vec![],
        });

        // allowed!
        let path = std::env::current_dir()
            .unwrap()
            .join("sudo-rs-test-file.txt");
        let file = traversed_secure_open(&path, &other_user, &user, &user.group()).unwrap();
        if file.metadata().is_ok_and(|meta| meta.len() == 0) {
            std::fs::remove_file(path).unwrap();
        }
    }
}
