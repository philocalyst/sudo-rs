//! Descriptor-based Darwin ACL checks for sudoedit's mutation prohibition.

use crate::system::{GroupId, User};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

// sys/acl.h: opaque handles, four-byte enum tags/flags, and a u64 rights mask.
unsafe extern "C" {
    fn acl_get_fd_np(fd: i32, kind: u32) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> i32;
    fn acl_valid(acl: *mut c_void) -> i32;
    fn acl_get_entry(acl: *mut c_void, index: i32, entry: *mut *mut c_void) -> i32;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut u32) -> i32;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> i32;
    fn acl_get_flagset_np(entry: *mut c_void, flags: *mut *mut c_void) -> i32;
    fn acl_get_flag_np(flags: *mut c_void, flag: u32) -> i32;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn mbr_uuid_to_id(uuid: *const u8, id: *mut u32, kind: *mut i32) -> i32;
}

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: every Allocation owns an object returned by the ACL API.
        unsafe {
            acl_free(self.0);
        }
    }
}

const WRITE: u64 = 1 << 2;
const DELETE: u64 = 1 << 4;
const APPEND: u64 = 1 << 5;
const DELETE_CHILD: u64 = 1 << 6;
const WRITE_SECURITY: u64 = 1 << 12;
const CHANGE_OWNER: u64 = 1 << 13;
const MUTATION: u64 = WRITE | DELETE | APPEND | DELETE_CHILD | WRITE_SECURITY | CHANGE_OWNER;

fn in_group(user: &User, gid: u32) -> io::Result<bool> {
    // Darwin's built-in everyone group applies even to explicit group lists.
    if gid == 12 || user.gid.inner() == gid || user.groups.contains(&GroupId::new(gid)) {
        Ok(true)
    } else if user.default_groups {
        super::is_group_member(user.uid, GroupId::new(gid))
    } else {
        Ok(false)
    }
}

fn applies_to(entry: *mut c_void, user: &User) -> io::Result<bool> {
    // SAFETY: entry is a live entry from the owned ACL. Its qualifier is uuid_t.
    let qualifier = unsafe { acl_get_qualifier(entry) };
    if qualifier.is_null() {
        return Err(io::Error::last_os_error());
    }
    let qualifier = Allocation(qualifier);
    let (mut id, mut kind) = (0, -1);
    // SAFETY: the allocated qualifier contains sixteen UUID bytes; outputs are valid.
    let error = unsafe { mbr_uuid_to_id(qualifier.0.cast(), &mut id, &mut kind) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    match kind {
        0 => Ok(id == user.uid.inner()), // ID_TYPE_UID
        1 => in_group(user, id),         // ID_TYPE_GID
        _ => Err(io::Error::other("unsupported ACL principal type")),
    }
}

pub(super) fn permits_mutation(fd: BorrowedFd<'_>, user: &User) -> io::Result<bool> {
    // Read as the privileged observer, after the real-UID kernel check restored
    // credentials. The invoking user need not have ACL_READ_SECURITY access.
    // SAFETY: fd is live; ACL_TYPE_EXTENDED is the native Darwin ACL type.
    let raw = unsafe { acl_get_fd_np(fd.as_raw_fd(), 0x100) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let acl = Allocation(raw);
    // SAFETY: acl owns a live native ACL object.
    crate::cutils::cerr(unsafe { acl_valid(acl.0) })?;
    let mut remaining = MUTATION;
    for index in 0..=128 {
        let mut entry = std::ptr::null_mut();
        // Darwin returns zero for an entry, and EINVAL at the end of a valid ACL.
        // SAFETY: acl is valid and entry is writable; NEXT_ENTRY is -1.
        let result = unsafe { acl_get_entry(acl.0, if index == 0 { 0 } else { -1 }, &mut entry) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(error);
        }
        if index == 128 || entry.is_null() {
            return Err(io::Error::other("invalid or oversized ACL"));
        }
        let (mut tag, mut mask, mut flags) = (0, 0, std::ptr::null_mut());
        // SAFETY: all output pointers are valid and entry remains owned by acl.
        unsafe {
            crate::cutils::cerr(acl_get_tag_type(entry, &mut tag))?;
            crate::cutils::cerr(acl_get_permset_mask_np(entry, &mut mask))?;
            crate::cutils::cerr(acl_get_flagset_np(entry, &mut flags))?;
            if flags.is_null() {
                return Err(io::Error::other("missing ACL entry flags"));
            }
            if crate::cutils::cerr(acl_get_flag_np(flags, 1 << 8))? != 0 {
                continue;
            }
        }
        if mask & remaining == 0 || !applies_to(entry, user)? {
            continue;
        }
        match tag {
            1 => return Ok(true), // first applicable allow resolves a mutation right
            2 => remaining &= !mask,
            _ => return Err(io::Error::other("unsupported ACL entry tag")),
        }
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is live and stat is a correctly sized writable buffer.
    crate::cutils::cerr(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
    // SAFETY: successful fstat initialized the output.
    let stat = unsafe { stat.assume_init() };
    let shift = if stat.st_uid == user.uid.inner() {
        6
    } else if in_group(user, stat.st_gid)? {
        3
    } else {
        0
    };
    let fallback = WRITE
        | APPEND
        | if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            DELETE_CHILD
        } else {
            0
        };
    Ok((stat.st_mode >> shift) & 2 != 0 && remaining & fallback != 0)
}
