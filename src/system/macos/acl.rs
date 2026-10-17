//! Descriptor-based Darwin ACL checks for sudoedit's mutation prohibition.
//!
//! `ATTR_CMN_USERACCESS` aggregates a vnode's rights into the `R_OK`/`W_OK`/
//! `X_OK` triple, so a partial ACL that grants, say, `add_file` but not
//! `write` leaves `W_OK` clear while the user can still mutate the object.
//! sudoedit must not treat that as "the user cannot write here", so the
//! ordered ACL is evaluated directly on the same opened vnode.

use crate::system::{GroupId, User};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

// sys/acl.h: opaque handles, four-byte enum tags/flags, and a u64 rights mask.
//
// The return conventions below are not stated in the SDK headers and Darwin
// ships no acl(3) manual pages, so they were established against the system
// library: `acl_get_entry` yields 0 for an entry and -1/`EINVAL` at the end of
// an ACL (not the POSIX.1e 1/0/-1), `acl_get_flag_np` yields 1 when the flag is
// set and 0 when it is not, `acl_valid` yields 0 for a valid ACL, and both
// `acl_get_fd_np` and `acl_get_qualifier` return owned allocations that must be
// released with `acl_free`.
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

/// `acl_type_t::ACL_TYPE_EXTENDED`, the only ACL type Darwin stores.
const ACL_TYPE_EXTENDED: u32 = 0x100;
/// `acl_entry_id_t::ACL_FIRST_ENTRY` and `ACL_NEXT_ENTRY`.
const ACL_FIRST_ENTRY: i32 = 0;
const ACL_NEXT_ENTRY: i32 = -1;
/// `acl_tag_t::ACL_EXTENDED_ALLOW` and `ACL_EXTENDED_DENY`.
const ACL_EXTENDED_ALLOW: u32 = 1;
const ACL_EXTENDED_DENY: u32 = 2;
/// `acl_flag_t::ACL_ENTRY_ONLY_INHERIT`: the entry is passed to new children
/// and never applies to the object carrying it.
const ACL_ENTRY_ONLY_INHERIT: u32 = 1 << 8;
/// `KAUTH_ACL_MAX_ENTRIES`, the kernel's hard limit on entries per ACL.
const ACL_MAX_ENTRIES: usize = 128;
/// `membership.h` identity kinds that `mbr_uuid_to_id` can report.
const ID_TYPE_UID: i32 = 0;
const ID_TYPE_GID: i32 = 1;
/// Primary group id of Darwin's built-in `everyone` group, which every ACL
/// "everyone" entry resolves to.
const EVERYONE_GID: u32 = 12;

// acl_perm_t bits that let the holder change the object or its contents.
// ACL_ADD_FILE shares its bit with ACL_WRITE_DATA, and ACL_ADD_SUBDIRECTORY
// shares its bit with ACL_APPEND_DATA, so directory rights are covered too.
const WRITE: u64 = 1 << 2;
const DELETE: u64 = 1 << 4;
const APPEND: u64 = 1 << 5;
const DELETE_CHILD: u64 = 1 << 6;
const WRITE_SECURITY: u64 = 1 << 12;
const CHANGE_OWNER: u64 = 1 << 13;
const MUTATION: u64 = WRITE | DELETE | APPEND | DELETE_CHILD | WRITE_SECURITY | CHANGE_OWNER;

/// The POSIX mode bit for write access, before shifting into a class.
const POSIX_WRITE: libc::mode_t = 2;

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: every Allocation owns an object returned by the ACL API.
        unsafe {
            acl_free(self.0);
        }
    }
}

fn in_group(user: &User, gid: u32) -> io::Result<bool> {
    // Darwin's built-in everyone group applies even to explicit group lists.
    if gid == EVERYONE_GID || user.gid.inner() == gid || user.groups.contains(&GroupId::new(gid)) {
        Ok(true)
    } else if user.groups_may_expand {
        // The kernel resolves memberships beyond the sixteen-entry credential
        // cache through Open Directory, but only while the credential still
        // permits it; `setgroups` turns that off for good.
        super::is_group_member(user.uid, GroupId::new(gid))
    } else {
        Ok(false)
    }
}

fn applies_to(entry: *mut c_void, user: &User) -> io::Result<bool> {
    // SAFETY: entry is a live entry from the owned ACL. Its qualifier is uuid_t.
    let qualifier = unsafe { acl_get_qualifier(entry) };
    if qualifier.is_null() {
        // An entry without a principal cannot be matched, so refuse rather
        // than assume it does not apply.
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
        ID_TYPE_UID => Ok(id == user.uid.inner()),
        ID_TYPE_GID => in_group(user, id),
        _ => Err(io::Error::other("unsupported ACL principal type")),
    }
}

/// Whether `user` holds any right that lets them change the object behind `fd`.
///
/// Errors fail closed: the caller treats them as a refusal rather than as
/// "the user cannot write".
pub(super) fn permits_mutation(fd: BorrowedFd<'_>, user: &User) -> io::Result<bool> {
    // Read as the privileged observer, after the real-UID kernel check restored
    // credentials. The invoking user need not have ACL_READ_SECURITY access.
    // SAFETY: fd is live; ACL_TYPE_EXTENDED is the native Darwin ACL type.
    let raw = unsafe { acl_get_fd_np(fd.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // Darwin reports "no extended ACL" as ENOENT. The POSIX mode alone
        // already decided the aggregate W_OK answer the caller started from.
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let acl = Allocation(raw);
    // SAFETY: acl owns a live native ACL object.
    crate::cutils::cerr(unsafe { acl_valid(acl.0) })?;
    // Rights that no preceding entry has denied yet. Darwin resolves an ACL in
    // order and stops at the first entry that answers for a right.
    let mut remaining = MUTATION;
    for index in 0..=ACL_MAX_ENTRIES {
        let mut entry = std::ptr::null_mut();
        let position = if index == 0 {
            ACL_FIRST_ENTRY
        } else {
            ACL_NEXT_ENTRY
        };
        // SAFETY: acl is valid and entry is writable.
        let result = unsafe { acl_get_entry(acl.0, position, &mut entry) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(error);
        }
        if index == ACL_MAX_ENTRIES || entry.is_null() {
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
            // An inherit-only entry describes future children, not this object.
            if crate::cutils::cerr(acl_get_flag_np(flags, ACL_ENTRY_ONLY_INHERIT))? != 0 {
                continue;
            }
        }
        if mask & remaining == 0 || !applies_to(entry, user)? {
            continue;
        }
        match tag {
            // The first applicable allow resolves a mutation right.
            ACL_EXTENDED_ALLOW => return Ok(true),
            ACL_EXTENDED_DENY => remaining &= !mask,
            _ => return Err(io::Error::other("unsupported ACL entry tag")),
        }
    }
    // No entry answered. A deny may still have removed the right the POSIX
    // mode would otherwise grant, so check what the mode grants that the ACL
    // did not take away: denying `write` does not withdraw the right to append.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is live and stat is a correctly sized writable buffer.
    crate::cutils::cerr(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
    // SAFETY: successful fstat initialized the output.
    let stat = unsafe { stat.assume_init() };
    let shift = if stat.st_uid == user.uid.inner() {
        6 // owner
    } else if in_group(user, stat.st_gid)? {
        3 // group
    } else {
        0 // other
    };
    let granted_by_mode = WRITE
        | APPEND
        | if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            DELETE_CHILD
        } else {
            0
        };
    Ok((stat.st_mode >> shift) & POSIX_WRITE != 0 && remaining & granted_by_mode != 0)
}
