//! Group installation prepared before fork, with no directory lookup in the child.
#[cfg(target_os = "macos")]
use super::UserId;
use super::{GroupId, User, inject_group, set_supplementary_groups};
use std::io;

pub(super) struct Groups {
    groups: Vec<GroupId>,
    #[cfg(target_os = "macos")]
    member: Option<UserId>,
}

impl Groups {
    pub(super) fn prepare(user: &User, primary: GroupId, explicit: Option<&[GroupId]>) -> Self {
        let mut groups = explicit.unwrap_or(&user.groups).to_vec();
        inject_group(primary, &mut groups);
        Self {
            groups,
            #[cfg(target_os = "macos")]
            member: explicit.is_none().then_some(user.uid),
        }
    }

    pub(super) fn install(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if let Some(member) = self.member {
            // This is only a cache: gmuid preserves directory-service membership
            // beyond the 16-entry kernel credential. No lookup occurs here.
            // https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/bsd/kern/kern_prot.c
            let cached = &self.groups[..self.groups.len().min(16)];
            // SAFETY: transparent GroupId has gid_t layout and cached has len entries.
            super::cerr(unsafe {
                __initgroups(cached.len() as u32, cached.as_ptr().cast(), member.inner())
            })?;
            return Ok(());
        }
        set_supplementary_groups(&self.groups)
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // Private libsystem_kernel entry used by Libinfo's public initgroups wrapper.
    // Calling initgroups itself here would perform an unsafe post-fork XPC lookup.
    fn __initgroups(size: u32, groups: *const libc::gid_t, member: libc::uid_t) -> libc::c_int;
    fn pthread_setugid_np(user: libc::uid_t, group: libc::gid_t) -> libc::c_int;
    fn pthread_getugid_np(user: *mut libc::uid_t, group: *mut libc::gid_t) -> libc::c_int;
}

#[cfg(target_os = "macos")]
pub(super) fn with_identity<T>(
    user: &User,
    group: GroupId,
    operation: impl FnOnce() -> T,
) -> io::Result<T> {
    let groups = Groups::prepare(user, group, None);
    let (mut uid, mut gid) = (0, 0);
    // Nested overrides cannot be restored exactly; refuse before changing anything.
    // SAFETY: both output pointers are valid.
    let result = unsafe { pthread_getugid_np(&mut uid, &mut gid) };
    if result == 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ESRCH) {
        return Err(error);
    }
    // Unlike seteuid/setgroups, a thread override leaves the process credential
    // intact, including its memberd state and all original cached groups.
    // kern_settid restores the original credential when uid is KAUTH_UID_NONE.
    // SAFETY: scalar IDs; the kernel checks privilege and existing override state.
    super::cerr(unsafe { pthread_setugid_np(user.uid.inner(), group.inner()) })?;
    // An identical credential can make settid a no-op. Never install groups unless
    // the kernel confirms an override, or __initgroups could alter the process.
    // SAFETY: both output pointers are valid.
    if unsafe { pthread_getugid_np(&mut uid, &mut gid) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Err(error);
        }
        std::process::abort();
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: KAUTH_UID_NONE requests restoration of the process credential.
            if unsafe { pthread_setugid_np(u32::MAX, u32::MAX) } != 0 {
                // Continuing with unexpected credentials is never safe, even on unwind.
                std::process::abort();
            }
        }
    }
    let _restore = Restore;
    groups.install()?;
    Ok(operation())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unprivileged_identity_switch_never_runs_the_operation() {
        let user = User::real().unwrap().unwrap();
        assert_ne!(user.uid, UserId::ROOT);
        let before = User::real_groups().unwrap();
        let result = with_identity(&user, user.gid, || {
            panic!("operation ran without privilege")
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(User::real_groups().unwrap(), before);
    }

    #[test]
    fn explicit_groups_and_account_groups_are_distinct() {
        let user = User::real().unwrap().unwrap();
        let requested = [GroupId::new(123), GroupId::new(456)];
        let groups = Groups::prepare(&user, requested[1], Some(&requested));
        assert_eq!(groups.groups, [requested[1], requested[0]]);
        let account = Groups::prepare(&user, user.gid, None);
        assert_eq!(account.groups[0], user.gid);
        for group in &user.groups {
            assert!(account.groups.contains(group));
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(groups.member, None);
            assert_eq!(account.member, Some(user.uid));
        }
    }
}
