//! AppArmor confinement requested through `APPARMOR_PROFILE=` or the
//! `apparmor_profile` default.
//!
//! Enforcement exists only on Linux, and only when sudo-rs is built with the
//! `apparmor` feature. Everywhere else a profile selected by the matching rule
//! has to be refused: running the command unconfined would silently ignore the
//! confinement the policy asked for.

use std::io;

#[cfg(all(feature = "apparmor", target_os = "linux"))]
use std::ffi::{CStr, CString, c_char, c_int};
#[cfg(all(feature = "apparmor", target_os = "linux"))]
use std::{fs, mem};

#[cfg(all(feature = "apparmor", target_os = "linux"))]
use crate::cutils::cerr;

/// Whether this build can apply an AppArmor profile at all.
pub const SUPPORTED: bool = cfg!(all(feature = "apparmor", target_os = "linux"));

/// Refuse a profile that this build could never apply.
///
/// Call this before authenticating, so that a policy demanding confinement
/// sudo-rs cannot provide stops before it has any effect, rather than running
/// the command unconfined. Whether the running kernel has AppArmor enabled is
/// a separate, deliberately soft failure handled by
/// [`set_profile_for_next_exec`].
pub fn ensure_profile_supported(profile_name: Option<&str>) -> io::Result<()> {
    match profile_name {
        Some(_) if !SUPPORTED => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            if cfg!(target_os = "linux") {
                xlat!("sudo-rs was built without AppArmor support")
            } else {
                xlat!("AppArmor is only available on Linux")
            },
        )),
        _ => Ok(()),
    }
}

/// Set the profile for the next exec call if AppArmor is enabled
#[cfg(all(feature = "apparmor", target_os = "linux"))]
pub fn set_profile_for_next_exec(profile_name: &str) -> io::Result<()> {
    if apparmor_is_enabled()? {
        apparmor_prepare_exec(profile_name)
    } else {
        // if the sysadmin doesn't have apparmor enabled, fail softly
        Ok(())
    }
}

#[cfg(all(feature = "apparmor", target_os = "linux"))]
fn apparmor_is_enabled() -> io::Result<bool> {
    match fs::read_to_string("/sys/module/apparmor/parameters/enabled") {
        Ok(enabled) => Ok(enabled.starts_with("Y")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Switch the apparmor profile to the given profile on the next exec call
#[cfg(all(feature = "apparmor", target_os = "linux"))]
fn apparmor_prepare_exec(new_profile: &str) -> io::Result<()> {
    // SAFETY: Always safe to call
    unsafe { libc::dlerror() }; // Clear any existing error

    // SAFETY: Loading a known safe dylib. LD_LIBRARY_PATH is ignored because we are setuid.
    let handle = unsafe { libc::dlopen(c"libapparmor.so.1".as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        // SAFETY: In case of an error, dlerror returns a valid C string.
        return Err(io::Error::new(io::ErrorKind::NotFound, unsafe {
            CStr::from_ptr(libc::dlerror())
                .to_string_lossy()
                .into_owned()
        }));
    }

    // SAFETY: dlsym will either return a function pointer of the right signature or NULL.
    let aa_change_onexec = unsafe { libc::dlsym(handle, c"aa_change_onexec".as_ptr()) };

    if aa_change_onexec.is_null() {
        // SAFETY: Always safe to call
        let err = unsafe { libc::dlerror() };
        return Err(if err.is_null() {
            // There was no error in dlsym, but the symbol itself was defined as NULL pointer.
            // This is still an error for us, but dlerror will not return any error.
            io::Error::other("aa_change_onexec symbol is a NULL pointer")
        } else {
            // SAFETY: In case of an error, dlerror returns a valid C string.
            io::Error::new(io::ErrorKind::NotFound, unsafe {
                CStr::from_ptr(err).to_string_lossy().into_owned()
            })
        });
    }

    //SAFETY: aa_change_onexec is non-NULL, so we can cast it into a function pointer
    let aa_change_onexec: unsafe extern "C" fn(*const c_char) -> c_int =
        unsafe { mem::transmute(aa_change_onexec) };

    let new_profile_cstr = CString::new(new_profile)?;
    // SAFETY: new_profile_cstr provided by CString ensures a valid ptr
    cerr(unsafe { aa_change_onexec(new_profile_cstr.as_ptr()) })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_without_confinement_is_always_accepted() {
        assert!(ensure_profile_supported(None).is_ok());
    }

    #[test]
    fn a_selected_profile_is_refused_unless_it_can_be_applied() {
        let result = ensure_profile_supported(Some("confined"));
        if SUPPORTED {
            // Whether the running kernel has AppArmor loaded is decided later,
            // by set_profile_for_next_exec; this check is about the build.
            assert!(result.is_ok());
        } else {
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            assert!(!err.to_string().is_empty());
        }
    }
}
