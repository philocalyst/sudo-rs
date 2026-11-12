#!/bin/sh
# Compare the bindings actually used by this target with its native PAM headers.
# Requires a native Rust compiler and C11 compiler, but not bindgen.
set -eu
case $(uname -s) in
    Linux) bindings=sys_linuxpam.rs ;;
    FreeBSD|NetBSD|Darwin) bindings=sys_openpam.rs ;;
    *) echo 'Unsupported PAM platform' >&2; exit 1 ;;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp "$root/src/pam/$bindings" "$work/sys.rs"
cat > "$work/probe.rs" <<'RS'
#![allow(dead_code, nonstandard_style)]
mod sys;
use std::mem::{align_of, offset_of, size_of};
use std::ffi::{c_char, c_int, c_void};
use sys::{pam_handle_t, pam_conv, pam_message, pam_response};
fn main() {
    println!("#include <stddef.h>\n#include <security/pam_appl.h>");
    macro_rules! layout {
        ($ty:ident, $($field:ident),+) => {
            println!("_Static_assert(sizeof(struct {}) == {}, \"size\");", stringify!($ty), size_of::<sys::$ty>());
            println!("_Static_assert(_Alignof(struct {}) == {}, \"alignment\");", stringify!($ty), align_of::<sys::$ty>());
            $(println!("_Static_assert(offsetof(struct {}, {}) == {}, \"offset\");", stringify!($ty), stringify!($field), offset_of!(sys::$ty, $field));)+
        }
    }
    layout!(pam_message, msg_style, msg);
    layout!(pam_response, resp, resp_retcode);
    layout!(pam_conv, conv, appdata_ptr);
    macro_rules! signature {
        ($name:ident, $rust:ty, $c:literal) => {
            let _: $rust = sys::$name;
            println!("_Static_assert(_Generic(&{}, {}: 1, default: 0), \"{} signature\");", stringify!($name), $c, stringify!($name));
        }
    }
    macro_rules! flags {
        ($($name:ident),+) => { $(signature!($name, unsafe extern "C" fn(*mut pam_handle_t, c_int) -> c_int, "int (*)(pam_handle_t *, int)");)+ }
    }
    flags!(pam_acct_mgmt, pam_authenticate, pam_chauthtok, pam_close_session, pam_end, pam_open_session, pam_setcred);
    signature!(pam_get_item, unsafe extern "C" fn(*const pam_handle_t, c_int, *mut *const c_void) -> c_int, "int (*)(const pam_handle_t *, int, const void **)");
    signature!(pam_set_item, unsafe extern "C" fn(*mut pam_handle_t, c_int, *const c_void) -> c_int, "int (*)(pam_handle_t *, int, const void *)");
    signature!(pam_getenvlist, unsafe extern "C" fn(*mut pam_handle_t) -> *mut *mut c_char, "char **(*)(pam_handle_t *)");
    signature!(pam_start, unsafe extern "C" fn(*const c_char, *const c_char, *const pam_conv, *mut *mut pam_handle_t) -> c_int, "int (*)(const char *, const char *, const struct pam_conv *, pam_handle_t **)");
    #[cfg(target_os = "linux")]
    signature!(pam_strerror, unsafe extern "C" fn(*mut pam_handle_t, c_int) -> *const c_char, "const char *(*)(pam_handle_t *, int)");
    #[cfg(not(target_os = "linux"))]
    signature!(pam_strerror, unsafe extern "C" fn(*const pam_handle_t, c_int) -> *const c_char, "const char *(*)(const pam_handle_t *, int)");
    let conv: pam_conv = unsafe { std::mem::zeroed() };
    let _: Option<unsafe extern "C" fn(c_int, *mut *const pam_message, *mut *mut pam_response, *mut c_void) -> c_int> = conv.conv;
    println!("_Static_assert(_Generic(((struct pam_conv *)0)->conv, int (*)(int, const struct pam_message **, struct pam_response **, void *): 1, default: 0), \"conversation signature\");");
}
RS
rustc --edition=2024 "$work/probe.rs" -o "$work/probe"
"$work/probe" > "$work/probe.c"
# The generated shared OpenPAM file also contains PAM_BAD_ITEM. Apple does
# not define it, and error.rs deliberately does not use it on that target.
awk -v apple="$(uname -s)" '
/^pub const PAM_/ {
    name=$3; sub(/:$/, "", name)
    if (apple == "Darwin" && name == "PAM_BAD_ITEM") next
    value=$NF; sub(/;$/, "", value)
    if (value !~ /^-?[0-9]+$/) { print "unsupported binding expression" > "/dev/stderr"; exit 1 }
    printf "_Static_assert(%s == %s, \"%s\");\n", name, value, name
}' "$work/sys.rs" >> "$work/probe.c"
${CC:-cc} -std=c11 -Werror -fsyntax-only "$work/probe.c"
echo "PAM constants, layouts and function signatures match $(uname -s) headers"
