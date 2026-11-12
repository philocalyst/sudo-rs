#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fmt::{self, Write};

pub use command::CommandAndArguments;
pub use context::Context;
pub use error::Error;
pub use path::SudoPath;
pub use string::SudoString;

pub mod bin_serde;
pub mod command;
pub mod context;
pub mod error;
mod path;
pub mod resolve;
mod string;

// Hardened enum values used for critical enums to mitigate attacks like Rowhammer.
// See for example https://arxiv.org/pdf/2309.02545.pdf
// The values are copied from https://github.com/sudo-project/sudo/commit/7873f8334c8d31031f8cfa83bd97ac6029309e4f#diff-b8ac7ab4c3c4a75aed0bb5f7c5fd38b9ea6c81b7557f775e46c6f8aa115e02cd
pub const HARDENED_ENUM_VALUE_0: u32 = 0x52a2925; // 0101001010100010100100100101
pub const HARDENED_ENUM_VALUE_1: u32 = 0xad5d6da; // 1010110101011101011011011010
pub const HARDENED_ENUM_VALUE_2: u32 = 0x69d61fc8; // 1101001110101100001111111001000
pub const HARDENED_ENUM_VALUE_3: u32 = 0x1629e037; // 0010110001010011110000000110111
pub const HARDENED_ENUM_VALUE_4: u32 = 0x1fc8d3ac; // 11111110010001101001110101100
pub const HARDENED_ENUM_VALUE_5: u32 = 0x70372c52; // 1110000001101110010110001010011

/// Exit, with a warning, unless SUDO_RS_IS_UNSTABLE acknowledges that sudo-rs may break the
/// system. This is an acknowledgement, not a security boundary.
pub(crate) fn unstable_warning() {
    let check_var = std::env::var("SUDO_RS_IS_UNSTABLE").unwrap_or_default();

    if check_var != "I accept that my system may break unexpectedly" {
        eprintln_ignore_io_error!(
            "WARNING!
Sudo-rs is compiled with development logs on, or runs on a platform it does not support yet,
which means it is less secure and could potentially break your system. We recommend that you
do not run this on any production environment.
To turn off this warning and use sudo-rs you need to set the environment variable
SUDO_RS_IS_UNSTABLE to the value `I accept that my system may break unexpectedly`."
        );

        std::process::exit(1);
    }
}

// FIXME replace with OsStr::display() once our MSRV is 1.87
pub(crate) struct DisplayOsStr<'a>(pub(crate) &'a OsStr);

impl fmt::Display for DisplayOsStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.as_encoded_bytes().utf8_chunks() {
            let valid = chunk.valid();
            // If we successfully decoded the whole chunk as a valid string then
            // we can return a direct formatting of the string which will also
            // respect various formatting flags if possible.
            if chunk.invalid().is_empty() {
                return valid.fmt(f);
            }

            f.write_str(valid)?;
            f.write_char(char::REPLACEMENT_CHARACTER)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn unstable_warning_needs_the_exact_acknowledgement() {
        const CHILD: &str = "SUDO_RS_TEST_UNSTABLE_WARNING";
        if std::env::var_os(CHILD).is_some() {
            super::unstable_warning();
            crate::system::_exit(42);
        }

        // unstable_warning exits the process, so it runs in a fresh copy of the test binary
        let accept = "I accept that my system may break unexpectedly";
        for (value, status) in [(None, 1), (Some("yes"), 1), (Some(accept), 42)] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "common::tests::unstable_warning_needs_the_exact_acknowledgement",
                ])
                .env(CHILD, "1")
                .env_remove("SUDO_RS_IS_UNSTABLE")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(value) = value {
                command.env("SUDO_RS_IS_UNSTABLE", value);
            }
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(60);
            let exit = loop {
                if let Some(exit) = child.try_wait().unwrap() {
                    break exit;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the test process did not exit within 60 seconds");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            // exits with 1 when refusing; 42 only after unstable_warning returned
            assert_eq!(exit.code(), Some(status), "SUDO_RS_IS_UNSTABLE={value:?}");
        }
    }
}
