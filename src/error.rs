//! Error type for windows-token.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("win32 call {op} failed: 0x{code:08x}")]
    Win32 { op: &'static str, code: u32 },

    #[error("privilege {0:?} not held or could not be adjusted")]
    PrivilegeNotHeld(crate::privilege::Privilege),

    #[error("token information class {class} returned an unexpected buffer size")]
    BadTokenInfoSize { class: &'static str },

    #[error("this API is only available on windows")]
    NotOnWindows,
}

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Build an `Error::Win32` from the current thread's `GetLastError()` value.
    pub(crate) fn from_last_os_error(op: &'static str) -> Self {
        let code = unsafe { win32_min::foundation::GetLastError() };
        Error::Win32 { op, code }
    }
}
