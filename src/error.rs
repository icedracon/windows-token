//! Error type for windows-token.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("win32 call {op} failed: {source}")]
    Win32 {
        op: &'static str,
        #[source]
        source: windows_core::Error,
    },

    #[error("privilege {0:?} not held or could not be adjusted")]
    PrivilegeNotHeld(crate::privilege::Privilege),

    #[error("token information class {class} returned an unexpected buffer size")]
    BadTokenInfoSize { class: &'static str },

    #[error("this API is only available on windows")]
    NotOnWindows,
}

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub(crate) fn win32(op: &'static str, source: windows_core::Error) -> Self {
        Error::Win32 { op, source }
    }
}
