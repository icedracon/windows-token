//! # windows-token
//!
//! RAII wrappers over the Win32 access-token surface:
//! `OpenProcessToken`, `OpenThreadToken`, `DuplicateTokenEx`,
//! `ImpersonateLoggedOnUser`, `SetThreadToken`, `LookupPrivilegeValue`,
//! `AdjustTokenPrivileges`.
//!
//! The single hard requirement: dropping an [`ImpersonationGuard`] calls
//! `RevertToSelf`, always — including on unwind. Hand-written impersonation
//! code (Rubeus-style) forgets this on early returns; here it is structurally
//! impossible.
//!
//! ## Status
//!
//! **0.1.0-dev — pre-alpha.** Skeleton with the intended API surface, a
//! partial implementation of the core primitives (open / duplicate / adjust /
//! impersonate / query user + integrity), and structural + smoke + round-trip
//! tests. Not yet exercised against a live DC. `OpenThreadToken` and named-SID
//! lookup (`LookupAccountSidW`) are not yet wired.
//!
//! ## Example
//!
//! ```no_run
//! use windows_token::{Token, Privilege};
//!
//! let tok = Token::open_current_process()?;
//! // Normal users always hold SeChangeNotifyPrivilege enabled.
//! let prev = tok.enable_privilege(Privilege::SeChangeNotify)?;
//! let _ = prev;
//! # Ok::<(), windows_token::Error>(())
//! ```

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

#[cfg(windows)]
mod error;
#[cfg(windows)]
mod impersonation;
#[cfg(windows)]
mod privilege;
#[cfg(windows)]
mod sid;
#[cfg(windows)]
mod token;

#[cfg(windows)]
pub use error::{Error, Result};
#[cfg(windows)]
pub use impersonation::ImpersonationGuard;
#[cfg(windows)]
pub use privilege::{PrevState, Privilege};
#[cfg(windows)]
pub use sid::{IntegrityLevel, Sid};
#[cfg(windows)]
pub use token::{SecurityImpersonationLevel, Token, TokenType};

#[cfg(not(windows))]
compile_error!("windows-token targets Windows only (cfg(windows)). Build on Windows or use a cross-compilation target.");
