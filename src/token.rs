//! Owned `HANDLE` wrapper: RAII, `Send + !Sync` (kernel handles are safe to
//! move between threads but not to share, since duplicate operations mutate
//! kernel state associated with the handle).

use crate::error::{Error, Result};
use crate::impersonation::ImpersonationGuard;
use crate::privilege::{adjust_enable, PrevState, Privilege};
use crate::sid::{IntegrityLevel, Sid};

use core::ffi::c_void;
use win32_min::foundation::{CloseHandle, HANDLE};
use win32_min::security_token::{
    DuplicateTokenEx, GetCurrentProcess, GetTokenInformation, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, SECURITY_IMPERSONATION_LEVEL, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_TYPE, TOKEN_USER,
};

/// TOKEN_TYPE alias — primary tokens are the ones you can assign to a new
/// process (`CreateProcessAsUserW`); impersonation tokens attach to a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Primary,
    Impersonation,
}

impl TokenType {
    fn as_win32(self) -> TOKEN_TYPE {
        match self {
            TokenType::Primary => TOKEN_TYPE::TokenPrimary,
            TokenType::Impersonation => TOKEN_TYPE::TokenImpersonation,
        }
    }
}

/// Mirrors `SECURITY_IMPERSONATION_LEVEL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityImpersonationLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegation,
}

impl SecurityImpersonationLevel {
    fn as_win32(self) -> SECURITY_IMPERSONATION_LEVEL {
        match self {
            SecurityImpersonationLevel::Anonymous => {
                SECURITY_IMPERSONATION_LEVEL::SecurityAnonymous
            }
            SecurityImpersonationLevel::Identification => {
                SECURITY_IMPERSONATION_LEVEL::SecurityIdentification
            }
            SecurityImpersonationLevel::Impersonation => {
                SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation
            }
            SecurityImpersonationLevel::Delegation => {
                SECURITY_IMPERSONATION_LEVEL::SecurityDelegation
            }
        }
    }
}

/// Owned access token handle. Closed on drop.
#[derive(Debug)]
pub struct Token {
    handle: HANDLE,
}

// HANDLE is a kernel handle — safe to move across threads, but concurrent
// access from multiple threads is a footgun (state mutation via Adjust*, etc.).
unsafe impl Send for Token {}

impl Token {
    /// Wrap a raw handle. The `Token` takes ownership and will `CloseHandle`
    /// on drop.
    ///
    /// # Safety
    /// `handle` must be a valid, owned access-token handle that is not closed
    /// or duplicated elsewhere.
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Token { handle }
    }

    /// Consume the wrapper and return the raw handle without closing it.
    pub fn into_raw(mut self) -> HANDLE {
        let h = self.handle;
        // Prevent Drop from closing.
        self.handle = core::ptr::null_mut();
        h
    }

    /// Borrow the underlying handle.
    pub fn as_raw(&self) -> HANDLE {
        self.handle
    }

    /// `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE, ...)`.
    ///
    /// The default access mask is the intersection of what most callers need:
    /// query info (SID, integrity), toggle privileges, and duplicate. Use
    /// [`Token::open_current_process_with_access`] for a custom mask.
    pub fn open_current_process() -> Result<Self> {
        Self::open_current_process_with_access(
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE,
        )
    }

    pub fn open_current_process_with_access(access: u32) -> Result<Self> {
        let mut h: HANDLE = core::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) };
        if ok == 0 {
            return Err(Error::from_last_os_error("OpenProcessToken(current)"));
        }
        Ok(Token { handle: h })
    }

    /// `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid)` then `OpenProcessToken`.
    ///
    /// Requires `SeDebugPrivilege` on the caller's token for processes not
    /// owned by the caller. Enable it via
    /// `Token::open_current_process()?.enable_privilege(Privilege::SeDebug)?`.
    pub fn open_process(pid: u32, access: u32) -> Result<Self> {
        let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if proc_handle.is_null() {
            return Err(Error::from_last_os_error("OpenProcess"));
        }
        // Ensure the process handle is always closed, even on early return.
        let _proc_guard = HandleGuard(proc_handle);

        let mut h: HANDLE = core::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(proc_handle, access, &mut h) };
        if ok == 0 {
            return Err(Error::from_last_os_error("OpenProcessToken(pid)"));
        }
        Ok(Token { handle: h })
    }

    /// Duplicate this token. Combine `ty` and `level` to produce either a
    /// primary token (for `CreateProcessAsUserW`) or an impersonation token
    /// (for `SetThreadToken` / `ImpersonateLoggedOnUser`).
    pub fn duplicate(&self, ty: TokenType, level: SecurityImpersonationLevel) -> Result<Token> {
        let mut new_h: HANDLE = core::ptr::null_mut();
        let ok = unsafe {
            DuplicateTokenEx(
                self.handle,
                TOKEN_ALL_ACCESS,
                core::ptr::null(),
                level.as_win32(),
                ty.as_win32(),
                &mut new_h,
            )
        };
        if ok == 0 {
            return Err(Error::from_last_os_error("DuplicateTokenEx"));
        }
        Ok(Token { handle: new_h })
    }

    /// Enable a named privilege. Returns the previous state so the caller can
    /// restore it. Errors with [`Error::PrivilegeNotHeld`] if the privilege is
    /// not present on this token (the classic
    /// `ERROR_NOT_ALL_ASSIGNED` case that `AdjustTokenPrivileges` reports via
    /// `GetLastError` on nominal success).
    pub fn enable_privilege(&self, p: Privilege) -> Result<PrevState> {
        adjust_enable(self.handle, p)
    }

    /// Impersonate this token on the calling thread via
    /// `ImpersonateLoggedOnUser`. Drop of the returned guard =
    /// `RevertToSelf`, always — including on unwind.
    pub fn impersonate_on_thread(&self) -> Result<ImpersonationGuard> {
        ImpersonationGuard::impersonate_logged_on(self.handle)
    }

    /// Attach this token to the current thread via `SetThreadToken`. Requires
    /// the token to be an impersonation token. Drop = `RevertToSelf`.
    pub fn set_on_current_thread(&self) -> Result<ImpersonationGuard> {
        ImpersonationGuard::set_on_current_thread(self.handle)
    }

    /// `GetTokenInformation(TokenUser)` → owned `Sid`.
    pub fn user_sid(&self) -> Result<Sid> {
        let buf = get_token_info_var(self.handle, TOKEN_INFORMATION_CLASS::TokenUser, "TokenUser")?;
        if buf.len() < core::mem::size_of::<TOKEN_USER>() {
            return Err(Error::BadTokenInfoSize { class: "TokenUser" });
        }
        unsafe {
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            Sid::copy_from(tu.User.Sid)
        }
    }

    /// `GetTokenInformation(TokenIntegrityLevel)` → parsed level.
    pub fn integrity_level(&self) -> Result<IntegrityLevel> {
        let buf = get_token_info_var(
            self.handle,
            TOKEN_INFORMATION_CLASS::TokenIntegrityLevel,
            "TokenIntegrityLevel",
        )?;
        if buf.len() < core::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
            return Err(Error::BadTokenInfoSize {
                class: "TokenIntegrityLevel",
            });
        }
        let sid = unsafe {
            let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            Sid::copy_from(tml.Label.Sid)?
        };
        let rid = sid.last_subauthority().unwrap_or(0);
        Ok(IntegrityLevel::from_rid(rid))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Local RAII closer for a raw HANDLE that we don't want to wrap in `Token`.
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Two-call idiom for variable-length `GetTokenInformation`.
fn get_token_info_var(
    handle: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    label: &'static str,
) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    unsafe {
        // First call: pass length 0 to learn the required size. This
        // deliberately errors with ERROR_INSUFFICIENT_BUFFER; we ignore that
        // failure and act on `needed`.
        let _ = GetTokenInformation(handle, class, core::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(Error::BadTokenInfoSize { class: label });
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            handle,
            class,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        if ok == 0 {
            return Err(Error::from_last_os_error("GetTokenInformation"));
        }
        Ok(buf)
    }
}
