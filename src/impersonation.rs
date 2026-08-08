//! RAII impersonation guard. `Drop` always calls `RevertToSelf`, including on
//! unwind — this is the whole point of the wrapper. The single most common
//! hand-written Rubeus bug is forgetting the revert on early return; here it
//! is structurally impossible.

use crate::error::{Error, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
use windows::Win32::System::Threading::SetThreadToken;

/// RAII guard. While alive the current thread runs under the impersonation
/// context set at construction. Dropped = `RevertToSelf` called; failures are
/// swallowed (there is nothing sensible to do on drop) but a `debug_assert!`
/// will trip in debug builds.
///
/// The guard is intentionally `!Send + !Sync` — thread-token state is
/// per-thread and moving it across threads would be a bug.
#[must_use = "dropping this guard calls RevertToSelf; if you drop it immediately \
              the impersonation is instantly reverted"]
pub struct ImpersonationGuard {
    _not_send: core::marker::PhantomData<*const ()>,
}

impl ImpersonationGuard {
    /// Call `ImpersonateLoggedOnUser` on `token` and return a guard.
    pub(crate) fn impersonate_logged_on(token: HANDLE) -> Result<Self> {
        unsafe {
            ImpersonateLoggedOnUser(token)
                .map_err(|e| Error::win32("ImpersonateLoggedOnUser", e))?;
        }
        Ok(ImpersonationGuard {
            _not_send: core::marker::PhantomData,
        })
    }

    /// Call `SetThreadToken(nullptr, token)` and return a guard. Used when the
    /// token is an impersonation token that must be attached to the current
    /// thread directly (as opposed to `ImpersonateLoggedOnUser`, which does a
    /// duplicate-and-attach internally).
    pub(crate) fn set_on_current_thread(token: HANDLE) -> Result<Self> {
        unsafe {
            SetThreadToken(None, token).map_err(|e| Error::win32("SetThreadToken", e))?;
        }
        Ok(ImpersonationGuard {
            _not_send: core::marker::PhantomData,
        })
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // The revert MUST run even during unwind. Failure is logged in debug
        // only — production callers cannot handle a failed revert anyway
        // (thread is in an undefined identity state; abort might be safer).
        unsafe {
            let r = RevertToSelf();
            debug_assert!(
                r.is_ok(),
                "RevertToSelf failed in ImpersonationGuard::drop: {:?}",
                r
            );
        }
    }
}
