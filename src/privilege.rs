//! Named privileges and `AdjustTokenPrivileges` wrapper.

use crate::error::{Error, Result};
use win32_min::foundation::{GetLastError, HANDLE, LUID, PCWSTR};
use win32_min::security_token::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES,
};

/// Well-known token privileges. Names map 1:1 to the `SE_*_NAME` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    SeDebug,
    SeBackup,
    SeTcb,
    SeRestore,
    SeAssignPrimary,
    SeSecurity,
    SeShutdown,
    SeChangeNotify,
    SeImpersonate,
    SeIncreaseQuota,
    SeLoadDriver,
    SeSystemtimePrivilege,
    SeTakeOwnership,
}

impl Privilege {
    pub fn as_str(&self) -> &'static str {
        match self {
            Privilege::SeDebug => "SeDebugPrivilege",
            Privilege::SeBackup => "SeBackupPrivilege",
            Privilege::SeTcb => "SeTcbPrivilege",
            Privilege::SeRestore => "SeRestorePrivilege",
            Privilege::SeAssignPrimary => "SeAssignPrimaryTokenPrivilege",
            Privilege::SeSecurity => "SeSecurityPrivilege",
            Privilege::SeShutdown => "SeShutdownPrivilege",
            Privilege::SeChangeNotify => "SeChangeNotifyPrivilege",
            Privilege::SeImpersonate => "SeImpersonatePrivilege",
            Privilege::SeIncreaseQuota => "SeIncreaseQuotaPrivilege",
            Privilege::SeLoadDriver => "SeLoadDriverPrivilege",
            Privilege::SeSystemtimePrivilege => "SeSystemtimePrivilege",
            Privilege::SeTakeOwnership => "SeTakeOwnershipPrivilege",
        }
    }

    /// Resolve the LUID for this privilege on the local system.
    pub fn lookup_luid(&self) -> Result<LUID> {
        let mut wide: Vec<u16> = self.as_str().encode_utf16().collect();
        wide.push(0);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let ok = unsafe { LookupPrivilegeValueW(PCWSTR::NULL, PCWSTR(wide.as_ptr()), &mut luid) };
        if ok == 0 {
            return Err(Error::from_last_os_error("LookupPrivilegeValueW"));
        }
        Ok(luid)
    }
}

/// Snapshot returned by [`crate::Token::enable_privilege`] so the caller can restore
/// the prior state. `attributes` is the previous privilege attribute bitmask
/// (0 = disabled, `SE_PRIVILEGE_ENABLED` = enabled, etc.).
#[derive(Debug, Clone)]
pub struct PrevState {
    pub privilege: Privilege,
    pub luid: LUID,
    pub attributes: u32,
    /// True if `AdjustTokenPrivileges` returned success AND `GetLastError()`
    /// was NOT `ERROR_NOT_ALL_ASSIGNED` (which the API signals via last-error
    /// even on nominal success). False = privilege was not present on the token.
    pub was_applied: bool,
}

pub(crate) fn adjust_enable(token: HANDLE, priv_enum: Privilege) -> Result<PrevState> {
    let luid = priv_enum.lookup_luid()?;

    let new_state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let mut prev = TOKEN_PRIVILEGES {
        PrivilegeCount: 0,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            Attributes: 0,
        }],
    };
    let mut ret_len: u32 = 0;

    // AdjustTokenPrivileges is peculiar: it returns success even when the
    // privilege is not held on the token; the caller MUST inspect GetLastError.
    let ok = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &new_state,
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            &mut prev,
            &mut ret_len,
        )
    };
    if ok == 0 {
        return Err(Error::from_last_os_error("AdjustTokenPrivileges"));
    }

    let last = unsafe { GetLastError() };
    // 1300 = ERROR_NOT_ALL_ASSIGNED
    let was_applied = last != 1300;

    let prev_attrs = if prev.PrivilegeCount >= 1 {
        prev.Privileges[0].Attributes
    } else {
        0
    };

    if !was_applied {
        return Err(Error::PrivilegeNotHeld(priv_enum));
    }

    Ok(PrevState {
        privilege: priv_enum,
        luid,
        attributes: prev_attrs,
        was_applied,
    })
}
