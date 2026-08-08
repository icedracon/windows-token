//! Named privileges and `AdjustTokenPrivileges` wrapper.

use crate::error::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::LUID;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES,
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
        let mut luid = LUID::default();
        unsafe {
            LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid)
                .map_err(|e| Error::win32("LookupPrivilegeValueW", e))?;
        }
        Ok(luid)
    }
}

/// Snapshot returned by [`Token::enable_privilege`] so the caller can restore
/// the prior state. `attributes` is the previous `TOKEN_PRIVILEGES_ATTRIBUTES`
/// bitmask (0 = disabled, `SE_PRIVILEGE_ENABLED` = enabled, etc.).
#[derive(Debug, Clone)]
pub struct PrevState {
    pub privilege: Privilege,
    pub luid: LUID,
    pub attributes: TOKEN_PRIVILEGES_ATTRIBUTES,
    /// True if `AdjustTokenPrivileges` returned success AND `GetLastError()`
    /// was NOT `ERROR_NOT_ALL_ASSIGNED` (which the API signals via last-error
    /// even on nominal success). False = privilege was not present on the token.
    pub was_applied: bool,
}

pub(crate) fn adjust_enable(
    token: windows::Win32::Foundation::HANDLE,
    priv_enum: Privilege,
) -> Result<PrevState> {
    let luid = priv_enum.lookup_luid()?;

    let new_state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let mut prev = TOKEN_PRIVILEGES::default();
    let mut ret_len: u32 = 0;

    // AdjustTokenPrivileges is peculiar: it returns success even when the
    // privilege is not held on the token; the caller MUST inspect GetLastError.
    let res = unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(&new_state),
            core::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            Some(&mut prev),
            Some(&mut ret_len),
        )
    };
    res.map_err(|e| Error::win32("AdjustTokenPrivileges", e))?;

    let last = unsafe { windows::Win32::Foundation::GetLastError() };
    // 1300 = ERROR_NOT_ALL_ASSIGNED
    let was_applied = last.0 != 1300;

    let prev_attrs = if prev.PrivilegeCount >= 1 {
        prev.Privileges[0].Attributes
    } else {
        TOKEN_PRIVILEGES_ATTRIBUTES(0)
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
