//! Minimal owned SID wrapper — enough to render `S-1-...` and read the last
//! subauthority (needed for integrity-level classification). Deliberately
//! avoids `ConvertSidToStringSidW` to keep the feature list narrow.

use crate::error::{Error, Result};
use windows::Win32::Security::{
    GetLengthSid, GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
    IsValidSid, PSID,
};

/// Owned copy of a SID as a raw byte blob. Cheap, `Send + Sync`, no handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Copy a SID pointed to by `psid` into an owned buffer.
    ///
    /// # Safety
    /// `psid` must point to a valid SID for the duration of the call.
    pub(crate) unsafe fn copy_from(psid: PSID) -> Result<Self> {
        if !IsValidSid(psid).as_bool() {
            return Err(Error::win32(
                "IsValidSid",
                windows_core::Error::from_win32(),
            ));
        }
        let len = GetLengthSid(psid) as usize;
        let mut buf = vec![0u8; len];
        core::ptr::copy_nonoverlapping(psid.0 as *const u8, buf.as_mut_ptr(), len);
        Ok(Sid(buf))
    }

    /// Return the last subauthority (used for integrity-level classification).
    pub fn last_subauthority(&self) -> Option<u32> {
        unsafe {
            let psid = PSID(self.0.as_ptr() as *mut _);
            let count_ptr = GetSidSubAuthorityCount(psid);
            if count_ptr.is_null() {
                return None;
            }
            let count = *count_ptr;
            if count == 0 {
                return None;
            }
            let sub_ptr = GetSidSubAuthority(psid, (count - 1) as u32);
            if sub_ptr.is_null() {
                None
            } else {
                Some(*sub_ptr)
            }
        }
    }

    /// Return the number of subauthorities in this SID.
    pub fn subauthority_count(&self) -> u8 {
        unsafe {
            let psid = PSID(self.0.as_ptr() as *mut _);
            let count_ptr = GetSidSubAuthorityCount(psid);
            if count_ptr.is_null() {
                0
            } else {
                *count_ptr
            }
        }
    }

    /// Return the raw bytes of the SID (for callers doing lookups).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Format as the canonical `S-R-I-S1-S2-...` string.
    pub fn to_display_string(&self) -> String {
        unsafe {
            let psid = PSID(self.0.as_ptr() as *mut _);
            let revision = self.0[0];
            let count_ptr = GetSidSubAuthorityCount(psid);
            let count = if count_ptr.is_null() { 0 } else { *count_ptr };
            let auth_ptr = GetSidIdentifierAuthority(psid);
            // SID_IDENTIFIER_AUTHORITY::Value is [u8; 6], big-endian
            let auth_bytes = if auth_ptr.is_null() {
                [0u8; 6]
            } else {
                (*auth_ptr).Value
            };
            let auth: u64 = auth_bytes
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | b as u64);

            let mut s = format!("S-{}-{}", revision, auth);
            for i in 0..count {
                let sub_ptr = GetSidSubAuthority(psid, i as u32);
                if sub_ptr.is_null() {
                    break;
                }
                s.push_str(&format!("-{}", *sub_ptr));
            }
            s
        }
    }
}

impl core::fmt::Display for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

/// Coarse integrity-level classification derived from the mandatory-label SID.
///
/// The kernel encodes integrity as the last subauthority of an `S-1-16-*` SID
/// (`SECURITY_MANDATORY_*_RID`). Values that don't match a named level fall
/// into [`IntegrityLevel::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityLevel {
    Untrusted,  // 0x0000
    Low,        // 0x1000
    Medium,     // 0x2000
    MediumPlus, // 0x2100
    High,       // 0x3000
    System,     // 0x4000
    Protected,  // 0x5000
    Other(u32),
}

impl IntegrityLevel {
    pub fn from_rid(rid: u32) -> Self {
        match rid {
            0x0000 => IntegrityLevel::Untrusted,
            0x1000 => IntegrityLevel::Low,
            0x2000 => IntegrityLevel::Medium,
            0x2100 => IntegrityLevel::MediumPlus,
            0x3000 => IntegrityLevel::High,
            0x4000 => IntegrityLevel::System,
            0x5000 => IntegrityLevel::Protected,
            other => IntegrityLevel::Other(other),
        }
    }
}
