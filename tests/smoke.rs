//! Live smoke tests. All are cfg(windows).

#![cfg(windows)]

use windows_token::{Privilege, SecurityImpersonationLevel, Token, TokenType};

#[test]
fn open_current_process_token() {
    let tok = Token::open_current_process().expect("open current-process token");
    assert!(!tok.as_raw().is_invalid(), "expected a live token handle");
}

#[test]
fn sechangenotify_is_enabled_for_normal_user() {
    // SeChangeNotifyPrivilege ("bypass traverse checking") is granted and
    // enabled for every interactive user by default. If this ever fails on a
    // stock account, the machine's local policy has been custom-hardened.
    let tok = Token::open_current_process().expect("open token");
    let prev = tok
        .enable_privilege(Privilege::SeChangeNotify)
        .expect("SeChangeNotify should be present on every normal user");
    assert!(prev.was_applied);
    assert_eq!(prev.privilege, Privilege::SeChangeNotify);
}

#[test]
fn duplicate_round_trip_impersonation_and_revert() {
    let tok = Token::open_current_process().expect("open token");
    let dup = tok
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
        )
        .expect("duplicate as impersonation");
    assert!(!dup.as_raw().is_invalid());

    // Impersonate, then let the guard drop → RevertToSelf runs. If the guard
    // failed to revert, subsequent OpenProcessToken(GetCurrentProcess()) would
    // still succeed but any privilege-adjust would refer to the wrong token.
    // We can at least prove the drop path executes without panicking.
    {
        let _g = dup.impersonate_on_thread().expect("impersonate");
        // guard drops here → RevertToSelf
    }

    // A second impersonation on the same thread should work (proves the
    // previous revert really landed; otherwise the thread would still be
    // carrying the last impersonation token).
    let _g2 = dup.impersonate_on_thread().expect("re-impersonate");
}
