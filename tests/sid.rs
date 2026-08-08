//! Structural tests around SID + integrity-level parsing.

#![cfg(windows)]

use windows_token::{IntegrityLevel, Token};

#[test]
fn user_sid_is_formatted_canonically() {
    let tok = Token::open_current_process().expect("open token");
    let sid = tok.user_sid().expect("query user SID");
    let s = sid.to_display_string();
    assert!(s.starts_with("S-1-"), "sid should be canonical: {}", s);
    assert!(sid.subauthority_count() >= 1);
    assert!(sid.last_subauthority().is_some());
}

#[test]
fn integrity_level_is_recognisable() {
    let tok = Token::open_current_process().expect("open token");
    let il = tok.integrity_level().expect("query integrity");
    // Every process on modern Windows is at least Low; unelevated interactive
    // user processes are Medium; elevated is High; services are System.
    assert!(
        matches!(
            il,
            IntegrityLevel::Low
                | IntegrityLevel::Medium
                | IntegrityLevel::MediumPlus
                | IntegrityLevel::High
                | IntegrityLevel::System
                | IntegrityLevel::Other(_)
        ),
        "unexpected IL: {:?}",
        il
    );
}
