//! Inspect the current Windows access token and prove scoped impersonation.
//!
//! Usage:
//!   cargo run --example current_identity
//!
//! The duplicated token represents the same identity as the caller. The
//! impersonation guard always calls RevertToSelf when the scope ends.

use windows_token::{SecurityImpersonationLevel, Token, TokenType};

fn main() -> windows_token::Result<()> {
    let token = Token::open_current_process()?;
    println!("user_sid={}", token.user_sid()?);
    println!("integrity={:?}", token.integrity_level()?);

    let duplicate = token.duplicate(
        TokenType::Impersonation,
        SecurityImpersonationLevel::Impersonation,
    )?;
    {
        let _guard = duplicate.impersonate_on_thread()?;
        println!("scoped_self_impersonation=active");
    }
    println!("scoped_self_impersonation=reverted");

    Ok(())
}
