# windows-token

[![Crates.io](https://img.shields.io/crates/v/windows-token.svg)](https://crates.io/crates/windows-token)
[![Docs.rs](https://docs.rs/windows-token/badge.svg)](https://docs.rs/windows-token)
[![CI](https://github.com/icedracon/windows-token/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/windows-token/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

RAII wrappers over the Win32 access-token surface — `OpenProcessToken`,
`DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `SetThreadToken`,
`AdjustTokenPrivileges`. The single hard invariant: dropping an
`ImpersonationGuard` calls `RevertToSelf` — always, including on unwind.
Hand-written impersonation code (popular Kerberos clients-style) forgets this on early returns;
here it is structurally impossible.

## Status

**`0.2` tested companion crate.** The token, privilege, duplication, SID, and
scoped impersonation paths are implemented on top of `win32-min`; APIs may
still evolve before 1.0. See the central
[`win32-min` ecosystem map](https://github.com/icedracon/win32-min/blob/master/ECOSYSTEM.md)
for compatibility and maturity information.

## What it does

Handle-owning wrappers around the token API described in the
`Access Tokens` section of the Windows security model (see
`processthreadsapi.h` and the `TOKEN_INFORMATION_CLASS` enumeration).
Correctly reads `ERROR_NOT_ALL_ASSIGNED` from `GetLastError` on nominal
`AdjustTokenPrivileges` success — the one thing every hand-rolled
"enable SeDebugPrivilege" snippet on the internet gets wrong.

## Usage

```rust,no_run
use windows_token::{Token, Privilege};

fn main() -> windows_token::Result<()> {
    let tok = Token::open_current_process()?;

    // Enable SeChangeNotifyPrivilege (normal users always hold this).
    let _prev = tok.enable_privilege(Privilege::SeChangeNotify)?;

    // Impersonation with guaranteed revert:
    {
        let _g = tok.impersonate_on_thread()?;
        // ...do work under the impersonated identity...
    } // <- RevertToSelf on drop, including on panic

    println!("user = {}",   tok.user_sid()?);
    println!("il   = {:?}", tok.integrity_level()?);
    Ok(())
}
```

## Research workflow

Inspect the current identity and integrity level, then prove that duplicated
self-impersonation is reverted by the RAII guard:

```powershell
cargo run --example current_identity
```

This workflow does not require elevation, enable a privilege, or impersonate a
different account. See the ecosystem's complete
[`RESEARCH-WORKFLOWS.md`](https://github.com/icedracon/win32-min/blob/master/RESEARCH-WORKFLOWS.md)
for permission and scope boundaries.

## What works / what does not (this version)

- Working:
  - `Token::open_current_process` / `Token::open_process(pid, access)` around
    `OpenProcessToken`.
  - `Token::duplicate(ty, level)` -> owned `DuplicateTokenEx` handle.
  - `Token::enable_privilege(Privilege::…)` via `LookupPrivilegeValueW` +
    `AdjustTokenPrivileges` with correct `ERROR_NOT_ALL_ASSIGNED` handling.
  - `Token::impersonate_on_thread()` / `set_on_current_thread()` returning an
    `ImpersonationGuard` (`Drop = RevertToSelf`).
  - `Token::user_sid()` / `integrity_level()` via
    `GetTokenInformation(TokenUser | TokenIntegrityLevel)`.
- Stubbed / next milestone:
  - `OpenThreadToken` is not yet wired (only `OpenProcessToken`).
  - No `LookupAccountSidW` — SIDs render as `S-1-...` strings only.
  - No `CreateProcessAsUserW` / restricted-token helpers.
  - No integration tests against a real DC; only smoke tests on
    `GetCurrentProcess()`.

## Dependencies

- `win32-min >= 0.1.2, < 0.2` with only `security-token` enabled.
- `thiserror` 2 for the public error taxonomy.
- No async runtime, serialization framework, logging facade, or generated
  Windows bindings.

## Related icedracon crates

- [`win32-min`](https://github.com/icedracon/win32-min) — verified,
  dependency-free Win32 ABI foundation used by this crate.
- [`windows-lsa`](https://github.com/icedracon/windows-lsa) — LSA ticket
  cache access; typical pattern is `impersonate_on_thread` then read the
  target LUID's cache.
- [`windows-sspi-shim`](https://github.com/icedracon/windows-sspi-shim) —
  SSPI Negotiate ergonomics; the impersonated identity flows straight into
  `SspiClient::for_spn`.
- [`windows-scm`](https://github.com/icedracon/windows-scm) — local Service
  Control Manager wrapper, for the SYSTEM-side of the same workflows.

Together these cover identity, authentication, and local administration
workflows for Windows security research and defensive tooling.

## License

MIT © 2026 [zevs](https://github.com/icedracon)
