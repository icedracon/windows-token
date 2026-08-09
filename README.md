# windows-token

[![Crates.io](https://img.shields.io/crates/v/windows-token.svg)](https://crates.io/crates/windows-token)
[![Docs.rs](https://docs.rs/windows-token/badge.svg)](https://docs.rs/windows-token)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

RAII wrappers over the Win32 access-token surface — `OpenProcessToken`,
`DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `SetThreadToken`,
`AdjustTokenPrivileges`. The single hard invariant: dropping an
`ImpersonationGuard` calls `RevertToSelf` — always, including on unwind.
Hand-written impersonation code (Rubeus-style) forgets this on early returns;
here it is structurally impossible.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. Part of
the [icedracon](https://github.com/icedracon) Rust offensive-AD ecosystem.

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

S-tier posture — narrow feature set on `windows`, no serde / log / async
runtime.

- `windows` 0.58 with only
  `Win32_Security`, `Win32_System_Threading`,
  `Win32_Security_Authentication_Identity`, `Win32_Foundation` enabled.
- `windows-core` 0.58 for `Result` / `Error` interop.
- `thiserror` 2 for error boilerplate.

## Related icedracon crates

- [`windows-lsa`](https://github.com/icedracon/windows-lsa) — LSA ticket
  cache access; typical pattern is `impersonate_on_thread` then read the
  target LUID's cache.
- [`windows-sspi-shim`](https://github.com/icedracon/windows-sspi-shim) —
  SSPI Negotiate ergonomics; the impersonated identity flows straight into
  `SspiClient::for_spn`.
- [`windows-scm`](https://github.com/icedracon/windows-scm) — local Service
  Control Manager wrapper, for the SYSTEM-side of the same workflows.

Together these enable "run adhammer as yourself" and impersonation-based
lateral-movement tooling without dragging in Impacket or Rubeus.

## License

MIT © 2026 [zevs](https://github.com/icedracon)
