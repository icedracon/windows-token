# windows-token

**STATUS: pre-alpha (0.1.0-dev).** API surface stable-ish; implementations partial; not exercised against a live DC.

RAII wrappers over the Win32 access-token surface. The one hard invariant: dropping an `ImpersonationGuard` calls `RevertToSelf` — always, including on unwind. That is the whole reason the crate exists; hand-written impersonation code (Rubeus-style) forgets this on early returns.

## Purpose

- `Token::open_current_process` / `open_process(pid, access)` — RAII around `OpenProcessToken`.
- `Token::duplicate(ty, level)` — `DuplicateTokenEx` returning an owned handle.
- `Token::enable_privilege(Privilege::…)` — `LookupPrivilegeValueW` + `AdjustTokenPrivileges`, correctly reading `ERROR_NOT_ALL_ASSIGNED` from `GetLastError` on nominal success.
- `Token::impersonate_on_thread()` / `set_on_current_thread()` — returns `ImpersonationGuard`, `Drop = RevertToSelf`.
- `Token::user_sid()` / `integrity_level()` — `GetTokenInformation(TokenUser | TokenIntegrityLevel)`.

## Minimal usage

```rust
use windows_token::{Token, Privilege};

let tok = Token::open_current_process()?;
let _prev = tok.enable_privilege(Privilege::SeChangeNotify)?;

// impersonation with guaranteed revert:
{
    let _g = tok.impersonate_on_thread()?;
    // …do work under the impersonation…
} // <- RevertToSelf on drop, including on panic
# Ok::<(), windows_token::Error>(())
```

## What is not done

- `OpenThreadToken` is not yet wired (only `OpenProcessToken`).
- No `LookupAccountSidW` — SIDs render as `S-1-…` strings only, no name resolution.
- No `CreateProcessAsUserW` / restricted-token helpers.
- No integration tests against a real DC; only smoke tests on `GetCurrentProcess()`.

## Deps (S-tier posture)

- `windows` 0.58 — narrowly featured (`Win32_Security`, `Win32_System_Threading`, `Win32_Security_Authentication_Identity`, `Win32_Foundation`).
- `windows-core` 0.58 — for `Result` / `Error` interop.
- `thiserror` 2 — error boilerplate only.

No serde, no log, no async runtime.

## License

MIT. See [`LICENSE`](LICENSE).
