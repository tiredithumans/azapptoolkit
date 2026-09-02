---
paths:
  - "crates/azapptoolkit-auth/**"
  - "apps/desktop/src-tauri/src/state.rs"
  - "apps/desktop/src-tauri/src/token_adapter.rs"
  - "apps/desktop/src-tauri/src/cert.rs"
  - "apps/desktop/src-tauri/src/commands/{auth,consent,readiness,graph_err}.rs"
  - "apps/desktop/src-tauri/src/commands/sso/**"
  - "crates/azapptoolkit-core/src/{token,reauth,capabilities,federation,thumbprint,azure_roles}.rs"
---

# Auth, consent & trusts — the detail behind the AGENTS.md one-liners

Deep-dive: `docs/architecture/auth-and-consent.md`. Pinned by `repo_invariants/trust.rs`.

- **Auth: lazy, shared token refresh.** Refreshes ~60s before expiry behind a shared mutex; refresh tokens in the OS keyring, chunked (Windows Credential Manager caps at 2560 UTF-16 bytes — don't collapse the chunking). Write scopes consented **incrementally**. Access tokens live in memory only, zeroized on drop, `Debug` prints `<redacted>`.
- **Extra-scope tokens (on-demand).** Admin-consent/premium scopes ride a `ScopedTokenAdapter`, never the sign-in scope set. Every call must **degrade gracefully** (an `unavailable`/`consent_required` state, never a hard error).
- **Silent grants can't *obtain* consent.** AADSTS65001/65004 → `AuthError::ConsentRequired` (≠ `InvalidGrant`). A command needing a "Grant consent" button must **pre-acquire** via `AppState::ensure_*` so `consent_required` survives `BearerProvider`. A missing consent must not purge the refresh token.
- **Force re-auth in place when the session is dead — don't sign the user out.** A dead refresh token (`InvalidGrant`/`RefreshTokenMissing` → **`refresh_missing`**; `NotSignedIn` → **`not_signed_in`**) can't be re-minted silently; `reauthenticate` runs ONE interactive round trip and restores the session **without** dropping data caches.
- **Role/scope catalog.** Three auth planes (Entra, Azure RBAC, Exchange) share one capabilities catalog. Adding a privileged feature → add a catalog entry instead of hardcoding role strings; splice its remediation into a 403 via `graph_err::forbidden_remediation`. Access Readiness enumerates only **direct** Azure role assignments (conservative supersets, never a false "Missing").
- **SAML signing-cert rollover: phase derives from live SP state, not stored.** Entra auto-promotes a staged cert when the active expires. A cert **thumbprint is SHA-1**; `core::thumbprint::canonical` is its ONE converter — 40 hex chars are *also* valid base64, so never hand-roll the decode.
- **Auth trusts are validated wherever minted.** Federated credentials go through `core::federation` on **every** path (Graph accepts a bad issuer silently); SAML cert lifetimes are bounded.
- **Errors are sanitized before they're shown or logged.** AAD errors are redacted to the AADSTS code; Exchange bodies are control-char-stripped and length-capped — log the `ui_code`/request id, never a raw body.
