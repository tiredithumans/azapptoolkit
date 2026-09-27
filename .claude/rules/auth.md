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

- **Auth: lazy, shared token refresh.** Refreshes ~60s before expiry behind a per-`(tenant, scope set)` lock; the access-token cache also keys on CAE-ness (Graph flows mint CAE — `is_graph_scope_set`); the `/token` POST rides `core::http_retry` (refresh grants idempotent, the auth code only on 429); refresh tokens in the OS keyring, chunked (Windows Credential Manager caps at 2560 UTF-16 bytes — don't collapse the chunking). Write scopes consented **incrementally**. Access tokens live in memory only, zeroized on drop, `Debug` prints `<redacted>`.
- **Extra-scope tokens (on-demand).** Admin-consent/premium scopes ride a `ScopedTokenAdapter`, never the sign-in scope set. Every call must **degrade gracefully** (an `unavailable`/`consent_required` state, never a hard error).
- **Silent grants can't *obtain* consent.** AADSTS65001/65004 → `AuthError::ConsentRequired` (≠ `InvalidGrant`). `consent_required` crosses `BearerProvider` (`reauth::passthrough_code`), so the shared toast fallback fires anywhere; a command that has side effects before its scoped call, or needs a specific feature's "Grant consent" button, still **pre-acquires** via `AppState::ensure_*` so consent surfaces before any work. A missing consent must not purge the refresh token. `interaction_required`/`login_required` (CA step-up, incl. `invalid_grant` + AADSTS50074/50076/50079/50158) → `AuthError::InteractionRequired`, a non-fatal pass-through (never in `REAUTH_FATAL_CODES`), never purges; recovery `request_scope_step_up` → `step_up_for_scopes` (`prompt=login`).
- **Force re-auth in place when the session is dead — don't sign the user out.** A dead refresh token (`InvalidGrant`/`RefreshTokenMissing` → **`refresh_missing`**; `NotSignedIn` → **`not_signed_in`**) can't be re-minted silently; `reauthenticate` runs ONE interactive round trip and restores the session **without** dropping data caches.
- **Role/scope catalog.** Three auth planes (Entra, Azure RBAC, Exchange) share one capabilities catalog. Adding a privileged feature → add a catalog entry instead of hardcoding role strings; splice its remediation into a 403 via `graph_err::forbidden_remediation`. Access Readiness enumerates only **direct** Azure role assignments (conservative supersets, never a false "Missing").
- **SAML signing-cert rollover: phase derives from live SP state, not stored.** Entra auto-promotes a staged cert when the active expires. A cert **thumbprint is SHA-1**; `core::thumbprint::canonical` is its ONE converter — 40 hex chars are *also* valid base64, so never hand-roll the decode.
- **Auth trusts are validated wherever minted.** Federated credentials go through `core::federation` on **every** path (Graph accepts a bad issuer silently); SAML cert lifetimes are bounded.
- **Errors are sanitized before they're shown or logged.** AAD errors are redacted to the AADSTS code; every client's error bodies (Graph, ARM, Key Vault, Exchange) are control-char-stripped and length-capped by `core::http_error::sanitize_error_body` — log the `ui_code`/status/request id, never a raw body.
