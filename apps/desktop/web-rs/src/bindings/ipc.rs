//! The single door from the bindings to `tauri-sys`'s IPC calls.
//!
//! Upstream `tauri_sys::core::invoke_result` decodes both sides via JSON
//! (`JSON.stringify` + `serde_json`), then `unwrap`s. Every command here rejects
//! with a `UiError` object, but Tauri itself rejects with a plain **string**
//! whenever the call never reached the command: arguments that do not match
//! the parameter list ("invalid args `tenantId` for command …"), an unknown
//! command, or a plugin permission the capability file does not grant. Decoded
//! as a `UiError`, that string failed the `unwrap`, and the panic hook aborted
//! the whole WASM instance — the window froze with no toast.
//!
//! This wrapper asks upstream for `serde_json::Value` on both sides, which
//! decodes any shape Tauri produces (numbers, strings, arrays, objects), then
//! decodes the real types itself: a rejection that is not a `UiError`, or a
//! reply that does not match the binding's type, becomes
//! `UiError { code: "ipc", .. }` on the action that caused it. A reply or
//! rejection `JSON.stringify` cannot render (`undefined`, a function, a
//! `Symbol`, a `BigInt`) still panics upstream, but Tauri never produces one:
//! its replies are `JSON.parse` output. `repo_invariants/ipc.rs` pins that no
//! binding reaches `tauri_sys::core`'s invoke functions except through this
//! module.

use azapptoolkit_dto::UiError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

/// The infallible call, re-exported unwrapped, for commands whose backend
/// signature has no `Result` (cache stats, cancel flags, the auth config
/// read, …): they cannot reject with a `UiError`, and the only failures left —
/// a wrong argument shape or a wrong return type — are pinned at test time by
/// `repo_invariants/ipc.rs` (arg keys, fallibility, return type) and, for the
/// Pages demo, by `demo_fixture_coverage.rs`. A fallible command bound through
/// it fails that rule, because upstream panics on its rejection.
pub(crate) use tauri_sys::core::invoke;

/// Invokes a fallible command, mapping every failure to a `UiError`.
///
/// A `UiError` rejection passes through unchanged (so `is_reauth_fatal` and
/// the session-dead handling still see the real code); any other rejection,
/// and a reply that does not decode as `T`, becomes code `ipc`.
pub(crate) async fn invoke_result<T: DeserializeOwned>(
    cmd: &str,
    args: impl Serialize,
) -> Result<T, UiError> {
    match tauri_sys::core::invoke_result::<Value, Value>(cmd, args).await {
        Ok(value) => decode_ok(cmd, value),
        Err(value) => Err(ui_error_from_rejection(cmd, value)),
    }
}

/// Decodes a command's reply as the binding's type, or names the mismatch.
fn decode_ok<T: DeserializeOwned>(cmd: &str, value: Value) -> Result<T, UiError> {
    serde_json::from_value(value).map_err(|e| {
        UiError::new(
            "ipc",
            format!("`{cmd}` returned a reply this window could not read: {e}"),
            false,
        )
    })
}

/// A rejection as a `UiError`: the command's own error when it is one, else a
/// non-retryable `ipc` error carrying whatever Tauri said.
fn ui_error_from_rejection(cmd: &str, value: Value) -> UiError {
    if let Ok(e) = UiError::deserialize(&value) {
        return e;
    }
    let detail = match value {
        Value::String(s) => s,
        other => other.to_string(),
    };
    UiError::new("ipc", format!("`{cmd}` failed: {detail}"), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_ui_error_rejection_passes_through_field_for_field() {
        let e = ui_error_from_rejection(
            "list_applications",
            json!({ "code": "throttled", "message": "slow down", "retryable": true }),
        );
        assert_eq!(e.code, "throttled");
        assert_eq!(e.message, "slow down");
        assert!(e.retryable);

        let dead = ui_error_from_rejection(
            "list_applications",
            json!({ "code": "refresh_missing", "message": "sign in", "retryable": false }),
        );
        assert_eq!(dead.code, "refresh_missing");
        assert!(
            dead.is_reauth_fatal(),
            "a dead session must still reach the re-auth path"
        );
    }

    #[test]
    fn a_tauri_string_rejection_becomes_an_ipc_error_not_a_panic() {
        let e = ui_error_from_rejection(
            "get_application_detail",
            Value::String(
                "invalid args `tenantId` for command `get_application_detail`: missing field"
                    .into(),
            ),
        );
        assert_eq!(e.code, "ipc");
        assert!(
            e.message.contains("invalid args `tenantId`"),
            "{}",
            e.message
        );
        assert!(
            e.message.contains("get_application_detail"),
            "{}",
            e.message
        );
        assert!(!e.retryable);
        assert!(!e.is_reauth_fatal());
    }

    #[test]
    fn any_other_rejection_shape_becomes_an_ipc_error() {
        for value in [Value::Null, json!({ "foo": 1 }), json!([1, 2]), json!(7)] {
            let e = ui_error_from_rejection("x", value.clone());
            assert_eq!(e.code, "ipc", "{value}");
            assert!(!e.retryable);
        }
    }

    #[test]
    fn replies_decode_as_the_binding_type_or_name_the_mismatch() {
        assert!(decode_ok::<()>("cancel_audit", Value::Null).is_ok());
        assert_eq!(decode_ok::<Option<u32>>("x", Value::Null).unwrap(), None);
        assert_eq!(
            decode_ok::<Vec<u32>>("x", json!([1, 2])).unwrap(),
            vec![1, 2]
        );

        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Status {
            sp_index_truncated: bool,
        }
        let e = decode_ok::<Status>(
            "get_directory_index_status",
            json!({ "spIndexTruncated": false }),
        )
        .unwrap_err();
        assert_eq!(e.code, "ipc");
        assert!(
            e.message.contains("get_directory_index_status"),
            "{}",
            e.message
        );
    }
}
