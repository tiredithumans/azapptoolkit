// Pure parsing helpers for `build.rs`, kept in their own file so they can be
// tested.
//
// A build script is not compiled into any test target, so anything defined
// inside `build.rs` is unreachable from `cargo test` — which is how a `.env`
// parser that decides the shipped client/tenant id ended up with no coverage
// at all. This file is `include!`d by `build.rs` and mounted again, under
// `#[cfg(test)]`, by `src/lib.rs`, so the same source is both used and tested.

/// One `KEY=value` line from a `.env`, or `None` for a blank/comment line.
fn parse_env_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, raw) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    let value = strip_quotes(raw.trim());
    Some((key.to_string(), value.to_string()))
}

/// The `cargo:rustc-env` name a `.env` key is baked under, or `None` for a
/// key the build does not bake. `state.rs` reads each back with `option_env!`;
/// a runtime env var of the `.env` key's name still overrides it.
fn baked_env_name(key: &str) -> Option<&'static str> {
    match key {
        "AZAPPTOOLKIT_CLIENT_ID" => Some("AZAPPTOOLKIT_BUILD_CLIENT_ID"),
        "AZAPPTOOLKIT_TENANT_ID" => Some("AZAPPTOOLKIT_BUILD_TENANT_ID"),
        // A cloud name (`usgov`, `usgovdod`, `china`), not a secret; validated
        // at runtime by `CloudEnvironment::parse`, the one vocabulary.
        "AZAPPTOOLKIT_CLOUD" => Some("AZAPPTOOLKIT_BUILD_CLOUD"),
        _ => None,
    }
}

/// A `cargo:warning` for a baked client/tenant id that cannot work, so a
/// mistyped team-build `.env` is caught at build time instead of at sign-in.
/// `None` for a usable value and for every other key (`AZAPPTOOLKIT_CLOUD` is
/// validated at runtime). Never echoes the value.
fn bake_warning(key: &str, value: &str) -> Option<String> {
    if !matches!(key, "AZAPPTOOLKIT_CLIENT_ID" | "AZAPPTOOLKIT_TENANT_ID") {
        return None;
    }
    if value.is_empty() {
        return Some(format!("{key} is empty in .env and was not baked"));
    }
    if !is_guid_shape(value) {
        return Some(format!("{key} in .env is not a GUID; sign-in will fail"));
    }
    None
}

/// Strict 8-4-4-4-12 hex check (case-insensitive). A local copy because a
/// build script cannot import `commands::guid::is_guid`; a conformance test
/// keeps the two in step.
fn is_guid_shape(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Removes one matching pair of surrounding single or double quotes.
fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_tenant_and_cloud_keys_are_baked_and_nothing_else() {
        assert_eq!(
            baked_env_name("AZAPPTOOLKIT_CLIENT_ID"),
            Some("AZAPPTOOLKIT_BUILD_CLIENT_ID")
        );
        assert_eq!(
            baked_env_name("AZAPPTOOLKIT_TENANT_ID"),
            Some("AZAPPTOOLKIT_BUILD_TENANT_ID")
        );
        assert_eq!(
            baked_env_name("AZAPPTOOLKIT_CLOUD"),
            Some("AZAPPTOOLKIT_BUILD_CLOUD")
        );
        assert_eq!(baked_env_name("TAURI_SIGNING_PRIVATE_KEY"), None);
        assert_eq!(baked_env_name("AZAPPTOOLKIT_BUILD_CLOUD"), None);
    }

    #[test]
    fn blank_and_comment_lines_are_skipped() {
        assert_eq!(parse_env_line(""), None);
        assert_eq!(parse_env_line("   "), None);
        assert_eq!(parse_env_line("# AZAPPTOOLKIT_CLIENT_ID=abc"), None);
        assert_eq!(parse_env_line("   # indented comment"), None);
    }

    #[test]
    fn a_line_without_an_equals_or_with_an_empty_key_is_skipped() {
        assert_eq!(parse_env_line("AZAPPTOOLKIT_CLIENT_ID"), None);
        assert_eq!(parse_env_line("=orphan-value"), None);
        assert_eq!(parse_env_line("   =orphan-value"), None);
    }

    #[test]
    fn key_and_value_are_trimmed() {
        assert_eq!(
            parse_env_line("  AZAPPTOOLKIT_CLIENT_ID  =  abc-123  "),
            Some(("AZAPPTOOLKIT_CLIENT_ID".into(), "abc-123".into()))
        );
    }

    #[test]
    fn only_a_matching_pair_of_surrounding_quotes_is_stripped() {
        // A GUID with a stray quote is a misconfiguration, not something to
        // silently repair — half-stripping it would bake a value that differs
        // from what the operator wrote.
        assert_eq!(strip_quotes("\"abc\""), "abc");
        assert_eq!(strip_quotes("'abc'"), "abc");
        assert_eq!(strip_quotes("\"abc'"), "\"abc'");
        assert_eq!(strip_quotes("\"abc"), "\"abc");
        assert_eq!(strip_quotes("abc\""), "abc\"");
        assert_eq!(strip_quotes("abc"), "abc");
        // Only ONE pair: an inner quote is part of the value.
        assert_eq!(strip_quotes("\"\"abc\"\""), "\"abc\"");
        // Too short to be a pair.
        assert_eq!(strip_quotes("\""), "\"");
        assert_eq!(strip_quotes(""), "");
    }

    #[test]
    fn a_value_may_contain_an_equals_sign() {
        // `split_once` keeps everything after the FIRST `=`, which matters for
        // any value that is itself a key/value pair.
        assert_eq!(
            parse_env_line("KEY=a=b=c"),
            Some(("KEY".into(), "a=b=c".into()))
        );
    }

    #[test]
    fn an_empty_value_parses_and_is_left_for_the_caller_to_reject() {
        // `bake_client_config` skips empty values; the parser's job is only to
        // report what the line said.
        assert_eq!(parse_env_line("KEY="), Some(("KEY".into(), String::new())));
        assert_eq!(
            parse_env_line("KEY=\"\""),
            Some(("KEY".into(), String::new()))
        );
    }

    #[test]
    fn an_empty_or_malformed_baked_id_warns_without_echoing_it() {
        let guid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        for key in ["AZAPPTOOLKIT_CLIENT_ID", "AZAPPTOOLKIT_TENANT_ID"] {
            assert_eq!(bake_warning(key, guid), None, "{key}");
            let empty = bake_warning(key, "").expect("empty warns");
            assert!(empty.contains(key) && empty.contains("empty"), "{empty}");
            let bad = bake_warning(key, "not-a-guid-value").expect("non-GUID warns");
            assert!(bad.contains(key) && bad.contains("not a GUID"), "{bad}");
            assert!(
                !bad.contains("not-a-guid-value"),
                "the value is never echoed"
            );
        }
        // Only the two ids are checked; the cloud name is validated at runtime.
        assert_eq!(bake_warning("AZAPPTOOLKIT_CLOUD", "usgov"), None);
        assert_eq!(bake_warning("OTHER", ""), None);
    }

    /// The build script's local GUID check must agree with the command layer's
    /// `is_guid`, the one the config screen validates with.
    #[test]
    fn the_local_guid_check_matches_the_command_layer() {
        for s in [
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
            "{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f00",
            "0f1e2d3c4b5a-6978-8796-a5b4c3d2e1f0-",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1fg",
            "contoso.onmicrosoft.com",
            "",
        ] {
            assert_eq!(
                is_guid_shape(s),
                crate::commands::guid::is_guid(s),
                "disagree on {s:?}"
            );
        }
    }
}
