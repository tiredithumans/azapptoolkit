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
}
