//! The one strict GUID shape check, shared by the desktop command layer (form
//! and search input) and the ARM client (ids echoed back by ARM before they are
//! spliced into a request path). Pure and dependency-free, so ungated.

/// Strict 8-4-4-4-12 hex check (case-insensitive). No braces, no urn-prefix.
pub fn is_guid(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let want_dash = matches!(i, 8 | 13 | 18 | 23);
        if want_dash {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_guid_accepts_canonical_and_rejects_junk() {
        assert!(is_guid("00000000-0000-0000-0000-000000000000"));
        assert!(is_guid("3fa85f64-5717-4562-b3fc-2c963f66afa6"));
        assert!(is_guid("3FA85F64-5717-4562-B3FC-2C963F66AFA6")); // hex is case-insensitive
        assert!(!is_guid(""));
        assert!(!is_guid("not-a-guid"));
        assert!(!is_guid("{00000003-0000-0000-c000-000000000000}"));
        assert!(!is_guid("urn:uuid:00000003-0000-0000-c000-000000000000"));
        assert!(!is_guid("00000003-0000-0000-c000-00000000000")); // too short
        assert!(!is_guid("3fa85f64-5717-4562-b3fc-2c963f66afa6-extra"));
        assert!(!is_guid("zzzzzzzz-5717-4562-b3fc-2c963f66afa6")); // non-hex
        // Path/query characters of the same length never pass.
        assert!(!is_guid("3fa85f64-5717-4562-b3fc-2c963f66af?a"));
        assert!(!is_guid("3fa85f64/5717-4562-b3fc-2c963f66afa6"));
    }
}
