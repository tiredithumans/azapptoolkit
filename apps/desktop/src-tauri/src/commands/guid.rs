//! Shared GUID helpers for the command layer: client-side v4 generation (the
//! portal-style pattern — supplying the id makes the write self-contained and,
//! for ARM role assignments, idempotent on retry) and the strict canonical
//! validator. Single-sourced so the generator can't drift between domains and
//! the two former `is_guid` copies (`search` strict-positional vs `config`
//! split-based) can't diverge again.

/// A random v4 GUID in canonical lowercase 8-4-4-4-12 form.
pub(crate) fn new_v4_guid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1 (RFC 4122)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Strict 8-4-4-4-12 hex check (case-insensitive). No braces, no urn-prefix.
pub(crate) fn is_guid(input: &str) -> bool {
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
    fn generated_guid_is_v4_canonical() {
        let g = new_v4_guid();
        assert!(is_guid(&g), "not a GUID: {g}");
        assert_eq!(g.as_bytes()[14], b'4', "version nibble");
        assert!(
            matches!(g.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "variant nibble: {g}"
        );
        // Vanishingly unlikely to collide — pins that it's actually random.
        assert_ne!(g, new_v4_guid());
    }

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
    }
}
