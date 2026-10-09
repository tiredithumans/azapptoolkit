//! Shape checks for identifiers spliced into a Graph request path.
//!
//! The SharePoint permission endpoints take a site id, a list id, an item id
//! and a permission id straight from an earlier Graph response — or, for a
//! remove, from the webview — and the composed URL keeps the Graph host, but a
//! `/`, `\` or `..` segment walks the call to a different resource and a `?`,
//! `#` or `:` rewrites what the rest of the path means, all under the
//! `Sites.FullControl.All` bearer. A DELETE that walks three segments up to `/drives/{d}/items/{i}`
//! deletes a file this crate otherwise has no call for. Mirrors
//! `azapptoolkit-arm`'s and `azapptoolkit-keyvault`'s `validate` modules;
//! refusals never echo the value.

use crate::error::{GraphError, Result};

/// Refuses a `value` that cannot stand as exactly one path segment: empty, a
/// `.` / `..` segment, or holding a `/`, `\`, `?`, `#`, `%`, `:`, whitespace
/// or a control character.
///
/// `%` is refused outright rather than decoded: Graph decodes `%2f` and
/// `%2e%2e` server-side, and no id this crate addresses is percent-encoded
/// (site ids are `host,guid,guid`, list ids GUIDs, item ids digits, permission
/// ids base64 — which never yields `/` or `+` for the ASCII identities
/// SharePoint encodes).
pub(crate) fn require_path_segment(what: &str, value: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', '?', '#', '%', ':'])
        && !value.chars().any(|c| c.is_control() || c.is_whitespace());
    if ok {
        Ok(())
    } else {
        Err(GraphError::Protocol(format!(
            "refusing a {what} that is not a single path segment"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_path_segment_accepts_the_ids_graph_hands_out() {
        for good in [
            "contoso.sharepoint.com,3fa85f64-5717-4562-b3fc-2c963f66afa6,9c2b1c6e-0f0e-4d7b-9f3a-1b2c3d4e5f60",
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "17",
            "aTowaS50fG1zLnNwLmV4dHwzZmE4NWY2NC01NzE3LTQ1NjItYjNmYy0yYzk2M2Y2NmFmYTZAY29udG9zbw==",
            "perm-1",
            "01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K",
        ] {
            assert!(require_path_segment("id", good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn require_path_segment_refuses_anything_that_changes_the_path() {
        for bad in [
            "",
            ".",
            "..",
            "../../../drives/d/items/i",
            "perm-1/..",
            "perm-1\\..\\..",
            "perm-1?x=1",
            "perm-1#x",
            "%2e%2e",
            "perm%2f1",
            "site:/drive/root:/x",
            "perm 1",
            "perm\n1",
        ] {
            let err = require_path_segment("permission id", bad).unwrap_err();
            assert!(
                matches!(&err, GraphError::Protocol(m) if m == "refusing a permission id that is not a single path segment"),
                "{bad:?}: {err:?}"
            );
        }
    }
}
