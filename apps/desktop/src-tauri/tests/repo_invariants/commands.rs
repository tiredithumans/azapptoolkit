//! Rules that scan the whole command layer, plus the shared source table the
//! other concern modules read.

/// The `.alert` tone vocabulary lives in exactly ONE component.
///
/// AGENTS.md states "one primitive per UI pattern", and `Callout` is that
/// primitive for inline notices — but 30 files had hand-rolled
/// `<div class="alert alert--…">` instead, none of them importing it. Nothing
/// caught that, because a bypass compiles and even looks right; it only shows
/// up when the tone vocabulary or the box's markup needs to change in 30 places
/// at once. The primitive now carries the `class`/`role` escape hatches those
/// sites needed, so there is no remaining reason to hand-roll one.
///
/// The first version of this rule matched the literal `class="alert`, which is
/// only the *inline* spelling. Five files had already drifted past it by binding
/// the class to a variable first — `let cls = if ok { "alert alert--ok" } else
/// { "alert alert--warn" }; view! { <div class=cls> }` — which is the same
/// bypass with one more line. Matching the tone-class strings themselves catches
/// both spellings, because the vocabulary is what must not be duplicated.
#[test]
fn inline_notice_markup_lives_only_in_the_callout_primitive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/desktop")
        .join("web-rs/src");
    let mut offenders: Vec<String> = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // The primitive itself is where this markup belongs.
            if path.ends_with("ui/callout.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            // Both spellings: the inline attribute AND the tone classes bound to
            // a variable first. Bare `"alert"` is deliberately not matched — it
            // is too common a substring to key on, and every real bypass so far
            // reached for a tone modifier.
            let bypass = src.contains("class=\"alert")
                || src.contains("\"alert alert--ok\"")
                || src.contains("\"alert alert--warn\"")
                || src.contains("\"alert alert--danger\"");
            if bypass {
                offenders.push(
                    path.strip_prefix(&root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                );
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "hand-rolled inline-notice markup outside the Callout primitive: {offenders:#?}\n\
         Use `components::ui::Callout` (tone=\"ok\"|\"warn\"|\"danger\", plus optional \
         class/role) instead of writing the `.alert` classes directly — including via a \
         `let cls = if .. {{ \"alert alert--ok\" }} ..` binding, which is the same bypass."
    );
}

/// A scope remediation must be gated on a POSITIVE "this resource can be
/// confined" test, never on the negation of a legacy/unscopable test.
///
/// AGENTS.md states this for mailbox, and the SharePoint sibling had already
/// drifted: `Sites.*` on Office 365 SharePoint Online was offered the Graph
/// `Sites.Selected` fix, which strips nothing on that resource and would have
/// left the app org-wide while the audit re-scored it as confined. A negation
/// silently admits every resource nobody has classified yet; the positive form
/// admits only what has been proved confinable.
#[test]
fn scope_fixes_are_gated_on_a_positive_resource_test() {
    let scoring = include_str!("../../../../../crates/azapptoolkit-core/src/audit/scoring.rs");
    for positive in [
        "is_scopable_exchange_resource_permission",
        "is_scopable_sharepoint_resource_permission",
    ] {
        assert!(
            scoring.contains(positive),
            "audit/scoring.rs no longer references {positive} — a scope Fix must be gated on the \
             positive resource test, not on the negation of a legacy one"
        );
        assert!(
            !scoring.contains(&format!("!{positive}")),
            "audit/scoring.rs negates {positive}; the gate must stay positive"
        );
    }
    for negated in [
        "!is_unscopable_legacy_exchange_permission",
        "!crate::scoping::is_unscopable_legacy_exchange_permission",
    ] {
        assert!(
            !scoring.contains(negated),
            "audit/scoring.rs gates on {negated}. Negating the legacy test admits every resource \
             nobody has classified — gate on is_scopable_*_resource_permission instead."
        );
    }
}
