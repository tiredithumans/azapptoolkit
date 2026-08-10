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

/// The resource-blind mailbox gates stay deleted.
///
/// `exchange_role_for_permission`, `is_scopable_exchange_permission` and
/// `scope_kind` answered from a permission's VALUE alone. Both mailbox
/// resources expose `Mail.*` / `Calendars.*` / `Contacts.*`, and only Microsoft
/// Graph's can be confined — so those forms reported a retired Outlook REST
/// grant as scopable, and every gate built on one hid org-wide mailbox access
/// behind a healthy badge.
///
/// They were deprecated first, which did not work: the crate root re-exported
/// them under a blanket `#[allow(deprecated)]`, so a caller reaching them
/// through `azapptoolkit_exchange::` got no compiler signal at all, and three
/// call sites carried their own `#[allow]` besides. AGENTS.md meanwhile said
/// the value-only forms were pinned as forbidden. Now they do not exist, and
/// this is what makes that true — reintroducing one by name fails here.
#[test]
fn the_resource_blind_mailbox_gates_are_not_reintroduced() {
    const GONE: [&str; 3] = [
        "exchange_role_for_permission",
        "is_scopable_exchange_permission",
        "fn scope_kind(",
    ];
    // Every Rust source in the workspace + the excluded frontend tree.
    // apps/desktop/src-tauri → apps/desktop → apps → repo root.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("apps/desktop/src-tauri → repo root")
        .to_path_buf();

    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut stack = vec![root.join("crates"), root.join("apps")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `target/` holds built copies of the very sources being checked.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // This file names them in `GONE`; it would flag itself.
            if path.ends_with("repo_invariants/commands.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for (line_no, line) in src.lines().enumerate() {
                let trimmed = line.trim_start();
                // This rule names them in prose, and so may a comment
                // explaining why they went.
                if trimmed.starts_with("//") {
                    continue;
                }
                // The resource-aware forms contain the shorter names.
                if line.contains("_resource_permission") || line.contains("scope_kind_for") {
                    continue;
                }
                if let Some(name) = GONE.iter().find(|n| line.contains(*n)) {
                    offenders.push(format!(
                        "{}:{} — {name}",
                        path.strip_prefix(&root).unwrap_or(&path).display(),
                        line_no + 1
                    ));
                }
            }
        }
    }

    assert!(
        scanned > 100,
        "scanned only {scanned} Rust files — the walk is broken, and a rule that scans nothing \
         passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "a resource-blind mailbox gate is back:\n  {}\n\
         Both mailbox resources expose the same permission names and only Microsoft Graph's can \
         be confined, so a value-only answer reports an unscopable legacy grant as scopable. Take \
         the resource: is_scopable_exchange_resource_permission / \
         exchange_role_for_resource_permission / scope_kind_for.",
        offenders.join("\n  ")
    );
}
