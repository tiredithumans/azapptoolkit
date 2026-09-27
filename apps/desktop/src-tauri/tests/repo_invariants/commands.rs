//! Rules that scan the command layer and the frontend as a whole rather than
//! one command at a time; the shared source walk lives in [`super::sources`].

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

/// A missing consent is recognised by ONE predicate, `UiError::is_consent_required`.
///
/// Twenty-odd surfaces compared `e.code == "consent_required"` by hand, so the
/// literal was restated at every consumer — the drift `core::reauth` exists to
/// prevent for the re-auth-fatal codes. The helper reads the one literal in
/// `core::reauth::CONSENT_REQUIRED`; a hand-rolled compare in the frontend or
/// the command layer is the bypass. (A `match` arm on the code, as the sign-in
/// hint table uses, is not a compare and is not matched.)
#[test]
fn consent_required_is_recognised_only_through_the_ui_error_helper() {
    let desktop = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/desktop");
    let roots = [
        desktop.join("web-rs/src"),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/commands"),
    ];
    let mut scanned = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for root in roots {
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
                let Ok(src) = std::fs::read_to_string(&path) else {
                    continue;
                };
                scanned += 1;
                let squashed: String = src.split_whitespace().collect();
                if squashed.contains("==\"consent_required\"")
                    || squashed.contains("!=\"consent_required\"")
                {
                    offenders.push(
                        path.strip_prefix(desktop)
                            .unwrap_or(&path)
                            .display()
                            .to_string(),
                    );
                }
            }
        }
    }
    assert!(
        scanned > 50,
        "the scan found almost no sources ({scanned}) — wrong root?"
    );
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "hand-rolled `consent_required` compares: {offenders:#?}\n\
         Use `UiError::is_consent_required()` (one literal, in core::reauth::CONSENT_REQUIRED)."
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

/// The `*_not_found` offenders in one (whitespace-squashed) source: a
/// `validation`/`new` code that spells the suffix by hand, or a
/// `UiError::not_found` resource that already carries it (which the factory
/// then doubles into `x_not_found_not_found`). Returns `(offender, seen)`, where
/// `seen` counts the `UiError::not_found(` sites with a literal resource.
fn not_found_offenders(src: &str) -> (Vec<String>, usize) {
    fn literals<'a>(squashed: &'a str, call: &str) -> Vec<&'a str> {
        let needle = format!("{call}(\"");
        squashed
            .match_indices(&needle)
            .filter_map(|(at, _)| {
                let rest = &squashed[at + needle.len()..];
                rest.find('"').map(|end| &rest[..end])
            })
            .collect()
    }
    let squashed: String = src.split_whitespace().collect();
    let mut offenders = Vec::new();
    for call in ["UiError::validation", "UiError::new"] {
        for code in literals(&squashed, call) {
            if code == "not_found" || code.ends_with("_not_found") {
                offenders.push(format!("{call}(\"{code}\""));
            }
        }
    }
    let factory = literals(&squashed, "UiError::not_found");
    for resource in &factory {
        if resource.ends_with("not_found") {
            offenders.push(format!("UiError::not_found(\"{resource}\""));
        }
    }
    (offenders, factory.len())
}

/// Every `*_not_found` wire code comes from `UiError::not_found(resource)`,
/// which formats `{resource}_not_found`.
///
/// The same condition — a service principal gone between list and detail —
/// reached the frontend as a bare `not_found` from the SSO tab and as
/// `service_principal_not_found` from the enterprise-app detail, and three
/// sites passed an already-suffixed code into the factory, putting
/// `*_not_found_not_found` on the wire. A future `ends_with("_not_found")`
/// handler would silently miss the first and match the others by accident.
/// (The bare `not_found` transport code from `http_error_enum!` lives outside
/// the command layer and is not scanned.)
#[test]
fn not_found_codes_come_only_from_the_factory() {
    let mut offenders: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for (name, src) in super::sources::command_modules() {
        let (found, sites) = not_found_offenders(&src);
        seen += sites;
        offenders.extend(found.into_iter().map(|o| format!("{name}: {o}")));
    }
    assert!(
        seen >= 10,
        "saw only {seen} `UiError::not_found(\"…\"` sites — the scan is broken, and a rule that \
         scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "hand-spelled or doubled not-found codes:\n  {}\n\
         Use `UiError::not_found(\"<resource>\", …)`, which formats `<resource>_not_found` — \
         pass the bare resource, never a code that already ends in `not_found`.",
        offenders.join("\n  ")
    );
}

/// The not-found scanner reads the shapes rustfmt produces, so the rule above
/// cannot pass because a call was wrapped across lines.
#[test]
fn the_not_found_scanner_reads_the_shapes_the_tree_uses() {
    let wrapped = "Err(UiError::not_found(\n    \"group_not_found\",\n    \"gone\",\n))";
    let (offenders, seen) = not_found_offenders(wrapped);
    assert_eq!(seen, 1);
    assert_eq!(
        offenders,
        vec!["UiError::not_found(\"group_not_found\"".to_string()]
    );

    let hand = "UiError::validation(\n        \"not_found\",\n        \"x\")\n\
                crate::dto::UiError::new(\"cert_not_found\", \"y\", false)";
    let (offenders, _) = not_found_offenders(hand);
    assert_eq!(offenders.len(), 2, "{offenders:?}");

    let clean = "UiError::not_found(\"service_principal\", \"gone\")\n\
                 UiError::validation(\"cert_is_active\", \"z\")\n\
                 UiError::not_found(resource, \"dynamic\")";
    let (offenders, seen) = not_found_offenders(clean);
    assert!(offenders.is_empty(), "{offenders:?}");
    assert_eq!(seen, 1, "a non-literal resource is not counted");
}
