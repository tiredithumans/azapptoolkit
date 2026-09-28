//! Cancellation identity: every long-running command claims exactly one
//! `CancelToken`.
//!
//! Replaces the old "call `reset()` at the top" rule, which pinned a shape that
//! could not be made correct — see the test's own doc comment.

/// Every long-running command claims a [`CancelToken`], and claims it once.
///
/// Replaces the old "call `reset()` at the top" rule, which pinned a shape that
/// could not be made correct: `reset()` was a destructive write on a shared
/// `AtomicBool`, so a second command starting cleared a cancellation the first
/// had not yet polled and that run carried on writing. A token's generation is
/// the run's identity, so starting a run says nothing about any other.
///
/// The *once* half is the same bug one level down. `commands/backup.rs` claimed
/// again for its enterprise-app phase, which took a fresh generation and dropped
/// a Cancel pressed during the app-registration phase at the phase boundary.
///
/// Two things changed after run 7 of the wavelet analysis:
///
/// 1. **The module list is gone.** It named seven files, so the rule could only
///    see the commands someone had remembered to add — and
///    `migrate_application_access_policies`, a whole-tenant Exchange + Entra
///    write loop, was not among them. The subject is now every
///    `#[tauri::command]` in the tree.
/// 2. **Bodies are brace-matched, not split on the attribute.** Splitting on
///    `"#[tauri::command]"` ran each "body" to the *next* attribute, so a
///    command absorbed every private helper that followed it. That made the
///    rule quietly lenient (a helper 200 lines below could satisfy the check for
///    a command that did nothing) and quietly wrong (two commands looked like
///    tenant-wide writers purely because a helper below them mentioned a
///    tenant-wide read).
///
/// Claim *placement* is the sibling rule
/// [`every_long_running_command_claims_before_its_first_await`].
#[test]
fn every_long_running_command_claims_exactly_one_cancel_token() {
    let mut missing: Vec<String> = Vec::new();
    let mut multiple: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for cmd in super::sources::commands() {
        let drives_long_run = cmd.body.contains("dispatch_capped(")
            || cmd.body.contains("run_bulk_seq(")
            // Sequential flows — no dispatcher, same hazard.
            || cmd.body.contains("report.cancelled = true");
        if !drives_long_run {
            continue;
        }
        checked += 1;
        match cmd.body.matches(".claim()").count() {
            0 => missing.push(format!("{}::{}", cmd.module, cmd.name)),
            1 => {}
            n => multiple.push(format!("{}::{} claims {n} times", cmd.module, cmd.name)),
        }
    }

    assert!(
        checked >= 5,
        "only {checked} long-running command(s) found — the source walk or the shape detector is \
         broken, and a rule that scans nothing passes vacuously"
    );
    assert!(
        missing.is_empty(),
        "long-running command(s) that never claim a CancelToken: {missing:#?}\n\
         `CancelFlag` has no pollable state without one — such a run cannot be cancelled at all. \
         Call `let cancel = state.<flag>_cancel.claim();` before the first write."
    );
    assert!(
        multiple.is_empty(),
        "long-running command(s) that claim more than once: {multiple:#?}\n\
         Each `claim()` takes a NEW generation, so a cancel issued against an earlier phase \
         stops applying at the phase boundary. Claim once and pass the token down."
    );
}

/// Every long-running command claims its token **before its first `await`**.
///
/// `claim()` takes a fresh generation and `cancel()` stamps whatever generation
/// is current when it runs, so a token claimed after a long phase carries a
/// higher generation than a cancel issued during that phase —
/// `is_cancelled()` compares `cancelled >= generation`, so the cancel is
/// silently discarded.
///
/// Pinned positionally because that is exactly what goes wrong: the claim is
/// present, correct in isolation, and in the wrong place. The sibling rule above
/// pins that a claim EXISTS, which is what let both known instances through CI.
///
/// This rule was `run_audit`-shaped for one run — it looked for that command's
/// `futures::join!` prefetch by name, so it could only ever catch the one bug it
/// was written against. `migrate_application_access_policies` claimed after
/// three tenant-wide reads (an Exchange client handshake, the mailbox resource
/// roles, and a walk of every Application Access Policy in the tenant) and the
/// rule had nothing to say about it. The subject is now every long-running
/// command, and the boundary is the first `.await` rather than one command's
/// particular prefetch: any await can be the long one, so the only position
/// that is right for all of them is "before all of them".
#[test]
fn every_long_running_command_claims_before_its_first_await() {
    let mut late: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for cmd in super::sources::commands() {
        let Some(claim) = cmd.body.find(".claim()") else {
            // Absent entirely is the sibling rule's finding, not this one's.
            continue;
        };
        checked += 1;
        let Some(first_await) = cmd.body.find(".await") else {
            continue;
        };
        if claim > first_await {
            let preceding = cmd.body[..first_await]
                .rsplit(['\n', ';'])
                .find(|s| !s.trim().is_empty())
                .unwrap_or("")
                .trim()
                .to_string();
            late.push(format!(
                "{}::{} claims after `{preceding}.await`",
                cmd.module, cmd.name
            ));
        }
    }

    assert!(
        checked >= 5,
        "only {checked} command(s) claim a CancelToken at all — the source walk is broken, and a \
         rule that scans nothing passes vacuously"
    );
    assert!(
        late.is_empty(),
        "command(s) that claim a CancelToken AFTER their first await: {late:#?}\n\
         A cancel pressed during that await stamps a LOWER generation than the token, so \
         `is_cancelled()` (`cancelled >= generation`) never sees it and the run carries on. Move \
         `let cancel = state.<flag>_cancel.claim();` above the first `.await` in the body."
    );
}

/// The identifiers immediately before each `call` (`".claim()"` /
/// `".cancel()"`) in `body`: `state.bulk_cancel.claim()` yields `bulk_cancel`.
fn flags_before(body: &str, call: &str) -> Vec<String> {
    body.match_indices(call)
        .map(|(at, _)| {
            let ident: String = body[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            ident.chars().rev().collect()
        })
        .collect()
}

/// One `CancelFlag` per run kind, and exactly one `cancel_*` command per flag.
///
/// `CancelFlag::cancel` stamps the flag's CURRENT generation, so it stops every
/// run on that flag, not just the newest one. The views that start these runs
/// stay mounted (keep-alive views, display-toggled panels), so runs of different
/// kinds overlap — and a flag shared between kinds let one kind's Cancel stop
/// the other: cancelling a read-only audit halted a bulk delete, a mailbox
/// probe's Cancel threw away a multi-minute site sweep, a backup's Cancel
/// stopped a restore between passes. Each of those shared flags was justified
/// by a doc comment saying the two runs "never run at once".
///
/// Derived from the source rather than a hand-kept table (see `sources.rs` for
/// why a list is not a ratchet): the flags a command claims and cancels are read
/// off its body. Two bulk runs started from different bulk action bars share
/// `bulk_cancel` — the one sanctioned multi-claimer, and it is one run kind.
#[test]
fn every_cancel_flag_belongs_to_one_run_kind_and_one_cancel_command() {
    use std::collections::BTreeMap;

    let mut claimers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cancellers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bad_shape: Vec<String> = Vec::new();
    let mut bad_canceller: Vec<String> = Vec::new();

    for cmd in super::sources::commands() {
        for flag in flags_before(&cmd.body, ".claim()") {
            if !flag.ends_with("_cancel") {
                bad_shape.push(format!("{}::{} claims `{flag}`", cmd.module, cmd.name));
            }
            claimers.entry(flag).or_default().push(cmd.name.clone());
        }
        let cancelled = flags_before(&cmd.body, ".cancel()");
        for flag in &cancelled {
            if !flag.ends_with("_cancel") {
                bad_shape.push(format!("{}::{} cancels `{flag}`", cmd.module, cmd.name));
            }
            cancellers
                .entry(flag.clone())
                .or_default()
                .push(cmd.name.clone());
        }
        if !cancelled.is_empty() && (!cmd.name.starts_with("cancel_") || cancelled.len() != 1) {
            bad_canceller.push(format!(
                "{}::{} cancels {cancelled:?} — a canceller is a `cancel_*` command that \
                 cancels exactly one flag",
                cmd.module, cmd.name
            ));
        }
    }

    assert!(
        bad_shape.is_empty(),
        "unrecognised claim/cancel shape: {bad_shape:#?}\n\
         Claim and cancel through a named `AppState.<kind>_cancel` field so this rule can read \
         which run kind a command belongs to."
    );
    assert!(bad_canceller.is_empty(), "{bad_canceller:#?}");
    assert!(
        claimers.len() >= 8,
        "only {} claimed cancel flag(s) found — the source walk or the call-shape detector is \
         broken, and a rule that scans nothing passes vacuously",
        claimers.len()
    );

    // One run kind per flag. The bulk commands are one kind (the bulk action
    // bar's runs), and every one of them rides `bulk_cancel`.
    for (flag, cmds) in &claimers {
        let is_bulk_kind = cmds.iter().all(|c| c.starts_with("bulk_"));
        assert!(
            cmds.len() == 1 || (is_bulk_kind && flag == "bulk_cancel"),
            "flag `{flag}` is shared by run kinds {cmds:?} — one kind's Cancel stops the others \
             (CancelFlag::cancel stamps every generation). Give each run kind its own \
             `AppState` flag and `cancel_*` command."
        );
        for cmd in cmds.iter().filter(|c| c.starts_with("bulk_")) {
            assert_eq!(
                flag, "bulk_cancel",
                "bulk command `{cmd}` claims `{flag}` — every `bulk_*` command rides `bulk_cancel`, \
                 which `cancel_bulk` stops"
            );
        }
    }

    // Exactly one Cancel command per claimed flag, and no orphan cancel.
    for (flag, cmds) in &claimers {
        let stoppers = cancellers.get(flag).map(Vec::as_slice).unwrap_or_default();
        assert!(
            stoppers.len() == 1,
            "flag `{flag}` (claimed by {cmds:?}) is cancelled by {stoppers:?} — it needs exactly \
             one `cancel_*` command, or its run has no Cancel (or two buttons that disagree)"
        );
    }
    for (flag, cmds) in &cancellers {
        assert!(
            claimers.contains_key(flag),
            "{cmds:?} cancel `{flag}`, which no command claims — an orphan Cancel stops nothing"
        );
    }

    // Every canceller is registered and has a typed binding, so the Cancel
    // button the flag exists for can actually be wired.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = std::fs::read_to_string(manifest.join("src/lib.rs")).expect("read src/lib.rs");
    let bindings_root = manifest
        .parent()
        .expect("apps/desktop")
        .join("web-rs/src/bindings");
    let mut bindings = String::new();
    let mut stack = vec![bindings_root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(src) = std::fs::read_to_string(&path)
            {
                bindings.push_str(&src);
            }
        }
    }
    assert!(
        !bindings.is_empty(),
        "read no bindings from {} — the walk is broken",
        bindings_root.display()
    );
    for name in cancellers.values().flatten() {
        assert!(
            lib.contains(&format!("::{name},")),
            "`{name}` is not in `generate_handler![]` (src/lib.rs) — its Cancel button would \
             reject at runtime"
        );
        assert!(
            bindings.contains(&format!("\"{name}\"")),
            "`{name}` has no typed binding under web-rs/src/bindings — nothing in the frontend \
             can press this Cancel"
        );
    }
}
