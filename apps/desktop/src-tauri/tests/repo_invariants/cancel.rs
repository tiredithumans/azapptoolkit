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
/// `run_audit`'s claim placement is a rule of its own — see
/// [`the_audit_claims_its_token_before_the_prefetch`].
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
