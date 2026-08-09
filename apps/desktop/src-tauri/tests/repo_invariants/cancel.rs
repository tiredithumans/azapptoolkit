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

/// The audit claims its token **before** the tenant-wide prefetch, not after.
///
/// `claim()` takes a fresh generation and `cancel()` stamps whatever generation
/// is current when it runs, so a token claimed after a long phase carries a
/// higher generation than a cancel issued during that phase —
/// `is_cancelled()` compares `cancelled >= generation`, so the cancel is
/// silently discarded. The six-way prefetch is the longest phase of a large
/// audit, which made it both the likeliest moment for an operator to press
/// Cancel and the one window where pressing it did nothing.
///
/// Pinned positionally because that is exactly what went wrong: the claim was
/// present, correct in isolation, and in the wrong place.
#[test]
fn the_audit_claims_its_token_before_the_prefetch() {
    let audit = super::sources::commands()
        .into_iter()
        .find(|c| c.name == "run_audit")
        .expect("commands/audit.rs no longer defines run_audit");
    let claim = audit
        .body
        .find(".claim()")
        .expect("run_audit no longer claims a CancelToken");
    let prefetch = audit
        .body
        .find("futures::join!")
        .expect("run_audit no longer uses a join! prefetch — re-check this rule still applies");
    assert!(
        claim < prefetch,
        "run_audit claims its CancelToken AFTER the tenant-wide prefetch join!. A cancel pressed \
         during the prefetch stamps a lower generation than the token, so `is_cancelled()` never \
         sees it and the run scores the whole tenant anyway. Move the claim above the join!."
    );
}
