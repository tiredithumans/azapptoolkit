//! Cancellation identity: every long-running command claims exactly one
//! `CancelToken`.
//!
//! Replaces the old "call `reset()` at the top" rule, which pinned a shape that
//! could not be made correct — see the test's own doc comment.

/// Command modules that own a long-running fan-out, for the cancel-flag rule.
const CANCEL_FLAG_MODULES: &[(&str, &str)] = &[
    (
        "commands/audit.rs",
        include_str!("../../src/commands/audit.rs"),
    ),
    (
        "commands/bulk.rs",
        include_str!("../../src/commands/bulk.rs"),
    ),
    (
        "commands/backup.rs",
        include_str!("../../src/commands/backup.rs"),
    ),
    (
        "commands/restore.rs",
        include_str!("../../src/commands/restore.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../../src/commands/sharepoint.rs"),
    ),
    (
        "commands/keyvault_rbac.rs",
        include_str!("../../src/commands/keyvault_rbac.rs"),
    ),
    (
        "commands/permission_tester.rs",
        include_str!("../../src/commands/permission_tester.rs"),
    ),
];

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
/// Splitting on `#[tauri::command]` gives one chunk per handler, which is enough
/// to tell "this handler drives a fan-out" from "this handler claims a token".
#[test]
fn every_long_running_command_claims_exactly_one_cancel_token() {
    let mut missing: Vec<String> = Vec::new();
    let mut multiple: Vec<String> = Vec::new();
    for (name, src) in CANCEL_FLAG_MODULES {
        for chunk in src.split("#[tauri::command]").skip(1) {
            // Stop at the module's test block: fixtures legitimately call the
            // fan-out helpers without being commands.
            let body = chunk.split("#[cfg(test)]").next().unwrap_or(chunk);
            let drives_long_run = body.contains("dispatch_capped(")
                || body.contains("run_bulk_seq(")
                // restore.rs is sequential — no dispatcher, same hazard.
                || body.contains("report.cancelled = true");
            if !drives_long_run {
                continue;
            }
            let signature = body
                .lines()
                .find(|l| l.contains("pub async fn") || l.contains("pub fn"))
                .unwrap_or("(unnamed)")
                .trim();
            match body.matches(".claim()").count() {
                0 => missing.push(format!("{name}: {signature}")),
                1 => {}
                n => multiple.push(format!("{name}: {signature} claims {n} times")),
            }
        }
    }
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
