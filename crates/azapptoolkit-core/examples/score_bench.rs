//! Throughput probe for the audit scorer — the CPU-bound half of a full-tenant
//! run. Temporary tool for answering the `[profile.release] opt-level` question;
//! see the note next to that block in /Cargo.toml.
//!
//!   cargo run --release --example score_bench -p azapptoolkit-core
//!   CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo run --release --example score_bench -p azapptoolkit-core

use azapptoolkit_core::audit::{AppPermissions, ResourcePermission, score_application};
use azapptoolkit_core::models::{Application, PasswordCredential};

fn main() {
    let now = chrono::Utc::now();
    let perms = AppPermissions {
        app_role_grants: vec![
            ResourcePermission::graph("Mail.ReadWrite"),
            ResourcePermission::graph("Mail.Read"),
            ResourcePermission::graph("Directory.ReadWrite.All"),
            ResourcePermission::graph("Sites.ReadWrite.All"),
            ResourcePermission::exchange_online("full_access_as_app"),
        ],
        scope_values: vec!["User.Read".into(), "Directory.AccessAsUser.All".into()],
        has_admin_consent: true,
        mail_scopes: Default::default(),
    };
    let app = Application {
        id: "obj".into(),
        app_id: "app".into(),
        display_name: "Bench App".into(),
        created_date_time: Some(now - chrono::Duration::days(400)),
        password_credentials: vec![PasswordCredential {
            display_name: Some("s1".into()),
            end_date_time: Some(now - chrono::Duration::days(1)),
            ..Default::default()
        }],
        owners: Some(vec![]),
        ..Default::default()
    };

    const N: usize = 200_000;
    let start = std::time::Instant::now();
    let mut checksum = 0u64;
    for _ in 0..N {
        let item = score_application(&app, Some(true), &perms, now);
        checksum = checksum.wrapping_add(item.risk_score as u64 + item.issues.len() as u64);
    }
    let elapsed = start.elapsed();
    println!(
        "scored {N} apps in {:?} ({:.0} apps/sec) checksum={checksum}",
        elapsed,
        N as f64 / elapsed.as_secs_f64()
    );
}
