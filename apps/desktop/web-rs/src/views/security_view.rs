//! Unified Security workbench.
//!
//! One posture strip (read-only severity counts + Run / Cancel / Export /
//! progress / consent — the single owner of the audit-run lifecycle via
//! [`AuditController`]) above four co-equal sub-tabs: **Findings** (grouped,
//! remediation-centric — the default), **All apps** (the ranked score table),
//! and the two inventory lenses (Credential expiry, Delegated grants). The
//! controller is constructed once here and provided via context so both audit
//! panes read the same scan; the strip's counts are display-only — filtering
//! happens inside the panes (this view retired the old triple-control setup:
//! severity TabBar + finding-chip drawer + clickable scorecard all driving the
//! same two signals).
//!
//! Sub-panes are **keep-alive** (mounted on first visit, then toggled by CSS
//! `display`) so switching never tears down the audit's scan result or refetches
//! a lens — mirroring the main shell's view keep-alive.

use std::collections::HashSet;

use leptos::prelude::*;
use thaw::{
    Body1, Button, ButtonAppearance, Menu, MenuItem, MenuPosition, MenuTrigger, ProgressBar,
    Spinner, SpinnerSize,
};

use crate::components::icon::{Icon, IconName};
use crate::components::ui::{Callout, SectionHeader};
use crate::state::use_session;
use crate::util::keep_alive;
use crate::views::audit_view::posture::PostureCounts;
use crate::views::audit_view::{AuditAppsPane, AuditController, FindingsPane};
use crate::views::consent_grants_view::ConsentGrantsView;
use crate::views::credentials_dashboard::CredentialsDashboard;

#[component]
pub fn SecurityView() -> impl IntoView {
    let session = use_session();
    let sub = session.security_tab;

    // One controller for the whole workbench: the strip runs/cancels/exports,
    // both audit panes read the same scan via context.
    let ctrl = AuditController::new(session);
    provide_context(ctrl);

    // The two audit panes share one selection set; switching between them
    // clears it so a Findings-group selection can't silently feed the All-apps
    // bar's action set (and vice versa).
    Effect::new(move |prev: Option<String>| {
        let cur = sub.get();
        if let Some(prev) = prev
            && prev != cur
        {
            session.clear_audit_selection();
        }
        cur
    });

    // Insert-only latch of visited panes, seeded with the active one so the
    // first pane mounts immediately and is grown as the user switches.
    let visited = RwSignal::new(HashSet::from([sub.get_untracked()]));
    Effect::new(move |_| {
        let v = sub.get();
        visited.update(|set| {
            set.insert(v);
        });
    });

    view! {
        <div class="security-view">
            <PostureStrip />
            <div class="security-lenses">
                {lens_btn(sub, "findings", "Findings")}
                {lens_btn(sub, "apps", "All apps")}
                {lens_btn(sub, "credentials", "Credential expiry")}
                {lens_btn(sub, "grants", "Delegated grants")}
            </div>
            {keep_alive(sub, visited, "findings", || view! { <FindingsPane /> })}
            {keep_alive(sub, visited, "apps", || view! { <AuditAppsPane /> })}
            {keep_alive(sub, visited, "credentials", || view! { <CredentialsDashboard /> })}
            {keep_alive(sub, visited, "grants", || view! { <ConsentGrantsView /> })}
        </div>
    }
}

/// The workbench header: title, Run/Cancel/Export actions, read-only severity
/// summary, scan progress (+ rate-limit notice), scan/export messages, and the
/// AuditLog.Read.All consent prompt. Owns no filter state — counts here are
/// informational; drilling happens in the panes.
#[component]
fn PostureStrip() -> impl IntoView {
    let ctrl = expect_context::<AuditController>();
    let scanning = ctrl.scanning;
    let progress = ctrl.progress;
    let peak_cap = ctrl.peak_cap;

    view! {
        <div class="posture-strip">
            <SectionHeader title="Security".to_string() crumb="Posture".to_string()>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| ctrl.run())
                    disabled=Signal::derive(move || scanning.get())
                >
                    {move || {
                        if scanning.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { "Run audit" }.into_any()
                        }
                    }}
                </Button>
                <Show when=move || scanning.get() fallback=|| view! { <></> }>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| ctrl.cancel())
                    >
                        "Cancel"
                    </Button>
                </Show>
                <Menu
                    position=MenuPosition::BottomEnd
                    on_select=move |fmt: String| {
                        match fmt.as_str() {
                            "csv" => ctrl.export("csv"),
                            "json" => ctrl.export("json"),
                            "html" => ctrl.export("html"),
                            _ => {}
                        }
                    }
                >
                    <MenuTrigger slot>
                        <Button
                            class="btn-icon-label"
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            disabled=Signal::derive(move || {
                                ctrl.exporting.get() || ctrl.result.with(|r| r.is_none())
                            })
                        >
                            "Export"
                            <Icon name=IconName::ChevronDown size=16 />
                        </Button>
                    </MenuTrigger>
                    <MenuItem value="csv".to_string()>"Export as CSV…"</MenuItem>
                    <MenuItem value="json".to_string()>"Export as JSON…"</MenuItem>
                    <MenuItem value="html".to_string()>"Export as HTML…"</MenuItem>
                </Menu>
            </SectionHeader>
            {move || {
                ctrl.posture
                    .get()
                    .map(|c: PostureCounts| {
                        view! {
                            <div class="posture-strip__counts dash-metrics">
                                {metric_box(c.critical, "Critical", "danger")}
                                {metric_box(c.high, "High", "danger")}
                                {metric_box(c.medium, "Medium", "warning")}
                                {metric_box(c.low, "Low", "muted")}
                            </div>
                        }
                    })
            }}
            {move || {
                progress
                    .get()
                    .map(|p| {
                        let pct = if p.total > 0 {
                            (p.done as f64) / (p.total as f64)
                        } else {
                            0.0
                        };
                        let cap = p.in_flight_cap;
                        view! {
                            <div class="audit-progress">
                                <ProgressBar value=Signal::derive(move || pct) />
                                <Body1>
                                    {format!(
                                        "{} / {} apps  (cap: {}{})",
                                        p.done,
                                        p.total,
                                        cap,
                                        if p.cancelled { ", cancelled" } else { "" },
                                    )}
                                </Body1>
                                {p.current_app.map(|n| view! { <Body1>{n}</Body1> })}
                                <Show when=move || cap < peak_cap.get()>
                                    <p class="audit-progress__notice" role="status">
                                        "Microsoft Graph is rate-limiting this scan, so it's automatically slowing down to recover. It will still complete — large tenants just take longer."
                                    </p>
                                </Show>
                            </div>
                        }
                    })
            }}
            {move || {
                ctrl.scan_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
            }}
            {move || {
                ctrl.export_msg.get().map(|m| view! { <Callout tone="ok">{m}</Callout> })
            }}
            // AuditLog.Read.All consent prompt — the sign-in activity report
            // (behind the Unused finding) needs it. Offered when the last run
            // found it un-consented; granting re-runs the audit.
            {move || {
                ctrl.consent_needed
                    .get()
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                "Unused-app detection needs the AuditLog.Read.All permission (it reads each app's last sign-in). Grant consent to enable it — requires a Global Reader / Security Reader / Reports Reader role and Entra ID P1 or P2."
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(move |_| ctrl.grant_reports_consent())
                                        disabled=Signal::derive(move || scanning.get())
                                    >
                                        "Grant consent & re-run"
                                    </Button>
                                </div>
                            </Callout>
                        }
                    })
            }}
        </div>
    }
}

/// One read-only severity count. Zero counts render muted; non-zero use the
/// tone colour. Deliberately NOT clickable — the strip summarizes, the panes
/// filter (the old clickable scorecard doubled the panes' own controls).
fn metric_box(n: usize, label: &'static str, tone: &'static str) -> impl IntoView {
    let num_class = if n == 0 {
        "dash-metric__num".to_string()
    } else {
        format!("dash-metric__num dash-metric__num--{tone}")
    };
    view! {
        <div class="dash-metric dash-metric--box">
            <span class=num_class>{n}</span>
            <span class="dash-metric__label">{label}</span>
        </div>
    }
}

/// One entry in the workbench's sub-tab selector.
fn lens_btn(sub: RwSignal<String>, value: &'static str, label: &'static str) -> impl IntoView {
    let class = move || {
        let mut c = String::from("security-lens");
        if sub.with(|s| s == value) {
            c.push_str(" security-lens--active");
        }
        c
    };
    view! {
        <button type="button" class=class on:click=move |_| sub.set(value.to_string())>
            {label}
        </button>
    }
}
