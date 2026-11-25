//! Conditional Access tab — which CA policies apply to this app, and what they
//! enforce. Read-only; degrades gracefully when the tenant lacks an Entra ID
//! P1/P2 license or the account a policy-reading role, and offers the lever for
//! every other failure — its own "Grant consent & retry" for Policy.Read.All
//! (the `policy` feature, which also enables the credential-lifetime policy
//! reads), Verify identity, Re-authenticate.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::applications::ApplicationDetail;
use crate::bindings::conditional_access::{
    self, ConditionalAccessPolicyDto, NetworkLockStatus, ReportOnlyReadout,
};
use crate::components::feature_load_error::FeatureLoadError;
use crate::components::requires_role::RequiresRole;
use crate::components::ui::{Badge, BadgeTone, DataTable, FormError, SkeletonList};
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::dialogs::network_lock_dialog::NetworkLockDialog;
use azapptoolkit_core::conditional_access::{LockIneligible, NetworkLock};

use crate::util::no_tenant;

/// App-registration Conditional Access tab (keys on the app's appId): the
/// Network lock section, then the policies that apply. A lock write refreshes
/// both.
#[component]
pub fn ConditionalAccessTab(#[prop(into)] detail: Signal<Arc<ApplicationDetail>>) -> impl IntoView {
    let app_id = Signal::derive(move || detail.with(|d| d.application.app_id.clone()));
    let app_name = Signal::derive(move || detail.with(|d| d.application.display_name.clone()));
    let reload = RwSignal::new(0_u32);
    view! {
        <NetworkLockSection
            app_id=app_id
            app_name=app_name
            on_changed=Callback::new(move |()| reload.update(|n| *n += 1))
        />
        <ConditionalAccessPanel app_id=app_id reload=reload />
    }
}

/// Core CA panel for an appId. Shared by the app-registration and
/// enterprise-application detail panes. `reload` lets a host refresh it (the
/// app-registration tab does after a lock write).
#[component]
pub fn ConditionalAccessPanel(
    #[prop(into)] app_id: Signal<String>,
    #[prop(optional)] reload: Option<RwSignal<u32>>,
) -> impl IntoView {
    let session = use_session();
    let reload = reload.unwrap_or_else(|| RwSignal::new(0_u32));

    let policies = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let app_id = app_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            conditional_access::list_conditional_access_for_app(&t.tenant_id, &app_id).await
        }
    });

    view! {
        <div class="conditional-access-tab">
            <header class="row-between">
                <div class="row">
                    <strong>"Conditional Access"</strong>
                    <RequiresRole capability_key="conditional_access" />
                </div>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| reload.update(|n| *n += 1))
                >
                    "Refresh"
                </Button>
            </header>
            <span class="ui-text">
                "Conditional Access policies that target this application — as a resource (directly, or via an \"All apps\" / grouping include) or as a client (its service principal / workload-identity clients). Requires Policy.Read.All consent and an Entra ID P1/P2 license."
            </span>

            <Suspense fallback=move || view! { <SkeletonList rows=4 /> }>
                {move || Suspend::new(async move {
                    match policies.await {
                        Ok(list) => ca_table(list).into_any(),
                        // Every failure gets its lever: consent, step-up, the
                        // session's toast, the backend's "ca_unavailable"
                        // notice (license / role / transient), or Retry.
                        Err(e) => {
                            view! {
                                <FeatureLoadError
                                    error=e
                                    consent_feature="policy"
                                    step_up_features=&["policy"]
                                    consent_text="Conditional Access needs admin consent to Policy.Read.All (the same consent enables the credential-lifetime policy checks)."
                                    unavailable_code="ca_unavailable"
                                    on_retry=Callback::new(move |()| reload.update(|n| *n += 1))
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

fn ca_table(list: Vec<ConditionalAccessPolicyDto>) -> impl IntoView {
    view! {
        <DataTable
            headers=vec!["Policy", "State", "Applies", "Controls"]
            rows=list
            empty_message="No Conditional Access policies target this app."
            row=|p| ca_row(p).into_any()
        />
    }
}

fn ca_row(p: ConditionalAccessPolicyDto) -> impl IntoView {
    let (state_label, state_tone) = state_badge(&p.state);
    let applies = applies_label(&p.applies_reason, p.workload_clients);
    let controls = if p.grant_controls.is_empty() {
        "—".to_string()
    } else {
        p.grant_controls
            .iter()
            .map(|c| control_label(c))
            .collect::<Vec<_>>()
            .join(if p.grant_operator.as_deref() == Some("OR") {
                " or "
            } else {
                " and "
            })
    };
    view! {
        <tr>
            <td>{p.display_name}</td>
            <td>
                <Badge label=state_label tone=state_tone />
            </td>
            <td>{applies}</td>
            <td>{controls}</td>
        </tr>
    }
}

fn state_badge(state: &str) -> (&'static str, BadgeTone) {
    match state {
        "enabled" => ("Enabled", BadgeTone::Ok),
        "enabledForReportingButNotEnforced" => ("Report-only", BadgeTone::Warning),
        "disabled" => ("Disabled", BadgeTone::Neutral),
        _ => ("Unknown", BadgeTone::Neutral),
    }
}

/// Renders the `Applies` cell. Resource-axis codes say which *resource* set
/// the policy targets; a set `workload_clients` flag narrows it to policies
/// whose client axis names this app's service principal (or workload
/// identities generally), so the suffix keeps "All apps" honest when only
/// workload clients are gated. The `sp`/`allWorkload`/`clientFilter*` codes
/// are client-only policies — they gate this app signing in *elsewhere*
/// with its credentials, which the resource-only view used to drop.
fn applies_label(reason: &str, workload_clients: bool) -> String {
    let base = match reason {
        "appId" => "This app",
        "all" => "All apps",
        "office365" => "Office 365 (may apply)",
        "adminPortals" => "Admin portals (may apply)",
        "filter" => "App filter (may apply)",
        "filterExclude" => "App filter (applies unless excluded)",
        "sp" => "This app's service principal (as a client)",
        "allWorkload" => "All workload identities (as clients)",
        "clientFilter" => "Client filter (may apply)",
        "clientFilterExclude" => "Client filter (applies unless excluded)",
        _ => "May apply",
    };
    let narrowed = matches!(
        reason,
        "appId" | "all" | "office365" | "adminPortals" | "filter" | "filterExclude"
    ) && workload_clients;
    if narrowed {
        format!("{base} — workload-identity clients only")
    } else {
        base.to_string()
    }
}

/// Friendly label for a known grant control, or the raw Graph name for any
/// control we don't have a translation for (so it still renders meaningfully).
fn control_label(control: &str) -> String {
    match control {
        "mfa" => "MFA",
        "block" => "Block access",
        "compliantDevice" => "Compliant device",
        "domainJoinedDevice" => "Hybrid-joined device",
        "approvedApplication" => "Approved app",
        "compliantApplication" => "App protection policy",
        "passwordChange" => "Password change",
        other => return other.to_string(),
    }
    .to_string()
}

/// Why Conditional Access can't target the app, in the checklist's words.
fn ineligible_text(reason: LockIneligible) -> &'static str {
    match reason {
        LockIneligible::OtherTenant => {
            "Not possible — Conditional Access can't target an app owned by another tenant."
        }
        LockIneligible::MultiTenantApp => {
            "Not possible — Conditional Access can't target a multi-tenant app."
        }
        LockIneligible::ManagedIdentity => {
            "Not possible — Conditional Access can't target a managed identity."
        }
        LockIneligible::NoServicePrincipal => {
            "Not possible — Conditional Access can't target an app with no service principal."
        }
    }
}

/// What a report-only lock would have blocked, as one sentence — never a
/// reassurance without evidence: no evaluated sign-ins says so, and a capped
/// read is a floor.
fn readout_line(readout: Option<&ReportOnlyReadout>) -> String {
    let Some(r) = readout else {
        return "Couldn't read the app's sign-in log, so what the lock would block is unknown."
            .to_string();
    };
    if r.evaluated == 0 {
        return "No sign-ins have been checked against the lock yet — wait until the app has \
                signed in before turning it on."
            .to_string();
    }
    let checked = if r.truncated {
        format!(
            "Of the latest {} sign-ins the lock checked in the last {} days (older ones weren't read)",
            r.evaluated, r.window_days
        )
    } else {
        format!(
            "Of {} sign-in{} the lock checked in the last {} days",
            r.evaluated,
            if r.evaluated == 1 { "" } else { "s" },
            r.window_days
        )
    };
    let blocked = match (r.would_block, r.truncated) {
        (0, false) => "none would have been blocked".to_string(),
        (n, true) => format!("at least {n} would have been blocked"),
        (n, false) => format!("{n} would have been blocked"),
    };
    let from = if r.would_block > 0 && !r.sample_ips.is_empty() {
        format!(" (from {})", r.sample_ips.join(", "))
    } else {
        String::new()
    };
    format!("{checked}, {blocked}{from}.")
}

/// The app's Network lock: a per-app Conditional Access policy that blocks
/// its sign-ins from everywhere except chosen named locations. Offers only the
/// toolkit's own actions — create when nothing locks the app, turn on / remove
/// the toolkit's lock in any state — and nothing for another policy's lock or
/// an app Conditional Access can't target. A lock limits where a stolen
/// credential works; it never narrows what the app can read.
#[component]
pub fn NetworkLockSection(
    #[prop(into)] app_id: Signal<String>,
    #[prop(into)] app_name: Signal<String>,
    #[prop(optional)] on_changed: Option<Callback<()>>,
) -> impl IntoView {
    let session = use_session();
    let reload = RwSignal::new(0_u32);
    let create_open = RwSignal::new(false);
    let pending_turn_on: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);
    let cmd = use_command().with_consent_feature("conditional_access_write");

    let status = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let app_id = app_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            conditional_access::get_network_lock(&t.tenant_id, &app_id).await
        }
    });
    let changed = move || {
        reload.update(|n| *n += 1);
        if let Some(cb) = on_changed {
            cb.try_run(());
        }
    };
    let turn_on = move |policy_id: String| {
        let app = app_id.get();
        cmd.run(
            move |()| changed(),
            move |tenant| async move {
                conditional_access::enable_network_lock(&tenant, &app, &policy_id).await
            },
        );
    };
    let remove = move |policy_id: String| {
        let app = app_id.get();
        cmd.run(
            move |()| changed(),
            move |tenant| async move {
                conditional_access::remove_network_lock(&tenant, &app, &policy_id).await
            },
        );
    };

    view! {
        <section class="conditional-access-tab">
            <header class="row-between">
                <div class="row">
                    <strong>"Network lock"</strong>
                    <RequiresRole capability_key="conditional_access_lock" />
                </div>
            </header>
            <Suspense fallback=move || view! { <SkeletonList rows=2 /> }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(s) => {
                            lock_state_view(s, app_name, create_open, pending_turn_on, pending_remove)
                                .into_any()
                        }
                        Err(e) => {
                            view! {
                                <FeatureLoadError
                                    error=e
                                    consent_feature="policy"
                                    step_up_features=&["policy"]
                                    consent_text="The network lock reads Conditional Access, which needs admin consent to Policy.Read.All."
                                    unavailable_code="ca_unavailable"
                                    on_retry=Callback::new(move |()| reload.update(|n| *n += 1))
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
            {move || cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })}
            <NetworkLockDialog
                open=create_open
                app_id=app_id
                on_close=Callback::new(move |()| create_open.set(false))
                on_created=Callback::new(move |()| changed())
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_turn_on.with(|p| p.is_some()))
                title="Turn on the network lock?"
                body="Sign-ins by this app from outside the chosen locations will be blocked."
                subject=Signal::derive(move || {
                    pending_turn_on.with(|p| p.as_ref().map(|(_, s)| s.clone())).unwrap_or_default()
                })
                confirm_label="Turn on"
                busy=cmd.busy
                on_confirm=Callback::new(move |()| {
                    if let Some((id, _)) = pending_turn_on.get() {
                        pending_turn_on.set(None);
                        turn_on(id);
                    }
                })
                on_close=Callback::new(move |()| pending_turn_on.set(None))
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove the network lock?"
                body="Deletes the toolkit's lock policy. The named locations stay."
                subject=app_name
                confirm_label="Delete policy"
                busy=cmd.busy
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_remove.get() {
                        pending_remove.set(None);
                        remove(id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </section>
    }
}

/// The section body for one status.
fn lock_state_view(
    s: NetworkLockStatus,
    app_name: Signal<String>,
    create_open: RwSignal<bool>,
    pending_turn_on: RwSignal<Option<(String, String)>>,
    pending_remove: RwSignal<Option<String>>,
) -> impl IntoView {
    let button = |label: &'static str, on: Box<dyn Fn() + Send + Sync>| {
        view! {
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| on())
            >
                {label}
            </Button>
        }
    };
    if let Some(reason) = s.ineligible {
        return view! { <span class="ui-text">{ineligible_text(reason)}</span> }.into_any();
    }
    if let Some(lock) = s.toolkit_lock {
        let places = lock
            .excluded_locations
            .iter()
            .map(|l| l.display_name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let id_on = lock.policy_id.clone();
        let id_off = lock.policy_id.clone();
        let readout = readout_line(s.readout.as_ref());
        // The readout is only read for a report-only lock: a turned-off one
        // checks nothing, so its confirm says that instead.
        let readout_subject = if lock.state == "enabledForReportingButNotEnforced" {
            readout.clone()
        } else {
            "the lock is turned off, so it hasn't checked any sign-ins.".to_string()
        };
        let ask_turn_on: Box<dyn Fn() + Send + Sync> = Box::new(move || {
            pending_turn_on.set(Some((
                id_on.clone(),
                format!("{}: {readout_subject}", app_name.get_untracked()),
            )))
        });
        let ask_remove: Box<dyn Fn() + Send + Sync> =
            Box::new(move || pending_remove.set(Some(id_off.clone())));
        return match lock.state.as_str() {
            "enabled" => view! {
                <span class="ui-text">
                    {format!("Blocking this app's sign-ins from outside: {places}.")}
                </span>
                <div class="actions-row">{button("Remove lock", ask_remove)}</div>
            }
            .into_any(),
            "enabledForReportingButNotEnforced" => view! {
                <span class="ui-text">
                    {format!("Report-only — not blocking yet. Allowed locations: {places}.")}
                </span>
                <span class="ui-text">{readout}</span>
                <div class="actions-row">
                    {button("Turn on lock", ask_turn_on)} {button("Remove", ask_remove)}
                </div>
            }
            .into_any(),
            _ => view! {
                <span class="ui-text">
                    {format!(
                        "Turned off outside the toolkit (in the portal). Allowed locations: {places}.",
                    )}
                </span>
                <div class="actions-row">
                    {button("Turn on lock", ask_turn_on)} {button("Remove", ask_remove)}
                </div>
            }
            .into_any(),
        };
    }
    if let NetworkLock::Enforced { .. } = s.other {
        let name = s
            .other_policy_name
            .unwrap_or_else(|| "another policy".into());
        return view! {
            <span class="ui-text">{format!("Locked by {name} — not managed here.")}</span>
        }
        .into_any();
    }
    let maybe_other = matches!(s.other, NetworkLock::ReportOnly | NetworkLock::MayApply).then(|| {
        view! {
            <span class="ui-text muted">
                "Another policy may cover this app (report-only, or through a filter or app group)."
            </span>
        }
    });
    let open_create: Box<dyn Fn() + Send + Sync> = Box::new(move || create_open.set(true));
    view! {
        <span class="ui-text">
            "No network lock. A lock blocks this app's sign-ins from everywhere except the named locations you choose, so a stolen credential stops working elsewhere. It doesn't narrow what the app can read."
        </span>
        {maybe_other}
        <div class="actions-row">{button("Lock to named locations…", open_create)}</div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readout(
        evaluated: u32,
        would_block: u32,
        truncated: bool,
        ips: &[&str],
    ) -> ReportOnlyReadout {
        ReportOnlyReadout {
            evaluated,
            would_block,
            truncated,
            sample_ips: ips.iter().map(|s| s.to_string()).collect(),
            window_days: 7,
        }
    }

    #[test]
    fn readout_lines_never_reassure_without_evidence() {
        assert_eq!(
            readout_line(Some(&readout(0, 0, false, &[]))),
            "No sign-ins have been checked against the lock yet — wait until the app has signed in before turning it on."
        );
        assert_eq!(
            readout_line(Some(&readout(5, 3, false, &["203.0.113.7"]))),
            "Of 5 sign-ins the lock checked in the last 7 days, 3 would have been blocked (from 203.0.113.7)."
        );
        assert_eq!(
            readout_line(Some(&readout(5, 0, false, &[]))),
            "Of 5 sign-ins the lock checked in the last 7 days, none would have been blocked."
        );
        assert_eq!(
            readout_line(Some(&readout(1000, 12, true, &[]))),
            "Of the latest 1000 sign-ins the lock checked in the last 7 days (older ones weren't read), at least 12 would have been blocked."
        );
        assert_eq!(
            readout_line(None),
            "Couldn't read the app's sign-in log, so what the lock would block is unknown."
        );
    }
}
