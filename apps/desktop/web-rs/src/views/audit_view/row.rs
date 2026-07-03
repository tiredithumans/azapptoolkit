//! Per-row actions for an audit finding: the "Open" deep-link plus any
//! one-click remediation the scorer attached.

use azapptoolkit_core::audit::{
    AuditItem, AuditPrincipalKind, RemediationAction, RemediationKind, issue,
};
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::remediation;
use crate::state::use_session;
use crate::views::dialogs::add_owner::AddOwnerButton;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::dialogs::scope_remediation::{
    ScopeFixTarget, ScopeMailboxButton, ScopeSharePointButton,
};

/// Picks the most actionable detail-pane tab for an audit finding, so the row's
/// "Open" deep-link lands where the operator can act on it (mailbox/site
/// scoping and risky perms → Permissions, which hosts the Exchange/SharePoint
/// scoping sections; ownership → Owners; expiry → Credentials), falling back to
/// Overview. Which pane it opens follows `principal_kind` (app registration /
/// enterprise app / managed identity); SP-only rows never carry ownership or
/// credential findings, so their tab is always Permissions or Overview — both
/// exist on every pane.
fn target_tab(item: &AuditItem) -> &'static str {
    use azapptoolkit_core::audit::CredentialStatus;
    let has = |p: &str| item.issues.iter().any(|x| x.starts_with(p));
    if has(issue::ORG_WIDE_MAILBOX)
        || item
            .issues
            .iter()
            .any(|x| x.contains(issue::SCOPED_VIA_RBAC))
        || has(issue::ORG_WIDE_SHAREPOINT)
        || has(issue::SCOPED_SHAREPOINT)
        || has(issue::HIGH_RISK_APP_PERMS)
        || has(issue::HIGH_RISK_DELEGATED_PERMS)
        || has(issue::REDUNDANT_APP_PERMS)
    {
        "permissions"
    } else if has(issue::NO_OWNERS) || has(issue::SINGLE_OWNER) {
        "owners"
    } else if matches!(
        item.credential_status,
        CredentialStatus::ExpiringSoon | CredentialStatus::Expired
    ) {
        "credentials"
    } else {
        "overview"
    }
}

/// Per-row actions for an audit finding. Always renders an "Open" deep-link into
/// the app's detail pane on the most actionable tab (turning the audit from a
/// dead-end table into a launchpad), followed by any one-click remediation the
/// scorer attached: remove-expired-credentials (a static confirm dialog) and the
/// scoping fixes (guided group/site modals). On success each fires `on_done` so
/// the parent clears this item's remediations — the buttons disappear for good
/// (surviving facet/search changes) and the audit cache is busted server-side,
/// so a re-run reflects the new scores.
#[component]
pub(super) fn AuditRowActions(
    item: AuditItem,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let find = |k: RemediationKind| item.remediations.iter().find(|r| r.kind == k).cloned();
    let expired = find(RemediationKind::RemoveExpiredCredentials);
    let redundant = find(RemediationKind::RemoveRedundantPermissions);
    let mailbox = find(RemediationKind::ScopeMailboxAccess);
    let sharepoint = find(RemediationKind::ScopeSharePointAccess);
    let add_owner = find(RemediationKind::AddOwner);
    let disable = find(RemediationKind::DisableSignIn);

    let tab = target_tab(&item);
    let kind = item.principal_kind;
    let object_id = item.object_id.clone();
    // SP-only rows route their scope Fixes to the SP-only cores, which need the
    // appId + display name alongside the SP object id — all on the item.
    let scope_target = match kind {
        AuditPrincipalKind::Application => ScopeFixTarget::AppReg {
            object_id: object_id.clone(),
        },
        AuditPrincipalKind::ServicePrincipal | AuditPrincipalKind::ManagedIdentity => {
            ScopeFixTarget::ServicePrincipal {
                sp_object_id: object_id.clone(),
                app_id: item.app_id.clone(),
                display_name: item.application_name.clone(),
            }
        }
    };
    let oid_open = object_id.clone();
    let oid_r = object_id.clone();
    let oid_owner = object_id.clone();
    let oid_disable = object_id.clone();
    let target_m = scope_target.clone();
    let target_s = scope_target;
    view! {
        <div class="audit-actions-stack">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                on_click=Box::new(move |_| match kind {
                    AuditPrincipalKind::Application => {
                        session.open_app_on_tab(oid_open.clone(), tab)
                    }
                    AuditPrincipalKind::ServicePrincipal => {
                        session.open_enterprise_on_tab(oid_open.clone(), tab)
                    }
                    AuditPrincipalKind::ManagedIdentity => {
                        session.open_managed_identity_on_tab(oid_open.clone(), tab)
                    }
                })
            >
                "Open"
            </Button>
            {expired
                .map(|action| {
                    view! {
                        <ExpiredCredsAction object_id=object_id.clone() action=action on_done=on_done />
                    }
                })}
            {redundant
                .map(|action| {
                    view! {
                        <RedundantPermsAction object_id=oid_r.clone() action=action on_done=on_done />
                    }
                })}
            {mailbox
                .map(|action| {
                    view! { <ScopeMailboxButton target=target_m.clone() action=action on_done=on_done /> }
                })}
            {sharepoint
                .map(|action| {
                    view! {
                        <ScopeSharePointButton target=target_s.clone() action=action on_done=on_done />
                    }
                })}
            {add_owner
                .map(|action| {
                    view! { <AddOwnerButton object_id=oid_owner.clone() action=action on_done=on_done /> }
                })}
            {disable
                .map(|action| {
                    view! {
                        <DisableSignInAction object_id=oid_disable.clone() action=action on_done=on_done />
                    }
                })}
        </div>
    }
}

/// The disable-sign-in fix for an unused app: a button gated by a static
/// confirm dialog. Sets `accountEnabled: false` on the app's service principal
/// — reversible any time from the enterprise app's Overview toggle, which is
/// why a plain confirm (no typed keyword) suffices.
#[component]
fn DisableSignInAction(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let confirm = move |()| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let object_id = object_id.clone();
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match remediation::remediate_disable_sign_in(&t.tenant_id, &object_id).await {
                Ok(()) => {
                    open.set(false);
                    session.toast_success(
                        "Sign-in disabled — re-enable anytime from the enterprise app's Overview. Re-run the audit to refresh scores.",
                    );
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let label = action.label.clone();
    let detail = action.detail.clone();

    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ConfirmDialog
                open=Signal::derive(move || open.get())
                title="Disable sign-in?"
                body="Blocks token issuance for this unused app by disabling its service principal. This is reversible — re-enable it anytime from the enterprise app's Overview tab. Nothing is deleted. Re-run the audit afterward to refresh scores."
                confirm_label="Disable sign-in"
                busy=Signal::derive(move || busy.get())
                error=Signal::derive(move || error.get())
                on_confirm=Callback::new(confirm)
                on_close=Callback::new(move |()| open.set(false))
            />
        </div>
    }
        .into_any()
}

/// The remove-redundant-permissions fix: a button gated by a static confirm
/// dialog (the narrower permissions are previewed in-row and the covering
/// broader ones listed under Issues). The backend re-plans against the live
/// manifest + grants, so the toast reports what was actually removed/skipped.
#[component]
fn RedundantPermsAction(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let confirm = move |()| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let object_id = object_id.clone();
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match remediation::remediate_remove_redundant_permissions(&t.tenant_id, &object_id)
                .await
            {
                Ok(outcome) => {
                    open.set(false);
                    let n = outcome.removed.len();
                    let mut msg = format!(
                        "Removed {n} redundant permission{}",
                        if n == 1 { "" } else { "s" }
                    );
                    if !outcome.skipped.is_empty() {
                        msg.push_str(&format!(
                            "; skipped {} (covering grant no longer present)",
                            outcome.skipped.join(", ")
                        ));
                    }
                    msg.push_str(" — re-run the audit to refresh scores.");
                    session.toast_success(&msg);
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let label = action.label.clone();
    let detail = action.detail.clone();

    view! {
        <div class="audit-actions">
            <Button
                class="button--danger"
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ConfirmDialog
                open=Signal::derive(move || open.get())
                title="Remove redundant permissions?"
                body="Removes the narrower permissions listed under Issues — a broader permission this app also holds already grants the same access, so its calls keep working. Each removal is re-checked against the live grants first; a permission whose covering grant has since been revoked or scoped is skipped. Re-run the audit afterward to refresh scores."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.get())
                error=Signal::derive(move || error.get())
                on_confirm=Callback::new(confirm)
                on_close=Callback::new(move |()| open.set(false))
            />
        </div>
    }
        .into_any()
}

/// The remove-expired-credentials fix: a button gated by a static confirm dialog
/// (the specific credentials are previewed in-row and listed under Issues).
#[component]
fn ExpiredCredsAction(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let confirm = move |()| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let object_id = object_id.clone();
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match remediation::remediate_remove_expired_credentials(&t.tenant_id, &object_id).await
            {
                Ok(outcome) => {
                    open.set(false);
                    let n = outcome.removed_secrets + outcome.removed_certificates;
                    session.toast_success(
                        format!(
                            "Removed {n} expired credential{} — re-run the audit to refresh scores.",
                            if n == 1 { "" } else { "s" }
                        )
                        .as_str(),
                    );
                    // Parent drops this item's remediations → button replaced by
                    // "—", and the state can't be lost by a re-render.
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let label = action.label.clone();
    let detail = action.detail.clone();

    view! {
        <div class="audit-actions">
            <Button
                class="button--danger"
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ConfirmDialog
                open=Signal::derive(move || open.get())
                title="Remove expired credentials?"
                body="Permanently removes this app's expired secrets and certificates (listed under Issues). Expired credentials can't authenticate, so removing them won't disrupt a working sign-in — you can add a new credential anytime. Re-run the audit afterward to refresh scores."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.get())
                error=Signal::derive(move || error.get())
                on_confirm=Callback::new(confirm)
                on_close=Callback::new(move |()| open.set(false))
            />
        </div>
    }
        .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::{CredentialStatus, RiskLevel};

    fn blank() -> AuditItem {
        AuditItem {
            application_name: "App".into(),
            app_id: "app-1".into(),
            object_id: "obj-1".into(),
            created_date: None,
            publisher: None,
            sign_in_audience: None,
            risk_score: 0,
            risk_level: RiskLevel::Low,
            issues: vec![],
            recommendations: vec![],
            remediations: vec![],
            credential_status: CredentialStatus::Active,
            permission_count: 0,
            service_principal_enabled: None,
            days_since_created: None,
            certificates: vec![],
            secrets: vec![],
            last_sign_in: None,
            unused: false,
            sign_in_report_available: false,
            principal_kind: AuditPrincipalKind::Application,
        }
    }

    fn with_issue(text: String) -> AuditItem {
        AuditItem {
            issues: vec![text],
            ..blank()
        }
    }

    #[test]
    fn target_tab_routes_each_marker_to_its_detail_tab() {
        let tab = |text: String| target_tab(&with_issue(text));
        // Mailbox/site scoping findings land on Permissions, which hosts the
        // Exchange/SharePoint scoping sections (the dedicated tabs are gone).
        assert_eq!(tab(format!("{} x", issue::ORG_WIDE_MAILBOX)), "permissions");
        assert_eq!(
            tab(format!("Mail.Read {} (Sales)", issue::SCOPED_VIA_RBAC)),
            "permissions"
        );
        assert_eq!(
            tab(format!("{} x", issue::ORG_WIDE_SHAREPOINT)),
            "permissions"
        );
        assert_eq!(
            tab(format!("{} x", issue::REDUNDANT_APP_PERMS)),
            "permissions"
        );
        assert_eq!(tab(format!("{} x", issue::NO_OWNERS)), "owners");
        let expired = AuditItem {
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        assert_eq!(target_tab(&expired), "credentials");
        assert_eq!(target_tab(&blank()), "overview");
    }
}
