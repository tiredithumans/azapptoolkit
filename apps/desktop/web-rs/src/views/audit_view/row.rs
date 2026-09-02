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
use crate::views::dialogs::migrate_legacy_scope::MigrateLegacyScopeButton;
use crate::views::dialogs::scope_remediation::{
    ScopeFixTarget, ScopeMailboxButton, ScopeSharePointButton,
};

use super::groups::{GroupSpec, group_remediation_kinds};

/// Which detail-pane tab this row's "Open" deep-link lands on.
///
/// Under a finding section, the section decides (`GroupSpec::tab`): the
/// operator opened *that* finding, so Open must land where *it* is acted on —
/// otherwise Open from "Expired credentials" landed on Permissions, because the
/// item-wide scan below ranks a scoping finding the same app also tripped
/// above the credential one. Without a section (the ungrouped All-apps pane)
/// the row stands for the whole app, so the scan picks its most actionable tab.
///
/// Which *pane* opens follows `principal_kind`; the managed-identity pane has
/// only Overview and Permissions, so anything else is clamped to Overview
/// rather than deep-linking a tab that pane never renders.
fn target_tab(item: &AuditItem, section: Option<&GroupSpec>) -> &'static str {
    let tab = match section {
        Some(spec) => spec.tab,
        None => scan_item_for_tab(item),
    };
    if item.principal_kind == AuditPrincipalKind::ManagedIdentity
        && !matches!(tab, "overview" | "permissions")
    {
        return "overview";
    }
    tab
}

/// The item-wide fallback: the most actionable tab across *every* finding this
/// item tripped (mailbox/site scoping and risky perms → Permissions, which
/// hosts the Exchange/SharePoint scoping sections; ownership → Owners; expiry →
/// Credentials), falling back to Overview.
fn scan_item_for_tab(item: &AuditItem) -> &'static str {
    use azapptoolkit_core::audit::CredentialStatus;
    let has = |p: &str| item.issues.iter().any(|x| x.starts_with(p));
    if has(issue::ORG_WIDE_MAILBOX)
        || item
            .issues
            .iter()
            .any(|x| x.contains(issue::SCOPED_VIA_RBAC))
        // The Permissions tab hosts the Exchange scoping section, which is where
        // a legacy policy is managed by hand once the operator wants more than
        // the one-click migration.
        || has(issue::LEGACY_MAILBOX_POLICY)
        // The two "cannot be confined here" markers carry no one-click Fix, so
        // the Permissions tab — where the grant itself is removed or
        // re-declared on the confinable resource — is the only place to act.
        || has(issue::UNCONFINABLE_MAILBOX)
        || has(issue::UNCONFINABLE_SHAREPOINT)
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

/// The action for `kind`, if the item carries one AND this surface is allowed to
/// offer that kind. `kinds = None` means "no rule context" — the All-apps pane,
/// whose row stands for the whole application, so every attached Fix shows.
/// Under a finding group it is `Some(group_remediation_kinds(key))`, which keeps
/// a section to the Fix for its own rule.
fn pick(
    item: &AuditItem,
    kinds: Option<&[RemediationKind]>,
    kind: RemediationKind,
) -> Option<RemediationAction> {
    if kinds.is_some_and(|allowed| !allowed.contains(&kind)) {
        return None;
    }
    item.remediations.iter().find(|r| r.kind == kind).cloned()
}

/// Per-row actions for an audit finding. Always renders an "Open" deep-link into
/// the app's detail pane (turning the audit from a dead-end table into a
/// launchpad), followed by the one-click remediations the scorer attached that
/// this surface owns: remove-expired-credentials (a confirm dialog naming the
/// credentials) and the scoping fixes (guided group/site modals). On success
/// each fires `on_done` with its OWN kind, so the parent drops just that
/// remediation — the
/// button disappears for good (surviving facet/search changes) while the row's
/// other Fixes, which nothing has fixed yet, stay put. The audit cache is
/// busted server-side, so a re-run reflects the new scores.
#[component]
pub(super) fn AuditRowActions(
    item: AuditItem,
    /// The finding section rendering this row. It decides both which Fixes
    /// show (its own rule's) and where "Open" lands — a row listed under
    /// several sections must not offer, or deep-link to, a sibling's finding.
    /// Omitted by the All-apps pane, which is not grouped by rule: there the
    /// row stands for the whole app and offers everything it carries.
    #[prop(optional)]
    section: Option<&'static GroupSpec>,
    #[prop(into)] on_done: Callback<(String, RemediationKind)>,
) -> impl IntoView {
    let session = use_session();
    // Each button reports the kind it fixed, so `on_done` can clear that one
    // remediation instead of the row's whole set.
    let done = move |kind: RemediationKind| {
        Callback::new(move |row_id: String| on_done.run((row_id, kind)))
    };
    let kinds = section.map(|s| group_remediation_kinds(s.key));
    let find = |k: RemediationKind| pick(&item, kinds, k);
    let expired = find(RemediationKind::RemoveExpiredCredentials);
    let redundant = find(RemediationKind::RemoveRedundantPermissions);
    let mailbox = find(RemediationKind::ScopeMailboxAccess);
    let migrate = find(RemediationKind::MigrateApplicationAccessPolicy);
    let sharepoint = find(RemediationKind::ScopeSharePointAccess);
    let add_owner = find(RemediationKind::AddOwner);
    let disable = find(RemediationKind::DisableSignIn);

    let tab = target_tab(&item, section);
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
    // The legacy-policy migration is keyed on the **appId** (a policy names the
    // application, not a directory object), and works from granted roles — so it
    // needs no `ScopeFixTarget` split: one call serves an app registration, a
    // foreign enterprise app and a managed identity alike. `row_id` stays the
    // audit row's object id so `on_done` clears the right row.
    let app_id_migrate = item.app_id.clone();
    let oid_migrate = object_id.clone();
    // Disabling sign-in changes the app itself, so its confirm dialog names the
    // app rather than a credential or permission list (see `DisableSignInAction`).
    let app_name_disable = item.application_name.clone();
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
                        <ExpiredCredsAction
                            object_id=object_id.clone()
                            action=action
                            on_done=done(RemediationKind::RemoveExpiredCredentials)
                        />
                    }
                })}
            {redundant
                .map(|action| {
                    view! {
                        <RedundantPermsAction
                            object_id=oid_r.clone()
                            action=action
                            on_done=done(RemediationKind::RemoveRedundantPermissions)
                        />
                    }
                })}
            {mailbox
                .map(|action| {
                    view! {
                        <ScopeMailboxButton
                            target=target_m.clone()
                            action=action
                            on_done=done(RemediationKind::ScopeMailboxAccess)
                        />
                    }
                })}
            {migrate
                .map(|action| {
                    view! {
                        <MigrateLegacyScopeButton
                            app_id=app_id_migrate.clone()
                            row_id=oid_migrate.clone()
                            action=action
                            on_done=done(RemediationKind::MigrateApplicationAccessPolicy)
                        />
                    }
                })}
            {sharepoint
                .map(|action| {
                    view! {
                        <ScopeSharePointButton
                            target=target_s.clone()
                            action=action
                            on_done=done(RemediationKind::ScopeSharePointAccess)
                        />
                    }
                })}
            {add_owner
                .map(|action| {
                    view! {
                        <AddOwnerButton
                            object_id=oid_owner.clone()
                            action=action
                            on_done=done(RemediationKind::AddOwner)
                        />
                    }
                })}
            {disable
                .map(|action| {
                    view! {
                        <DisableSignInAction
                            object_id=oid_disable.clone()
                            app_name=app_name_disable.clone()
                            action=action
                            on_done=done(RemediationKind::DisableSignIn)
                        />
                    }
                })}
        </div>
    }
}

/// The disable-sign-in fix for an unused app: a button gated by a confirm
/// dialog naming the app. Sets `accountEnabled: false` on the app's service
/// principal — reversible any time from the enterprise app's Overview toggle,
/// which is why a plain confirm (no typed keyword) suffices.
#[component]
fn DisableSignInAction(
    object_id: String,
    /// The dialog's subject. Its siblings pass `action.detail`, which names the
    /// credentials or permissions they remove; this action changes the *app*, so
    /// the app is what the dialog has to name. `detail` here is a rationale
    /// ("No recent sign-in activity…") the body already covers, and
    /// `ConfirmDialog::subject` is documented as the object being affected.
    app_name: String,
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
                // The modal covers the row it was opened from, and every unused
                // app's dialog is otherwise identical.
                subject=app_name
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

/// The remove-redundant-permissions fix: a button gated by a confirm dialog
/// that names the narrower permissions (the same string previewed in-row). The
/// backend re-plans against the live manifest + grants, so the toast reports
/// what was actually removed/skipped.
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
    // The modal covers the row it was opened from, so it names the permissions
    // itself rather than pointing at a column it is sitting on top of.
    let subject = action.detail.clone();

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
                body="Removes these narrower permissions — a broader permission this app also holds already grants the same access, so its calls keep working. Each removal is re-checked against the live grants first; a permission whose covering grant has since been revoked or scoped is skipped. Re-run the audit afterward to refresh scores."
                subject=subject
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

/// The remove-expired-credentials fix: a button gated by a confirm dialog that
/// names the specific credentials (the same string previewed in-row).
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
    // The modal covers the in-row preview naming these credentials, so it
    // restates them: without it an app with six expired secrets showed six
    // identical dialogs.
    let subject = action.detail.clone();

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
                body="Permanently removes this app's expired secrets and certificates. Expired credentials can't authenticate, so removing them won't disrupt a working sign-in — you can add a new credential anytime. Re-run the audit afterward to refresh scores."
                subject=subject
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

    fn action(kind: RemediationKind) -> RemediationAction {
        RemediationAction {
            kind,
            label: format!("{kind:?}"),
            detail: String::new(),
            targets: Vec::new(),
        }
    }

    /// An item scored under several rules carries a Fix per rule and is listed
    /// under each of their sections. Without the `kinds` gate, the legacy-policy
    /// section rendered the expired-credentials button too — and firing it
    /// cleared the migration Fix the operator went there for.
    #[test]
    fn pick_offers_only_the_kinds_the_surface_owns() {
        let item = AuditItem {
            remediations: vec![
                action(RemediationKind::RemoveExpiredCredentials),
                action(RemediationKind::MigrateApplicationAccessPolicy),
            ],
            ..blank()
        };
        let legacy_only: &[RemediationKind] = &[RemediationKind::MigrateApplicationAccessPolicy];

        assert!(
            pick(
                &item,
                Some(legacy_only),
                RemediationKind::MigrateApplicationAccessPolicy
            )
            .is_some()
        );
        assert!(
            pick(
                &item,
                Some(legacy_only),
                RemediationKind::RemoveExpiredCredentials
            )
            .is_none(),
            "a section must not render a sibling rule's Fix"
        );
        // An advisory section owns nothing: "Open" only, even on a row that
        // carries fixes for other rules.
        assert!(pick(&item, Some(&[]), RemediationKind::RemoveExpiredCredentials).is_none());
        // No rule context (the All-apps pane) → every attached Fix.
        assert!(pick(&item, None, RemediationKind::RemoveExpiredCredentials).is_some());
        assert!(pick(&item, None, RemediationKind::MigrateApplicationAccessPolicy).is_some());
        // Owning a kind the item never carried still renders nothing.
        assert!(
            pick(
                &item,
                Some(&[RemediationKind::AddOwner]),
                RemediationKind::AddOwner
            )
            .is_none()
        );
    }

    /// Ungrouped (All-apps) routing: the item-wide scan.
    #[test]
    fn target_tab_routes_each_marker_to_its_detail_tab() {
        let tab = |text: String| target_tab(&with_issue(text), None);
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
        assert_eq!(target_tab(&expired, None), "credentials");
        assert_eq!(target_tab(&blank(), None), "overview");
    }

    fn spec(key: &str) -> &'static GroupSpec {
        super::super::groups::GROUP_CATALOG
            .iter()
            .find(|s| s.key == key)
            .unwrap_or_else(|| panic!("no group {key}"))
    }

    /// From a section, Open lands on THAT finding's tab. The item-wide scan
    /// ranks a scoping finding above a credential one, so an app tripping both
    /// opened on Permissions even from the Expired-credentials section.
    #[test]
    fn section_decides_the_tab_over_the_item_wide_scan() {
        let both = AuditItem {
            issues: vec![format!("{}: Mail.Read", issue::LEGACY_MAILBOX_POLICY)],
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        assert_eq!(target_tab(&both, None), "permissions", "scan ranks scoping");
        assert_eq!(target_tab(&both, Some(spec("expired"))), "credentials");
        assert_eq!(
            target_tab(&both, Some(spec("legacy_mailbox_scope"))),
            "permissions"
        );
        // A section pins its tab even for a row carrying no other finding — the
        // scan would have said "overview".
        assert_eq!(target_tab(&blank(), Some(spec("ownership"))), "owners");
        assert_eq!(target_tab(&blank(), Some(spec("unused"))), "overview");
    }

    /// The managed-identity pane renders Overview, Permissions and Azure RBAC
    /// only. Deep-linking it to "owners"/"credentials" leaves the pane's tab
    /// body empty — no `keep_alive` branch matches — so those clamp.
    #[test]
    fn managed_identity_rows_never_deep_link_a_tab_that_pane_lacks() {
        let mi = AuditItem {
            principal_kind: AuditPrincipalKind::ManagedIdentity,
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        assert_eq!(target_tab(&mi, Some(spec("ownership"))), "overview");
        assert_eq!(target_tab(&mi, Some(spec("expired"))), "overview");
        // The two tabs it does have pass through untouched.
        assert_eq!(
            target_tab(&mi, Some(spec("orgwide_mailbox"))),
            "permissions"
        );
        assert_eq!(target_tab(&mi, Some(spec("no_local_app"))), "overview");
        // Same clamp on the ungrouped path.
        assert_eq!(target_tab(&mi, None), "overview");
        // An enterprise-app row keeps them — that pane has both.
        let sp = AuditItem {
            principal_kind: AuditPrincipalKind::ServicePrincipal,
            ..blank()
        };
        assert_eq!(target_tab(&sp, Some(spec("ownership"))), "owners");
    }
}
