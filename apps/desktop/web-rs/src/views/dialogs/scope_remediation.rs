//! Guided one-click scoping remediations for the Security-audit view. Each is a
//! button + modal that turns an org-wide finding (Rule 11 mailbox / Rule 12
//! SharePoint) into a least-privilege grant, delegating to the backend
//! grant-before-strip scoping cores. Advisory only — the admin supplies the
//! groups / site URLs and confirms; nothing is scoped automatically.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Textarea};

use azapptoolkit_core::audit::RemediationAction;

use crate::bindings::remediation::{ExchangeAccessResult, SiteScopeResult};
use crate::bindings::{auth, exchange, remediation, sharepoint};
use crate::components::group_autocomplete::MailboxGroupsField;
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{Callout, FormError, Spinner};
use crate::state::use_session;
use crate::util::{count_noun, parse_lines};

/// Which principal a scope Fix targets. App-registration rows route to the
/// audit remediation wrappers (which re-resolve the application + its SP);
/// SP-only rows (foreign enterprise apps, managed identities, orphaned SPs —
/// `AuditPrincipalKind::{ServicePrincipal,ManagedIdentity}`) have no local
/// application for those wrappers to resolve, so they route to the same
/// SP-only cores the Grant-access wizard's bare-SP arms call.
#[derive(Clone, PartialEq)]
pub enum ScopeFixTarget {
    AppReg {
        object_id: String,
    },
    ServicePrincipal {
        sp_object_id: String,
        app_id: String,
        display_name: String,
    },
}

impl ScopeFixTarget {
    /// The row identity reported back through `on_done` — always the audit
    /// item's `object_id` (the app object id or the SP object id, per kind).
    fn row_id(&self) -> String {
        match self {
            ScopeFixTarget::AppReg { object_id } => object_id.clone(),
            ScopeFixTarget::ServicePrincipal { sp_object_id, .. } => sp_object_id.clone(),
        }
    }
}

/// "Scope mailbox access" remediation — confines the flagged org-wide mail
/// permissions to admin-chosen mail-enabled groups via Exchange RBAC.
#[component]
pub fn ScopeMailboxButton(
    target: ScopeFixTarget,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // Set when the grant failed on a missing Exchange admin-API consent: the
    // primary action becomes "Grant consent" (mirrors `ScopeSharePointButton`).
    let needs_consent = RwSignal::new(false);
    // A grant that came back with warnings — shown in the modal until read.
    let warned: RwSignal<Option<ExchangeAccessResult>> = RwSignal::new(None);
    let groups_text = RwSignal::new(String::new());

    let targets = action.targets.clone();
    let confirm = Callback::new(move |()| {
        if busy.get() {
            return;
        }
        let groups = parse_lines(&groups_text.get());
        if groups.is_empty() {
            error.set(Some(
                "Enter at least one mail-enabled group (one per line).".into(),
            ));
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        warned.set(None);
        let target = target.clone();
        let targets = targets.clone();
        leptos::task::spawn_local(async move {
            // Both paths share the grant-before-strip Exchange scoping core and
            // return the same `ExchangeAccessResult`; only the entry point
            // differs (manifest-resolving wrapper vs the SP-only command).
            let outcome = match &target {
                ScopeFixTarget::AppReg { object_id } => {
                    remediation::remediate_scope_mailbox_access(
                        &t.tenant_id,
                        object_id,
                        &targets,
                        &groups,
                    )
                    .await
                }
                ScopeFixTarget::ServicePrincipal {
                    sp_object_id,
                    app_id,
                    display_name,
                } => {
                    exchange::grant_managed_identity_scoped_exchange_access(
                        &t.tenant_id,
                        sp_object_id,
                        app_id,
                        display_name,
                        &targets,
                        &groups,
                        true,
                    )
                    .await
                }
            };
            // Land nothing on a switched or signed-out tenant: the task outlives
            // the dialog (`frontend-workspace.md`), and a toast here would
            // surface in whatever tenant is active now.
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(false);
                return;
            }
            match outcome {
                Ok(res) if res.warnings.is_empty() => {
                    open.set(false);
                    needs_consent.set(false);
                    session.toast_success(format!(
                        "Scoped mailbox access — removed {}. Re-run the audit to refresh scores.",
                        count_noun(
                            res.removed_entra_grants.len(),
                            "org-wide grant",
                            "org-wide grants"
                        )
                    ));
                    on_done.try_run(target.row_id());
                }
                // A warned grant stays in the modal and keeps the row's Fix:
                // the common warning ("a management scope already exists for
                // this app with a different group set") means the groups just
                // requested were NOT applied, so a success toast would read a
                // no-op as done. Same rule as the Exchange scoping section's
                // `grant_result`.
                Ok(res) => {
                    needs_consent.set(false);
                    warned.set(Some(res));
                }
                // Both entry points pre-acquire the Exchange token
                // (`exchange_client_checked`), so a missing consent arrives
                // typed, before anything was granted or stripped.
                Err(e) if e.is_consent_required() => {
                    needs_consent.set(true);
                    error.set(Some(
                        "Scoping mailbox access needs the Exchange admin-API scope (Exchange.Manage). Grant consent, then try again.".into(),
                    ));
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    let grant_consent = Callback::new(move |()| {
        if busy.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            let consent = auth::request_scope_consent(&t.tenant_id, "exchange").await;
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(false);
                return;
            }
            match consent {
                Ok(()) => {
                    needs_consent.set(false);
                    session.toast_success("Consent granted — select Scope access to continue.");
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    let label = action.label.clone();
    let detail = action.detail.clone();
    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| {
                    warned.set(None);
                    open.set(true);
                })
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ModalShell
                open=open
                title="Scope mailbox access"
                busy=busy
                on_close=Callback::new(move |()| open.set(false))
            >
                <span class="ui-text">
                    "Confine these permissions to members of specific mail-enabled groups via Exchange RBAC for Applications. The app keeps access only to those mailboxes; its org-wide grant is removed once the scoped roles are in place. You must be an Exchange administrator."
                </span>
                <p class="muted">{action.detail.clone()}</p>
                <MailboxGroupsField value=groups_text />
                {move || {
                    warned
                        .get()
                        .map(|r| {
                            let summary = format!(
                                "Scope “{}”: removed {}, but some of what you asked for may not have been applied — read the notes below.",
                                r.scope_name,
                                count_noun(r.removed_entra_grants.len(), "org-wide grant", "org-wide grants"),
                            );
                            view! {
                                <Callout tone="warn" role="status">
                                    <span class="ui-text">{summary}</span>
                                    <ul class="warnings">
                                        {r
                                            .warnings
                                            .into_iter()
                                            .map(|w| view! { <li>{w}</li> })
                                            .collect_view()}
                                    </ul>
                                </Callout>
                            }
                        })
                }}
                {move || {
                    error.get().map(|e| view! { <FormError>{e}</FormError> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| open.set(false))
                        disabled=Signal::derive(move || busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Show
                        when=move || needs_consent.get()
                        fallback=move || {
                            view! {
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| confirm.run(()))
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    {move || {
                                        if busy.get() {
                                            view! {
                                                <Spinner />
                                            }
                                                .into_any()
                                        } else {
                                            view! { "Scope access" }.into_any()
                                        }
                                    }}
                                </Button>
                            }
                        }
                    >
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| grant_consent.run(()))
                            disabled=Signal::derive(move || busy.get())
                        >
                            "Grant consent"
                        </Button>
                    </Show>
                </div>
            </ModalShell>
        </div>
    }
    .into_any()
}

/// "Restrict SharePoint access" remediation — converts the flagged org-wide
/// `Sites.*` permissions to `Sites.Selected` on admin-supplied site URLs.
#[component]
pub fn ScopeSharePointButton(
    target: ScopeFixTarget,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let needs_consent = RwSignal::new(false);
    // A conversion that came back with warnings — shown in the modal until read.
    let warned: RwSignal<Option<SiteScopeResult>> = RwSignal::new(None);
    let sites_text = RwSignal::new(String::new());

    // Performs the scope conversion for `role` ("read"/"write"). Reusable from
    // both grant buttons and the consent-retry path, so it's a Copy `Callback`.
    let do_scope = {
        let target = target.clone();
        Callback::new(move |write: bool| {
            if busy.get() {
                return;
            }
            let site_urls = parse_lines(&sites_text.get());
            if site_urls.is_empty() {
                error.set(Some("Enter at least one site URL (one per line).".into()));
                return;
            }
            let Some(t) = tenant.get() else {
                return;
            };
            busy.set(true);
            error.set(None);
            warned.set(None);
            let target = target.clone();
            let role = if write { "write" } else { "read" };
            leptos::task::spawn_local(async move {
                // Same convert-to-selected core either way, and the same
                // `SiteScopeResult`; the app-reg wrapper resolves the SP from
                // the application first, the SP-only path supplies it directly.
                let outcome = match &target {
                    ScopeFixTarget::AppReg { object_id } => {
                        remediation::remediate_scope_sharepoint_access(
                            &t.tenant_id,
                            object_id,
                            &site_urls,
                            role,
                        )
                        .await
                    }
                    ScopeFixTarget::ServicePrincipal {
                        sp_object_id,
                        app_id,
                        display_name,
                    } => {
                        sharepoint::convert_site_access_to_selected(
                            &t.tenant_id,
                            sp_object_id,
                            // SP-only target: no app registration exists to declare
                            // Sites.Selected on, so the assignment is the whole fix.
                            None,
                            app_id,
                            display_name,
                            &site_urls,
                            role,
                            true,
                        )
                        .await
                    }
                };
                if !session.is_active_tenant(&t.tenant_id) {
                    busy.set(false);
                    return;
                }
                match outcome {
                    Ok(res) if res.warnings.is_empty() => {
                        open.set(false);
                        needs_consent.set(false);
                        session.toast_success(format!(
                            "Restricted SharePoint access to {} — removed {}. Re-run the audit to refresh scores.",
                            count_noun(res.sites_granted.len(), "site", "sites"),
                            count_noun(
                                res.removed_orgwide_grants.len(),
                                "org-wide grant",
                                "org-wide grants"
                            ),
                        ));
                        on_done.try_run(target.row_id());
                    }
                    // A warned conversion stays in the modal and keeps the
                    // row's Fix, as a warned mailbox grant does: the warnings
                    // include "Scoping is NOT effective" (the app still reaches
                    // every site or file through a grant the conversion does not
                    // remove) and "no site access was granted, so the org-wide
                    // grant was left in place". A success toast here retired the
                    // Fix on an app that was still org-wide.
                    Ok(res) => {
                        needs_consent.set(false);
                        warned.set(Some(res));
                    }
                    // The error's own message, never a SharePoint-scope prompt:
                    // `consent_required` comes from the SharePoint pre-acquire
                    // AND from the Graph write scope the Sites.Selected grant
                    // rides, and the code does not say which. "Grant consent"
                    // still grants the SharePoint scope — right for the first,
                    // no help for the second, which this message names.
                    Err(e) => {
                        needs_consent.set(e.is_consent_required());
                        error.set(Some(e.message));
                    }
                }
                busy.set(false);
            });
        })
    };

    let grant_consent = Callback::new(move |()| {
        if busy.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            let consent = auth::request_scope_consent(&t.tenant_id, "sharepoint").await;
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(false);
                return;
            }
            match consent {
                Ok(()) => {
                    needs_consent.set(false);
                    session.toast_success("Consent granted — choose Read or Write to continue.");
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    let label = action.label.clone();
    let detail = action.detail.clone();
    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| {
                    warned.set(None);
                    open.set(true);
                })
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ModalShell
                open=open
                title="Restrict SharePoint access to selected sites"
                busy=busy
                on_close=Callback::new(move |()| open.set(false))
            >
                <span class="ui-text">
                    "Convert this app's org-wide SharePoint access to the Sites.Selected model — access only to the sites you list below. The org-wide grant is removed once at least one site grant lands. You must be a SharePoint administrator or site owner."
                </span>
                <p class="muted">{action.detail.clone()}</p>
                <label>
                    <span class="visually-hidden">"Site URLs, one per line"</span>
                    <Textarea
                        value=sites_text
                        placeholder="Site URLs — one per line (e.g. https://contoso.sharepoint.com/sites/Marketing)"
                    />
                </label>
                {move || {
                    warned
                        .get()
                        .map(|r| {
                            let summary = format!(
                                "Granted {} and removed {}. Read the notes below: they say what did not happen, or what the app can still reach.",
                                count_noun(r.sites_granted.len(), "site", "sites"),
                                count_noun(r.removed_orgwide_grants.len(), "org-wide grant", "org-wide grants"),
                            );
                            view! {
                                <Callout tone="warn" role="status">
                                    <span class="ui-text">{summary}</span>
                                    <ul class="warnings">
                                        {r
                                            .warnings
                                            .into_iter()
                                            .map(|w| view! { <li>{w}</li> })
                                            .collect_view()}
                                    </ul>
                                </Callout>
                            }
                        })
                }}
                {move || {
                    error.get().map(|e| view! { <FormError>{e}</FormError> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| open.set(false))
                        disabled=Signal::derive(move || busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Show
                        when=move || needs_consent.get()
                        fallback=move || {
                            // Read is the Primary (and, by this row's
                            // convention, last) button: this is a
                            // least-privilege remediation, so the
                            // emphasized default must not be the
                            // broader role. An operator working down a
                            // findings list at speed clicks the primary
                            // — which used to hand out write. The two
                            // equivalent paths already default to read
                            // (the wizard's `SiteSelectionPanel` starts
                            // `write=false`; the bulk bar's checkbox is
                            // labelled "default: read"; the SharePoint
                            // site access section's "Grant read" is its
                            // Primary), so this also stops the four
                            // surfaces disagreeing.
                            view! {
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(move |_| do_scope.run(true))
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    "Grant write access"
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| do_scope.run(false))
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    "Grant read access"
                                </Button>
                            }
                        }
                    >
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| grant_consent.run(()))
                            disabled=Signal::derive(move || busy.get())
                        >
                            "Grant consent"
                        </Button>
                    </Show>
                </div>
            </ModalShell>
        </div>
    }
    .into_any()
}

/// Rule 26's Fix: limit a tenant-wide directory write to an admin unit. Picks
/// (or creates) the unit, shows what the role also allows and what the app
/// can no longer do, then runs the same core as the wizard. Anything kept, or
/// a covering tenant-wide role, stays in the modal and keeps the row's Fix.
#[component]
pub fn ScopeDirectoryWriteButton(
    target: ScopeFixTarget,
    /// The audit row's appId: an app registration's service principal is
    /// resolved from it.
    app_id: String,
    action: RemediationAction,
    /// One write was limited: `(row, value)`. The audit view drops it from
    /// this row's Fix (and the Fix once none is left), so a remount keeps it.
    #[prop(into)]
    on_limited: Callback<(String, String)>,
) -> impl IntoView {
    use crate::bindings::admin_units::{self, AdminUnitDto, ScopeDirectoryWriteArgs};
    use crate::components::admin_unit_panel::{AdminUnitPanel, DirectoryWriteDisclosures};
    use crate::components::ui::Select;
    use crate::hooks::use_command::use_command;
    use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
    use azapptoolkit_core::scoping::admin_unit::directory_write_mapping;

    let session = use_session();
    let open = RwSignal::new(false);
    let cmd = use_command().with_consent_feature("admin_unit_roles");
    let permission = RwSignal::new(action.targets.first().cloned().unwrap_or_default());
    let unit: RwSignal<Option<AdminUnitDto>> = RwSignal::new(None);
    let created_now = RwSignal::new(false);
    let warned: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    // A write limited while notes are on screen: handed to the audit view
    // when the modal closes (that rebuilds the row, which would take the
    // notes with it).
    let pending: RwSignal<Option<String>> = RwSignal::new(None);
    let targets = action.targets.clone();
    let others = targets.len().saturating_sub(1);
    let member_kind = Signal::derive(move || {
        permission.with(|p| {
            directory_write_mapping(Some(MICROSOFT_GRAPH_APP_ID), p).map(|m| m.member_kind)
        })
    });
    let disclosed = Signal::derive(move || Some(permission.get()).filter(|p| !p.is_empty()));
    let row_id = target.row_id();

    let apply = {
        let target = target.clone();
        let app_id = app_id.clone();
        let row_id = row_id.clone();
        Callback::new(move |_: ()| {
            let Some(u) = unit.get_untracked() else {
                cmd.error
                    .set(Some("Pick an admin unit, or create one.".into()));
                return;
            };
            let value = permission.get_untracked();
            let value_done = value.clone();
            let created = created_now.get_untracked();
            let (sp, object_id) = match &target {
                ScopeFixTarget::AppReg { object_id } => (None, Some(object_id.clone())),
                ScopeFixTarget::ServicePrincipal { sp_object_id, .. } => {
                    (Some(sp_object_id.clone()), None)
                }
            };
            let app_id = app_id.clone();
            let row_id = row_id.clone();
            cmd.run_with(
                move |r: admin_units::DirectoryWriteScopeResult| {
                    // The tenant-wide write is gone: that permission is done,
                    // whatever the notes say.
                    let landed = r.orgwide_removed && r.kept_reason.is_none();
                    let mut notes: Vec<String> = Vec::new();
                    notes.extend(r.kept_reason.clone());
                    if let Some(c) = &r.covering_role {
                        notes.push(format!(
                            "The app also holds {c} tenant-wide, so its writes still reach everyone. Remove that role to make the limit real."
                        ));
                    }
                    notes.extend(r.warnings.clone());
                    if notes.is_empty() {
                        open.set(false);
                        session.toast_success(if others == 0 {
                            format!(
                                "Writes limited to {}. Re-run the audit to refresh scores.",
                                u.display_name
                            )
                        } else {
                            format!(
                                "{value_done} limited to {}; {} still need{} a unit.",
                                u.display_name,
                                count_noun(others, "permission", "permissions"),
                                if others == 1 { "s" } else { "" }
                            )
                        });
                        if landed {
                            on_limited.try_run((row_id, value_done));
                        }
                    } else {
                        if landed {
                            pending.set(Some(value_done));
                        }
                        warned.set(notes);
                    }
                },
                move |e| cmd.fail_inline(e),
                move |tenant| async move {
                    admin_units::scope_directory_write(ScopeDirectoryWriteArgs {
                        tenant_id: &tenant,
                        sp_object_id: sp.as_deref(),
                        object_id: object_id.as_deref(),
                        app_id: &app_id,
                        permission_value: &value,
                        admin_unit_id: &u.id,
                        created_now: created,
                        require_held: true,
                    })
                    .await
                },
            );
        })
    };

    let label = action.label.clone();
    let detail = action.detail.clone();
    // Closing hands over a write limited while notes were showing.
    let close = {
        let row_id = row_id.clone();
        Callback::new(move |()| {
            open.set(false);
            if let Some(v) = pending.get_untracked() {
                pending.set(None);
                on_limited.run((row_id.clone(), v));
            }
        })
    };

    view! {
        <div class="audit-actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new({
                    let first = targets.first().cloned().unwrap_or_default();
                    move |_| {
                        // A fresh open: no unit, nothing "just created", no
                        // notes from the last run.
                        cmd.error.set(None);
                        warned.set(Vec::new());
                        unit.set(None);
                        created_now.set(false);
                        permission.set(first.clone());
                        open.set(true);
                    }
                })
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ModalShell
                open=open
                title="Limit writes to an admin unit"
                busy=cmd.busy
                on_close=close
            >
                {(targets.len() > 1)
                    .then(|| {
                        let options = targets.clone();
                        {
                            view! {
                                <Select value=permission label="Permission">
                                    {options
                                        .into_iter()
                                        .map(|t| {
                                            let label = t.clone();
                                            view! { <option value=t>{label}</option> }
                                        })
                                        .collect_view()}
                                </Select>
                            }
                        }
                    })}
                <AdminUnitPanel member_kind=member_kind selected=unit created_now=created_now />
                <DirectoryWriteDisclosures permission=disclosed />
                {move || {
                    let notes = warned.get();
                    (!notes.is_empty())
                        .then(|| {
                            view! {
                                <Callout tone="warn">
                                    <ul class="member-list">
                                        {notes
                                            .into_iter()
                                            .map(|n| view! { <li>{n}</li> })
                                            .collect_view()}
                                    </ul>
                                </Callout>
                            }
                        })
                }}
                {move || cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        disabled=Signal::derive(move || cmd.busy.get())
                        on_click=Box::new(move |_| close.run(()))
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        disabled=Signal::derive(move || cmd.busy.get() || unit.with(Option::is_none))
                        on_click=Box::new(move |_| apply.run(()))
                    >
                        "Limit writes"
                    </Button>
                    {move || cmd.busy.get().then(|| view! { <Spinner /> })}
                </div>
            </ModalShell>
        </div>
    }
}
