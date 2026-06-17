//! Guided one-click scoping remediations for the Security-audit view. Each is a
//! button + modal that turns an org-wide finding (Rule 11 mailbox / Rule 12
//! SharePoint) into a least-privilege grant, delegating to the backend
//! grant-before-strip scoping cores. Advisory only — the admin supplies the
//! groups / site URLs and confirms; nothing is scoped automatically.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize, Textarea};

use azapptoolkit_core::audit::RemediationAction;

use crate::bindings::{auth, remediation};
use crate::components::group_autocomplete::GroupAutocomplete;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;
use crate::util::parse_lines;

/// "Scope mailbox access" remediation — confines the flagged org-wide mail
/// permissions to admin-chosen mail-enabled groups via Exchange RBAC.
#[component]
pub fn ScopeMailboxButton(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
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
        let object_id = object_id.clone();
        let targets = targets.clone();
        leptos::task::spawn_local(async move {
            match remediation::remediate_scope_mailbox_access(
                &t.tenant_id,
                &object_id,
                &targets,
                &groups,
            )
            .await
            {
                Ok(res) => {
                    open.set(false);
                    let removed = res.removed_entra_grants.len();
                    let warn = if res.warnings.is_empty() {
                        String::new()
                    } else {
                        format!(" ({} warning(s))", res.warnings.len())
                    };
                    session.toast_success(format!(
                        "Scoped mailbox access — removed {removed} org-wide grant(s){warn}. Re-run the audit to refresh scores."
                    ));
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || open.set(false),
    );
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open.into());

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
            <Show when=move || open.get() fallback=|| view! { <></> }>
                <div
                    class="modal-backdrop"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="scope-mailbox-dialog-title"
                >
                    <div class="modal" node_ref=modal_ref>
                        <h3 id="scope-mailbox-dialog-title">"Scope mailbox access"</h3>
                        <Body1>
                            "Confine these permissions to members of specific mail-enabled groups via Exchange RBAC for Applications. The app keeps access only to those mailboxes; its org-wide grant is removed once the scoped roles are in place. You must be an Exchange administrator."
                        </Body1>
                        <p class="muted">{action.detail.clone()}</p>
                        <GroupAutocomplete target=groups_text />
                        <Textarea
                            value=groups_text
                            placeholder="Mail-enabled groups — one per line (name, address, or object id)"
                        />
                        {move || {
                            error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                        }}
                        <div class="actions-row">
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                on_click=Box::new(move |_| open.set(false))
                                disabled=Signal::derive(move || busy.get())
                            >
                                "Cancel"
                            </Button>
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(move |_| confirm.run(()))
                                disabled=Signal::derive(move || busy.get())
                            >
                                {move || {
                                    if busy.get() {
                                        view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                            .into_any()
                                    } else {
                                        view! { "Scope access" }.into_any()
                                    }
                                }}
                            </Button>
                        </div>
                    </div>
                </div>
            </Show>
        </div>
    }
    .into_any()
}

/// "Restrict SharePoint access" remediation — converts the flagged org-wide
/// `Sites.*` permissions to `Sites.Selected` on admin-supplied site URLs.
#[component]
pub fn ScopeSharePointButton(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let needs_consent = RwSignal::new(false);
    let sites_text = RwSignal::new(String::new());

    // Performs the scope conversion for `role` ("read"/"write"). Reusable from
    // both grant buttons and the consent-retry path, so it's a Copy `Callback`.
    let do_scope = {
        let object_id = object_id.clone();
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
            let object_id = object_id.clone();
            let role = if write { "write" } else { "read" };
            leptos::task::spawn_local(async move {
                match remediation::remediate_scope_sharepoint_access(
                    &t.tenant_id,
                    &object_id,
                    &site_urls,
                    role,
                )
                .await
                {
                    Ok(res) => {
                        open.set(false);
                        needs_consent.set(false);
                        let removed = res.removed_orgwide_grants.len();
                        session.toast_success(format!(
                            "Restricted SharePoint access to {} site(s) — removed {removed} org-wide grant(s). Re-run the audit to refresh scores.",
                            res.sites_granted.len()
                        ));
                        on_done.run(object_id);
                    }
                    Err(e) if e.code == "consent_required" => {
                        needs_consent.set(true);
                        error.set(Some(
                            "Granting per-site access needs the SharePoint admin scope (Sites.FullControl.All). Grant consent, then try again.".into(),
                        ));
                    }
                    Err(e) => error.set(Some(e.message)),
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
            match auth::request_scope_consent(&t.tenant_id, "sharepoint").await {
                Ok(()) => {
                    needs_consent.set(false);
                    session.toast_success("Consent granted — choose Read or Write to continue.");
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || open.set(false),
    );
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open.into());

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
            <Show when=move || open.get() fallback=|| view! { <></> }>
                <div
                    class="modal-backdrop"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="scope-sharepoint-dialog-title"
                >
                    <div class="modal" node_ref=modal_ref>
                        <h3 id="scope-sharepoint-dialog-title">
                            "Restrict SharePoint access to selected sites"
                        </h3>
                        <Body1>
                            "Convert this app's org-wide SharePoint access to the Sites.Selected model — access only to the sites you list below. The org-wide grant is removed once at least one site grant lands. You must be a SharePoint administrator or site owner."
                        </Body1>
                        <p class="muted">{action.detail.clone()}</p>
                        <Textarea
                            value=sites_text
                            placeholder="Site URLs — one per line (e.g. https://contoso.sharepoint.com/sites/Marketing)"
                        />
                        {move || {
                            error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
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
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| do_scope.run(false))
                                            disabled=Signal::derive(move || busy.get())
                                        >
                                            "Grant read access"
                                        </Button>
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(move |_| do_scope.run(true))
                                            disabled=Signal::derive(move || busy.get())
                                        >
                                            "Grant write access"
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
                    </div>
                </div>
            </Show>
        </div>
    }
    .into_any()
}
