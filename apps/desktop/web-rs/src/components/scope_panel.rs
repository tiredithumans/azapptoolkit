//! Shared inline "scope an application permission" form. The managed-identity
//! detail and the app-registration Permissions tab built this twice, near
//! identically — an Exchange variant (confine mail/calendar/contacts to
//! mail-enabled groups via RBAC) and a SharePoint variant (confine `Sites.*` to
//! a single site via `Sites.Selected`). This is **pure presentation + wiring**:
//! the caller owns the form signals and the actual grant calls (passed as
//! callbacks), so the backend grant-before-strip logic is unchanged — only the
//! form markup is shared.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Textarea};

use crate::components::group_autocomplete::GroupAutocomplete;
use crate::components::requires_role::RequiresRole;

/// Which scoping model a "Scope…" action drives. The classifier that decides
/// this differs by call site (new-grant vs restrict-existing treat
/// `Sites.Selected` differently), so each caller computes it with its own helper
/// and passes the result in — this enum is shared, the classifiers are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// Mail/calendar/contacts → confine to mailbox group(s) via Exchange RBAC.
    Exchange,
    /// `Sites.*` → confine to a specific site via `Sites.Selected`.
    SharePoint,
}

#[component]
pub fn ScopePanel(
    kind: ScopeKind,
    #[prop(into)] permission_value: String,
    /// Free-text mail-enabled groups (Exchange variant).
    groups_text: RwSignal<String>,
    /// Site URL (SharePoint variant).
    site_url: RwSignal<String>,
    #[prop(into)] busy: Signal<bool>,
    /// Confine the permission to the entered mailbox groups.
    on_submit_exchange: Callback<()>,
    /// Grant per-site access; the arg is `write` (`true`) vs read (`false`).
    on_submit_sharepoint: Callback<bool>,
    on_cancel: Callback<()>,
    /// Grant-flow only: when set, shows a "Grant org-wide instead" fallback
    /// (the scope-first new-grant path; absent for restrict-after-the-fact).
    #[prop(optional, into)]
    on_orgwide: Option<Callback<()>>,
) -> impl IntoView {
    let orgwide_btn = on_orgwide.map(|cb| {
        view! {
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| cb.run(()))
                disabled=busy
            >
                "Grant org-wide instead"
            </Button>
        }
    });
    let cancel = view! {
        <Button
            appearance=Signal::derive(|| ButtonAppearance::Subtle)
            on_click=Box::new(move |_| on_cancel.run(()))
        >
            "Cancel"
        </Button>
    };
    match kind {
        ScopeKind::Exchange => view! {
            <div class="mi-scope-panel">
                <Body1>{format!("Scope “{permission_value}” to specific mailboxes")}</Body1>
                <GroupAutocomplete target=groups_text />
                <Textarea value=groups_text placeholder="hr-team@contoso.com\nFinanceMailboxes" />
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| on_submit_exchange.run(()))
                        disabled=busy
                    >
                        "Scope to mailboxes"
                    </Button>
                    {orgwide_btn}
                    {cancel}
                </div>
                <Body1 class="hint">
                    "Uses Exchange RBAC for Applications: builds a management scope from these groups, assigns the scoped role, and removes the org-wide Entra grant so access is confined to them."
                </Body1>
                <RequiresRole capability_key="exchange_rbac" />
            </div>
        }
        .into_any(),
        ScopeKind::SharePoint => view! {
            <div class="mi-scope-panel">
                <Body1>
                    {format!("Restrict “{permission_value}” to a specific site (Sites.Selected)")}
                </Body1>
                <Input
                    value=site_url
                    placeholder="https://contoso.sharepoint.com/sites/Marketing"
                />
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| on_submit_sharepoint.run(false))
                        disabled=busy
                    >
                        "Grant read access"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| on_submit_sharepoint.run(true))
                        disabled=busy
                    >
                        "Grant write access"
                    </Button>
                    {orgwide_btn}
                    {cancel}
                </div>
                <Body1 class="hint">
                    "Grants the Sites.Selected app role and read/write access to just this site, then removes any org-wide Sites.* grant so access is confined to it."
                </Body1>
                <RequiresRole capability_key="sharepoint_sites_selected" />
            </div>
        }
        .into_any(),
    }
}
