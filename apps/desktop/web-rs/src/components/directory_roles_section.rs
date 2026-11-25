//! The Directory roles section (C1): a principal's direct, active Microsoft
//! Entra directory roles — tenant-wide ones listed read-only, admin-unit ones
//! with Remove — and whether each admin-unit write limit is real or voided by
//! a tenant-wide role. Mounted on the app registration's Permissions tab and
//! the enterprise-app and managed-identity panels.

use leptos::prelude::*;

use azapptoolkit_core::scoping::admin_unit::{DIRECTORY_WRITE_MAPPINGS, covers_tenant_wide};

use crate::bindings::admin_units::{self, DirectoryRoleDto, DirectoryRoleScopeDto};
use crate::components::icon::IconName;
use crate::components::ui::{DataTable, DetailLoadError, IconButton, SkeletonList};
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::no_tenant;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

/// One line per directory-write role held at an admin unit: "Writes limited
/// to <unit>", or "Not limited: also holds <role> tenant-wide" when a tenant
/// role (the same one, or Global Administrator) still covers it.
pub(crate) fn limit_lines(roles: &[DirectoryRoleDto]) -> Vec<String> {
    let mut lines = Vec::new();
    for m in DIRECTORY_WRITE_MAPPINGS {
        let units: Vec<&str> = roles
            .iter()
            .filter(|r| r.role_template_id.eq_ignore_ascii_case(m.role_template_id))
            .filter_map(|r| match &r.scope {
                DirectoryRoleScopeDto::AdminUnit { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        if units.is_empty() {
            continue;
        }
        let covering = roles.iter().find(|r| {
            matches!(r.scope, DirectoryRoleScopeDto::Tenant)
                && covers_tenant_wide(m, &r.role_template_id)
        });
        lines.push(match covering {
            Some(c) => format!(
                "{} — Not limited: also holds {} tenant-wide",
                m.role_name, c.role_name
            ),
            None => format!("{} — Writes limited to {}", m.role_name, units.join(", ")),
        });
    }
    lines
}

fn scope_label(scope: &DirectoryRoleScopeDto) -> String {
    match scope {
        DirectoryRoleScopeDto::Tenant => "Tenant".to_string(),
        DirectoryRoleScopeDto::AdminUnit { name, .. } => format!("Admin unit: {name}"),
        DirectoryRoleScopeDto::Object { .. } => "One object".to_string(),
    }
}

#[component]
pub fn DirectoryRolesSection(
    /// The service principal whose roles to list (empty = none to show).
    #[prop(into)]
    sp_object_id: Signal<String>,
) -> impl IntoView {
    let session = use_session();
    let reload = RwSignal::new(0_u32);
    let roles = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let sp = sp_object_id.get();
        let _ = reload.get();
        async move {
            if sp.is_empty() {
                return Ok(Vec::new());
            }
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            admin_units::list_directory_roles(&t.tenant_id, &sp).await
        }
    });

    let cmd = use_command().with_consent_feature("admin_unit_roles");
    // The role a Remove is pending on: (assignment id, "<role> — <unit>").
    let pending: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let confirm = move |()| {
        let Some((assignment_id, _)) = pending.get_untracked() else {
            return;
        };
        let sp = sp_object_id.get_untracked();
        cmd.run_with(
            move |()| {
                pending.set(None);
                reload.update(|n| *n += 1);
            },
            move |e| cmd.fail_inline(e),
            move |tenant| async move {
                admin_units::remove_admin_unit_role(&tenant, &sp, &assignment_id).await
            },
        );
    };

    let row = move |r: DirectoryRoleDto| -> AnyView {
        let remove = match &r.scope {
            DirectoryRoleScopeDto::AdminUnit { name, .. } => {
                let subject = format!("{} — {}", r.role_name, name);
                let id = r.assignment_id.clone();
                let aria = format!("Remove {subject}");
                Some(view! {
                    <IconButton
                        icon=IconName::Trash
                        aria_label=aria
                        title="Remove".to_string()
                        class="button--danger".to_string()
                        disabled=Signal::derive(move || cmd.busy.get())
                        on_click=Callback::new(move |_| {
                            cmd.error.set(None);
                            pending.set(Some((id.clone(), subject.clone())));
                        })
                    />
                })
            }
            _ => None,
        };
        view! {
            <tr>
                <td>{r.role_name.clone()}</td>
                <td>{scope_label(&r.scope)}</td>
                <td class="cell-mid">{remove}</td>
            </tr>
        }
        .into_any()
    };

    view! {
        <section class="directory-roles">
            <h4>"Directory roles"</h4>
            <p class="muted">
                "Microsoft Entra admin roles this app's service principal holds directly. A role limited to an admin unit reaches only the unit's members."
            </p>
            <Suspense fallback=move || view! { <SkeletonList rows=2 /> }>
                {move || Suspend::new(async move {
                    match roles.await {
                        Ok(list) => {
                            let lines = limit_lines(&list);
                            view! {
                                <DataTable
                                    headers=vec!["Role", "Scope", ""]
                                    rows=list
                                    empty_message="No directory roles."
                                    row=row
                                />
                                <ul class="member-list">
                                    {lines
                                        .into_iter()
                                        .map(|l| view! { <li>{l}</li> })
                                        .collect_view()}
                                </ul>
                            }
                                .into_any()
                        }
                        Err(e) => {
                            view! {
                                <DetailLoadError
                                    error=e
                                    on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
            <ConfirmDialog
                open=Signal::derive(move || pending.with(Option::is_some))
                title="Remove this role?"
                body="Removes the admin role from this app at this admin unit. If the app no longer holds the matching tenant-wide permission, its writes to the unit's members stop."
                subject=Signal::derive(move || {
                    pending.with(|p| p.as_ref().map(|(_, s)| s.clone()).unwrap_or_default())
                })
                confirm_label="Remove role"
                busy=Signal::derive(move || cmd.busy.get())
                error=Signal::derive(move || cmd.error.get())
                on_confirm=Callback::new(confirm)
                on_close=Callback::new(move |()| pending.set(None))
            />
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(template: &str, name: &str, scope: DirectoryRoleScopeDto) -> DirectoryRoleDto {
        DirectoryRoleDto {
            assignment_id: format!("ra-{name}"),
            role_template_id: template.into(),
            role_name: name.into(),
            scope,
        }
    }

    #[test]
    fn limit_lines_name_the_unit_or_the_covering_role() {
        let unit = DirectoryRoleScopeDto::AdminUnit {
            id: "au".into(),
            name: "Finance".into(),
        };
        let user_admin = "fe930be7-5e62-47db-91af-98c3a49a38b1";
        assert_eq!(
            limit_lines(&[role(user_admin, "User Administrator", unit.clone())]),
            vec!["User Administrator — Writes limited to Finance".to_string()]
        );
        assert_eq!(
            limit_lines(&[
                role(user_admin, "User Administrator", unit),
                role(
                    user_admin,
                    "User Administrator",
                    DirectoryRoleScopeDto::Tenant
                ),
            ]),
            vec![
                "User Administrator — Not limited: also holds User Administrator tenant-wide"
                    .to_string()
            ]
        );
        assert!(limit_lines(&[]).is_empty());
    }
}
