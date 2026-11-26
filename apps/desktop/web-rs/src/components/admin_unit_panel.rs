//! Target panel for admin-unit scoping (C1): pick an existing administrative
//! unit, or create one whose members come from a dynamic rule. Shared by the
//! Grant access wizard and the audit's Scope fix. The caller owns the
//! selection and runs the apply.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Field, Input, Textarea};

use azapptoolkit_core::scoping::admin_unit::{AdminUnitMemberKind, UserRuleAttribute, user_rule};

use crate::bindings::admin_units::{self, AdminUnitDto};
use crate::components::ui::{DetailLoadError, FormError, Select, SkeletonList, Spinner};
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::no_tenant;

/// Whether a unit can hold members of `kind` (dynamic rules add users or
/// devices, never groups).
fn unit_can_hold(unit: &AdminUnitDto, kind: Option<AdminUnitMemberKind>) -> bool {
    !(unit.dynamic && kind == Some(AdminUnitMemberKind::Group))
}

#[component]
pub fn AdminUnitPanel(
    /// What the unit must contain for the role to reach anything.
    #[prop(into)]
    member_kind: Signal<Option<AdminUnitMemberKind>>,
    /// The unit picked or created.
    selected: RwSignal<Option<AdminUnitDto>>,
    /// The selected unit was created in this run (its members are still being
    /// calculated).
    created_now: RwSignal<bool>,
) -> impl IntoView {
    let session = use_session();
    let reload = RwSignal::new(0_u32);
    let units = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            admin_units::list_admin_units(&t.tenant_id).await
        }
    });

    let cmd = use_command().with_consent_feature("admin_unit_roles");
    let name = RwSignal::new(String::new());
    let attribute = RwSignal::new(UserRuleAttribute::Department.property().to_string());
    let value = RwSignal::new(String::new());
    let advanced = RwSignal::new(String::new());

    // The rule to create with: the advanced field when filled, else (users)
    // the attribute builder.
    let rule = move || -> Option<String> {
        let raw = advanced.get();
        if !raw.trim().is_empty() {
            return Some(raw.trim().to_string());
        }
        if member_kind.get() != Some(AdminUnitMemberKind::User) {
            return None;
        }
        let v = value.get();
        if v.trim().is_empty() {
            return None;
        }
        let attr = UserRuleAttribute::ALL
            .into_iter()
            .find(|a| a.property() == attribute.get())?;
        Some(user_rule(attr, &v))
    };

    let create = move |_| {
        let Some(r) = rule() else {
            cmd.error
                .set(Some("Enter a value or a membership rule.".into()));
            return;
        };
        let n = name.get_untracked();
        if n.trim().is_empty() {
            cmd.error.set(Some("Name the admin unit.".into()));
            return;
        }
        cmd.run_with(
            move |unit: AdminUnitDto| {
                selected.set(Some(unit));
                created_now.set(true);
                reload.update(|x| *x += 1);
            },
            move |e| cmd.fail_inline(e),
            move |tenant| async move {
                admin_units::create_admin_unit_by_rule(&tenant, n.trim(), &r).await
            },
        );
    };

    let unit_row = move |unit: AdminUnitDto| {
        let usable = unit_can_hold(&unit, member_kind.get_untracked());
        let id_checked = unit.id.clone();
        let picked = unit.clone();
        let kind = if unit.dynamic {
            match &unit.membership_rule {
                Some(rule) => format!("by rule: {rule}"),
                None => "by rule".to_string(),
            }
        } else {
            "assigned members".to_string()
        };
        let mut notes: Vec<&str> = Vec::new();
        if unit.dynamic && !unit.rule_processing_on {
            notes.push("rule paused");
        }
        if unit.restricted {
            notes.push("restricted management");
        }
        let notes = (!notes.is_empty()).then(|| format!(" · {}", notes.join(" · ")));
        view! {
            <label class="radio-row">
                <input
                    type="radio"
                    name="admin-unit"
                    disabled=!usable
                    prop:checked=move || {
                        selected.with(|s| s.as_ref().is_some_and(|s| s.id == id_checked))
                    }
                    on:change=move |_| {
                        selected.set(Some(picked.clone()));
                        created_now.set(false);
                    }
                />
                <span>
                    <strong>{unit.display_name.clone()}</strong>
                    <span class="hint">{format!(" — {kind}")} {notes}</span>
                </span>
            </label>
        }
    };

    view! {
        <div class="admin-unit-panel">
            <strong>"Admin unit"</strong>
            {move || {
                (member_kind.get() == Some(AdminUnitMemberKind::Group))
                    .then(|| {
                        view! {
                            <span class="ui-text hint">
                                "Dynamic rules can't add groups, so only a unit with assigned members can hold them. Add groups to a unit in the Entra portal."
                            </span>
                        }
                    })
            }}
            <Suspense fallback=move || view! { <SkeletonList rows=2 /> }>
                {move || Suspend::new(async move {
                    match units.await {
                        Ok(list) if list.is_empty() => {
                            view! {
                                <span class="ui-text muted">
                                    "No admin units yet — create one below."
                                </span>
                            }
                                .into_any()
                        }
                        Ok(list) => list.into_iter().map(unit_row).collect_view().into_any(),
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
            {move || {
                let kind = member_kind.get();
                (kind != Some(AdminUnitMemberKind::Group))
                    .then(|| {
                        let builder = (kind == Some(AdminUnitMemberKind::User))
                            .then(|| {
                                view! {
                                    <div class="form-grid">
                                        <Field label="Users whose">
                                            <Select value=attribute label="Attribute">
                                                {UserRuleAttribute::ALL
                                                    .into_iter()
                                                    .map(|a| {
                                                        view! {
                                                            <option value=a.property()>{a.label()}</option>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </Select>
                                        </Field>
                                        <div class="admin-unit-panel__value">
                                            <Field label="equals">
                                                <Input value=value placeholder="Finance" />
                                            </Field>
                                        </div>
                                    </div>
                                }
                            });
                        view! {
                            <strong>"Or create one by rule"</strong>
                            <div class="admin-unit-panel__name">
                                <Field label="Name">
                                    <Input value=name placeholder="Finance users" />
                                </Field>
                            </div>
                            {builder}
                            <div class="admin-unit-panel__rule">
                                <Field label="Advanced rule (optional)">
                                    <Textarea
                                        value=advanced
                                        placeholder="(device.deviceOSType -eq \"Windows\")"
                                    />
                                </Field>
                            </div>
                            <span class="ui-text hint">
                                "Microsoft takes a while to work out a new unit's members, so the tenant-wide permission stays this time; use Scope… again once the unit lists them. Dynamic membership needs Entra ID P1 for each member."
                            </span>
                            {move || cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })}
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    disabled=Signal::derive(move || cmd.busy.get())
                                    on_click=Box::new(create)
                                >
                                    "Create admin unit"
                                </Button>
                                {move || cmd.busy.get().then(|| view! { <Spinner /> })}
                            </div>
                        }
                    })
            }}
        </div>
    }
}

/// What limiting `permission` (Microsoft Graph) to an admin unit means, shown
/// before the operator confirms: the role, the tenant-wide read it keeps, what
/// the role also allows, and what the app can no longer do.
#[component]
pub fn DirectoryWriteDisclosures(
    #[prop(into)] permission: Signal<Option<String>>,
) -> impl IntoView {
    move || {
        let mapping = permission.with(|p| {
            p.as_deref().and_then(|v| {
                azapptoolkit_core::scoping::admin_unit::directory_write_mapping(
                    Some(azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID),
                    v,
                )
            })
        })?;
        Some(view! {
            <div class="scope-wizard__disclosures">
                <span class="ui-text">
                    {format!(
                        "Role: {}. Keeps tenant-wide read ({} or Directory.Read.All), which the role needs.",
                        mapping.role_name,
                        mapping.read_permission,
                    )}
                </span>
                <strong>"The role also allows"</strong>
                <ul class="member-list">
                    {mapping.also_allows.iter().map(|l| view! { <li>{*l}</li> }).collect_view()}
                </ul>
                <strong>"The app can no longer"</strong>
                <ul class="member-list">
                    {mapping.no_longer.iter().map(|l| view! { <li>{*l}</li> }).collect_view()}
                </ul>
            </div>
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(dynamic: bool) -> AdminUnitDto {
        AdminUnitDto {
            id: "au".into(),
            display_name: "Finance".into(),
            dynamic,
            membership_rule: None,
            rule_processing_on: true,
            restricted: false,
        }
    }

    #[test]
    fn a_dynamic_unit_cannot_hold_groups() {
        assert!(!unit_can_hold(
            &unit(true),
            Some(AdminUnitMemberKind::Group)
        ));
        assert!(unit_can_hold(
            &unit(false),
            Some(AdminUnitMemberKind::Group)
        ));
        assert!(unit_can_hold(&unit(true), Some(AdminUnitMemberKind::User)));
    }
}
