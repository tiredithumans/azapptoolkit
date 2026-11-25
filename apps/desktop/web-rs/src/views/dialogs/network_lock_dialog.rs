//! The Network lock's create dialog: pick the IP named locations the app may
//! sign in from (or add a new one), then create the lock — always report-only,
//! and any new location untrusted.

use std::collections::HashSet;

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Field, Input, Textarea};

use crate::bindings::conditional_access::{self, NewLocationArgs};
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{FormError, SkeletonList, Spinner};
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::{no_tenant, parse_lines};

#[component]
pub fn NetworkLockDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] app_id: Signal<String>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_created: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let chosen: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());
    let new_name = RwSignal::new(String::new());
    let new_cidrs = RwSignal::new(String::new());
    let cmd = use_command().with_consent_feature("conditional_access_write");

    let locations = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let is_open = open.get();
        async move {
            if !is_open {
                return Ok(Vec::new());
            }
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            conditional_access::list_named_locations(&t.tenant_id).await
        }
    });

    // A reopened dialog starts blank.
    Effect::new(move |_| {
        if !open.get() {
            chosen.set(HashSet::new());
            new_name.set(String::new());
            new_cidrs.set(String::new());
            cmd.error.set(None);
        }
    });

    let nothing_chosen =
        move || chosen.with(|c| c.is_empty()) && new_cidrs.with(|t| parse_lines(t).is_empty());
    let create = move |_| {
        let ids: Vec<String> = chosen.get().into_iter().collect();
        let cidrs = parse_lines(&new_cidrs.get());
        let new_location = (!cidrs.is_empty()).then(|| NewLocationArgs {
            name: new_name.get().trim().to_string(),
            cidrs,
        });
        let app = app_id.get();
        cmd.run(
            move |_created| {
                on_created.try_run(());
                on_close.try_run(());
            },
            move |tenant| async move {
                conditional_access::create_network_lock(&tenant, &app, &ids, new_location.as_ref())
                    .await
            },
        );
    };

    view! {
        <ModalShell
            open=open
            title="Lock this app to trusted locations"
            busy=cmd.busy
            on_close=on_close
        >
            <span class="ui-text">
                "Created report-only: nothing is blocked until you turn it on. New locations are created untrusted, so they don't relax anyone's MFA."
            </span>
            <strong>"Named locations the app may sign in from"</strong>
            <Suspense fallback=move || view! { <SkeletonList rows=2 /> }>
                {move || Suspend::new(async move {
                    match locations.await {
                        Ok(list) if list.is_empty() => {
                            view! {
                                <span class="ui-text muted">
                                    "No IP named locations yet — add one below."
                                </span>
                            }
                                .into_any()
                        }
                        Ok(list) => {
                            list.into_iter()
                                .map(|l| {
                                    let id = l.id.clone();
                                    let id_checked = id.clone();
                                    let id_toggle = id.clone();
                                    let label = format!(
                                        "{} ({} range{}{})",
                                        l.display_name,
                                        l.range_count,
                                        if l.range_count == 1 { "" } else { "s" },
                                        if l.is_trusted { ", trusted" } else { "" },
                                    );
                                    view! {
                                        <label class="checkbox-row">
                                            <input
                                                type="checkbox"
                                                value=id
                                                prop:checked=move || {
                                                    chosen.with(|c| c.contains(&id_checked))
                                                }
                                                on:change=move |_| {
                                                    chosen
                                                        .update(|c| {
                                                            if !c.remove(&id_toggle) {
                                                                c.insert(id_toggle.clone());
                                                            }
                                                        })
                                                }
                                            />
                                            {label}
                                        </label>
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }
                        Err(e) => view! { <FormError>{e.message}</FormError> }.into_any(),
                    }
                })}
            </Suspense>
            <Field label="New named location (optional)">
                <Input value=new_name placeholder="Payroll egress" />
            </Field>
            <Field label="Its IP ranges, one per line">
                <Textarea value=new_cidrs placeholder="203.0.113.0/24" />
            </Field>
            {move || cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })}
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    disabled=Signal::derive(move || cmd.busy.get())
                    on_click=Box::new(move |_| on_close.run(()))
                >
                    "Cancel"
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    disabled=Signal::derive(move || cmd.busy.get() || nothing_chosen())
                    on_click=Box::new(create)
                >
                    "Create lock"
                </Button>
                {move || cmd.busy.get().then(|| view! { <Spinner /> })}
            </div>
        </ModalShell>
    }
}
