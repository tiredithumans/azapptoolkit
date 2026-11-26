//! The Teams meeting access policy dialog (C3). Online-meeting, transcript,
//! recording, artifact and virtual-event permissions reach only the meetings
//! of users an app's application access policy covers. Microsoft has no API
//! for these policies, so this builds the exact PowerShell (users or one
//! group, never `-Global`) for the operator to run. Nothing is changed here.

use leptos::prelude::*;
use thaw::{Field, Input};

use azapptoolkit_core::models::DirectoryObject;
use azapptoolkit_core::teams_meeting_policy::{
    PolicyMode, PolicyRequest, PolicyTargets, default_policy_name, script,
};

use crate::components::directory_search::{DirectoryScope, DirectorySearch};
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{Callout, CopyBlock, FormError};

fn label_of(obj: &DirectoryObject) -> String {
    obj.display_name
        .clone()
        .or_else(|| obj.user_principal_name.clone())
        .unwrap_or_else(|| obj.id.clone())
}

#[component]
pub fn MeetingPolicyDialog(
    #[prop(into)] open: Signal<bool>,
    /// The app (client) id the policy names.
    #[prop(into)]
    app_id: Signal<String>,
    #[prop(into)] app_name: Signal<String>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    let mode = RwSignal::new(PolicyMode::New);
    let policy_name = RwSignal::new(String::new());
    let group_mode = RwSignal::new(false);
    let users: RwSignal<Vec<(String, String)>> = RwSignal::new(Vec::new());
    let group: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let rank = RwSignal::new(String::new());

    // Every open starts fresh, named after the app.
    Effect::new(move |_| {
        if open.get() {
            policy_name.set(default_policy_name(&app_name.get_untracked()));
            mode.set(PolicyMode::New);
            group_mode.set(false);
            users.set(Vec::new());
            group.set(None);
            rank.set(String::new());
        }
    });

    let output = Memo::new(move |_| {
        let targets = if group_mode.get() {
            match group.get() {
                Some((id, _)) => PolicyTargets::Group {
                    id,
                    rank: rank.get().trim().parse().ok(),
                },
                None => PolicyTargets::Users(Vec::new()),
            }
        } else {
            PolicyTargets::Users(users.get().into_iter().map(|(id, _)| id).collect())
        };
        script(&PolicyRequest {
            app_id: app_id.get(),
            app_name: app_name.get(),
            policy_name: policy_name.get().trim().to_string(),
            mode: mode.get(),
            targets,
        })
        .map_err(|e| e.to_string())
    });

    let on_pick = Callback::new(move |obj: DirectoryObject| {
        let entry = (obj.id.clone(), label_of(&obj));
        if group_mode.get_untracked() {
            group.set(Some(entry));
        } else {
            users.update(|u| {
                if !u.iter().any(|(id, _)| *id == entry.0) {
                    u.push(entry);
                }
            });
        }
    });
    let scope = Signal::derive(move || {
        if group_mode.get() {
            DirectoryScope::Groups
        } else {
            DirectoryScope::Users
        }
    });

    let radio =
        move |name: &'static str, checked: Signal<bool>, set: Callback<()>, text: &'static str| {
            view! {
                <label class="radio-row">
                    <input
                        type="radio"
                        name=name
                        prop:checked=move || checked.get()
                        on:change=move |_| set.run(())
                    />
                    <span>{text}</span>
                </label>
            }
        };

    view! {
        <ModalShell open=open title="Meeting access policy" on_close=on_close wide=true>
            <span class="ui-text">
                "Online-meeting, transcript and recording permissions reach only the meetings of users this app's Teams application access policy covers. Microsoft offers no API for these policies, so run this PowerShell as a Teams administrator; changes take up to 30 minutes."
            </span>
            {radio(
                "meeting-policy-mode",
                Signal::derive(move || mode.get() == PolicyMode::New),
                Callback::new(move |()| mode.set(PolicyMode::New)),
                "Create a new policy",
            )}
            {radio(
                "meeting-policy-mode",
                Signal::derive(move || mode.get() == PolicyMode::AddToExisting),
                Callback::new(move |()| mode.set(PolicyMode::AddToExisting)),
                "Add this app to an existing policy",
            )}
            {move || {
                (mode.get() == PolicyMode::New)
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                <span class="ui-text">
                                    "A user holds one application access policy; granting this one replaces theirs. For users who already have one, use Add this app to an existing policy."
                                </span>
                            </Callout>
                        }
                    })
            }}
            <Field label="Policy name">
                <Input value=policy_name />
            </Field>
            {radio(
                "meeting-policy-targets",
                Signal::derive(move || !group_mode.get()),
                Callback::new(move |()| group_mode.set(false)),
                "Specific users",
            )}
            {radio(
                "meeting-policy-targets",
                Signal::derive(move || group_mode.get()),
                Callback::new(move |()| group_mode.set(true)),
                "One group",
            )}
            <div class="meeting-policy__search">
                <DirectorySearch on_pick=on_pick scope=scope />
            </div>
            {move || {
                if group_mode.get() {
                    group
                        .get()
                        .map(|(_, name)| {
                            view! {
                                <span class="ui-text">{format!("Group: {name}")}</span>
                                <div class="meeting-policy__rank">
                                    <Field label="Rank (optional)">
                                        <Input value=rank placeholder="1" />
                                    </Field>
                                </div>
                            }
                                .into_any()
                        })
                        .unwrap_or_else(|| ().into_any())
                } else {
                    view! {
                        <ul class="member-list">
                            {users
                                .get()
                                .into_iter()
                                .map(|(id, name)| {
                                    let remove = id.clone();
                                    view! {
                                        <li>
                                            {name}
                                            " "
                                            <button
                                                type="button"
                                                class="link-btn"
                                                on:click=move |_| {
                                                    users.update(|u| u.retain(|(i, _)| *i != remove))
                                                }
                                            >
                                                "Remove"
                                            </button>
                                        </li>
                                    }
                                })
                                .collect_view()}
                        </ul>
                    }
                        .into_any()
                }
            }}
            <span class="ui-text muted">
                "-Global isn't offered: it covers every user without their own policy, which is the tenant-wide reach this exists to avoid."
            </span>
            {move || match output.get() {
                Ok(s) => {
                    view! {
                        <div class="meeting-policy__script">
                            <CopyBlock label="PowerShell" value=s />
                        </div>
                    }
                        .into_any()
                }
                Err(e) => view! { <FormError>{e}</FormError> }.into_any(),
            }}
        </ModalShell>
    }
}
