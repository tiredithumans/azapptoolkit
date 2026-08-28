//! Target panel for the sub-site SharePoint Selected scopes
//! (`Lists.`/`ListItems.`/`Files.SelectedOperations.Selected`): collects the
//! library / folder / file URLs to confine access to, plus the read/write role.
//!
//! The sibling of `SiteSelectionPanel` one level down, with one addition that
//! is not cosmetic: it **resolves each URL before the grant runs** and shows
//! what it found. Two reasons the site panel doesn't need this:
//!
//! * A grant here breaks SharePoint's permission inheritance on the target and
//!   consumes one of the library's unique permission scopes. That is not
//!   something to discover afterwards.
//! * A URL can resolve one level away from where the operator aimed it — a
//!   library root looks much like a folder inside it. The backend fails closed
//!   on a level mismatch; showing the resolved level here turns that from a
//!   post-hoc warning into a correctable typo.

use leptos::prelude::*;
use thaw::{Body1, Field, Spinner, SpinnerSize, Textarea};

use crate::bindings::sharepoint::{self, SharePointResourceRef};
use crate::components::ui::Callout;
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;
use crate::util::parse_lines;
use azapptoolkit_core::scoping::{SelectedScopeLevel, selected_scope_accepts};

/// What resolution turned one pasted URL into.
#[derive(Clone)]
enum Probe {
    Pending,
    Resolved(Box<SharePointResourceRef>),
    Failed(String),
}

/// Operator-facing noun for what a resolved URL points at. Distinct from
/// `SelectedScopeLevel::label` (which names a *scope's* reach) because a
/// resolved item is concretely a folder or a file, and saying so is the whole
/// value of the preview.
fn describe(r: &SharePointResourceRef) -> &'static str {
    match r.level {
        SelectedScopeLevel::Site => "Site",
        SelectedScopeLevel::List => "List or library",
        SelectedScopeLevel::ListItem => "List item",
        SelectedScopeLevel::File if r.is_folder => "Folder",
        SelectedScopeLevel::File => "File",
    }
}

#[component]
pub fn ItemSelectionPanel(
    /// Resource URLs to grant on, one per line.
    target_urls: RwSignal<String>,
    /// `true` = write access, `false` = read.
    write: RwSignal<bool>,
    /// The level the cart's permission grants at — a target that this level
    /// cannot reach is flagged here rather than failing during the apply.
    scope_level: Signal<Option<SelectedScopeLevel>>,
) -> impl IntoView {
    let session = use_session();
    // Resolution costs up to three Graph reads per URL, so it trails typing
    // rather than firing on every keystroke.
    let debounced = use_debounced(target_urls.into(), 600);
    let probes: RwSignal<Vec<(String, Probe)>> = RwSignal::new(Vec::new());

    Effect::new(move |_| {
        // Deduplicated: the `For` below is keyed on the URL, and the backend
        // skips repeats anyway (a second grant on one resource buys nothing and
        // costs another unique permission scope).
        let mut urls = parse_lines(&debounced.get());
        let mut seen: Vec<String> = Vec::new();
        urls.retain(|u| {
            let key = u.trim_end_matches('/').to_ascii_lowercase();
            let fresh = !seen.contains(&key);
            seen.push(key);
            fresh
        });
        let Some(tenant) = session.active_tenant.get() else {
            return;
        };
        if urls.is_empty() {
            probes.set(Vec::new());
            return;
        }
        probes.set(urls.iter().map(|u| (u.clone(), Probe::Pending)).collect());
        let tenant_id = tenant.tenant_id.clone();
        leptos::task::spawn_local(async move {
            for (i, url) in urls.iter().enumerate() {
                let outcome = match sharepoint::resolve_sharepoint_resource(&tenant_id, url).await {
                    Ok(r) => Probe::Resolved(Box::new(r)),
                    Err(e) => Probe::Failed(e.message),
                };
                // Re-check the row still belongs to this run: the operator may
                // have typed on, replacing the list underneath us.
                probes.update(|rows| {
                    if let Some(row) = rows.get_mut(i)
                        && row.0 == *url
                    {
                        row.1 = outcome;
                    }
                });
            }
        });
    });

    let any_mismatch = move || {
        let Some(level) = scope_level.get() else {
            return false;
        };
        probes.with(|rows| {
            rows.iter().any(|(_, p)| match p {
                Probe::Resolved(r) => !selected_scope_accepts(level, r.level),
                _ => false,
            })
        })
    };

    view! {
        <Field label="Library, folder or file URLs (one per line)">
            <Textarea
                value=target_urls
                placeholder="https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices/2026"
            />
        </Field>
        <div class="radio-row">
            <label class="radio-row">
                <input
                    type="radio"
                    name="item-access-role"
                    prop:checked=move || !write.get()
                    on:change=move |_| write.set(false)
                />
                <span>"Read"</span>
            </label>
            <label class="radio-row">
                <input
                    type="radio"
                    name="item-access-role"
                    prop:checked=move || write.get()
                    on:change=move |_| write.set(true)
                />
                <span>"Write"</span>
            </label>
        </div>

        <ul class="resource-probe-list" aria-label="Resolved targets">
            <For
                each=move || probes.get()
                key=|(url, _)| url.clone()
                let:row
            >
                {
                    let (url, probe) = row;
                    match probe {
                        Probe::Pending => {
                            view! {
                                <li class="resource-probe">
                                    <Spinner size=SpinnerSize::Tiny />
                                    <span class="muted">{url}</span>
                                </li>
                            }
                                .into_any()
                        }
                        Probe::Failed(msg) => {
                            view! {
                                <li class="resource-probe resource-probe--bad">
                                    <span class="badge badge--danger">"Not found"</span>
                                    <span>{url}</span>
                                    <span class="muted">{msg}</span>
                                </li>
                            }
                                .into_any()
                        }
                        Probe::Resolved(r) => {
                            let accepted = scope_level
                                .get_untracked()
                                .is_none_or(|l| selected_scope_accepts(l, r.level));
                            let kind = describe(&r);
                            let path = r.display_path.clone();
                            let level_label = r.level.label();
                            view! {
                                <li class=move || {
                                    if accepted {
                                        "resource-probe"
                                    } else {
                                        "resource-probe resource-probe--bad"
                                    }
                                }>
                                    <span class=move || {
                                        if accepted {
                                            "badge badge--ok"
                                        } else {
                                            "badge badge--danger"
                                        }
                                    }>{kind}</span>
                                    <span>{path}</span>
                                    {(!accepted)
                                        .then(|| {
                                            view! {
                                                <span class="muted">
                                                    {format!(
                                                        "this permission grants at the {} level and cannot reach it",
                                                        scope_level
                                                            .get_untracked()
                                                            .map(SelectedScopeLevel::label)
                                                            .unwrap_or(level_label),
                                                    )}
                                                </span>
                                            }
                                        })}
                                </li>
                            }
                                .into_any()
                        }
                    }
                }
            </For>
        </ul>

        <Show when=any_mismatch fallback=|| ()>
            <Callout tone="danger" role="alert">
                <Body1>
                    "One or more targets sit at a level this permission can't grant against. They'll be skipped — correct the URL, or pick the permission that matches."
                </Body1>
            </Callout>
        </Show>

        <Callout tone="warn">
            <Body1>
                "Granting below the site collection breaks SharePoint permission inheritance on the target and uses one of the library's unique permission scopes. Prefer a dedicated document library, or a dedicated site, where the content allows it."
            </Body1>
        </Callout>
        <Body1 class="hint">
            "Grants the Selected permission plus the chosen access on just these resources. Nothing org-wide is removed — these scopes start least-privilege."
        </Body1>
    }
}
