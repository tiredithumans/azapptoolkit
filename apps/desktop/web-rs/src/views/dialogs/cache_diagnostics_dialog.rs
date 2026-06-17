//! Cache diagnostics. Read hit/miss counters, toggle the in-process cache, and
//! adjust the per-kind TTLs / entry cap at runtime (ports
//! `Set-azapptoolkitCacheConfiguration`).

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input};

use crate::bindings::diagnostics::{self, CacheKindDto, CacheStatsDto, SetCacheConfigInput};
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;

#[component]
pub fn CacheDiagnosticsDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    let stats: RwSignal<Option<CacheStatsDto>> = RwSignal::new(None);
    let sp_ttl_min = RwSignal::new(String::new());
    let perm_ttl_min = RwSignal::new(String::new());
    let audit_ttl_min = RwSignal::new(String::new());
    let lists_ttl_min = RwSignal::new(String::new());
    let max_size = RwSignal::new(String::new());
    let config_error: RwSignal<Option<String>> = RwSignal::new(None);

    use_escape(move || open.get_untracked(), move || on_close.run(()));
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    // On open, fetch stats and seed the editable config fields from the current
    // effective configuration (TTLs shown in minutes).
    Effect::new(move |_| {
        if open.get() {
            leptos::task::spawn_local(async move {
                let s = diagnostics::cache_stats().await;
                sp_ttl_min.set((s.service_principal_ttl_secs / 60).to_string());
                perm_ttl_min.set((s.permissions_ttl_secs / 60).to_string());
                audit_ttl_min.set((s.audit_ttl_secs / 60).to_string());
                lists_ttl_min.set((s.lists_ttl_secs / 60).to_string());
                max_size.set(s.max_cache_size.to_string());
                config_error.set(None);
                stats.set(Some(s));
            });
        }
    });

    let toggle = move |_| {
        let enabled = stats.with(|s| s.as_ref().map(|s| !s.enabled).unwrap_or(true));
        leptos::task::spawn_local(async move {
            diagnostics::set_cache_enabled(enabled).await;
            stats.set(Some(diagnostics::cache_stats().await));
        });
    };

    let clear = move |kind: CacheKindDto| {
        leptos::task::spawn_local(async move {
            diagnostics::clear_cache(kind).await;
            stats.set(Some(diagnostics::cache_stats().await));
        });
    };

    let apply_config = move |_| {
        config_error.set(None);
        let parse_min = |v: String| v.trim().parse::<u64>().ok().map(|m| m * 60);
        let sp_secs = parse_min(sp_ttl_min.get());
        let perm_secs = parse_min(perm_ttl_min.get());
        let audit_secs = parse_min(audit_ttl_min.get());
        let lists_secs = parse_min(lists_ttl_min.get());
        let max = max_size.get().trim().parse::<u64>().ok();
        let (Some(sp_secs), Some(perm_secs), Some(audit_secs), Some(lists_secs), Some(max)) =
            (sp_secs, perm_secs, audit_secs, lists_secs, max)
        else {
            config_error.set(Some("Enter whole numbers for all fields.".into()));
            return;
        };
        let input = SetCacheConfigInput {
            enabled: None,
            service_principal_ttl_secs: Some(sp_secs),
            permissions_ttl_secs: Some(perm_secs),
            audit_ttl_secs: Some(audit_secs),
            lists_ttl_secs: Some(lists_secs),
            max_cache_size: Some(max),
        };
        leptos::task::spawn_local(async move {
            match diagnostics::set_cache_config(input).await {
                Ok(()) => stats.set(Some(diagnostics::cache_stats().await)),
                Err(e) => config_error.set(Some(e.message)),
            }
        });
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="cache-dialog-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="cache-dialog-title">"Cache"</h3>
                    {move || {
                        match stats.get() {
                            None => view! { <Body1>"Loading…"</Body1> }.into_any(),
                            Some(s) => {
                                view! {
                                    <table class="data-table">
                                        <tbody>
                                            <tr>
                                                <td>"Service principal hits / misses"</td>
                                                <td>
                                                    {format!(
                                                        "{} / {}",
                                                        s.service_principal_hits,
                                                        s.service_principal_misses,
                                                    )}
                                                </td>
                                            </tr>
                                            <tr>
                                                <td>"Permissions hits / misses"</td>
                                                <td>
                                                    {format!(
                                                        "{} / {}",
                                                        s.permissions_hits,
                                                        s.permissions_misses,
                                                    )}
                                                </td>
                                            </tr>
                                            <tr>
                                                <td>"Audit hits / misses"</td>
                                                <td>{format!("{} / {}", s.audit_hits, s.audit_misses)}</td>
                                            </tr>
                                            <tr>
                                                <td>"Lists hits / misses"</td>
                                                <td>{format!("{} / {}", s.lists_hits, s.lists_misses)}</td>
                                            </tr>
                                            <tr>
                                                <td>"Enabled"</td>
                                                <td>{if s.enabled { "yes" } else { "no" }}</td>
                                            </tr>
                                            <tr>
                                                <td>"Service principal TTL"</td>
                                                <td>{format!("{} min", s.service_principal_ttl_secs / 60)}</td>
                                            </tr>
                                            <tr>
                                                <td>"Permissions TTL"</td>
                                                <td>{format!("{} min", s.permissions_ttl_secs / 60)}</td>
                                            </tr>
                                            <tr>
                                                <td>"Audit TTL"</td>
                                                <td>{format!("{} min", s.audit_ttl_secs / 60)}</td>
                                            </tr>
                                            <tr>
                                                <td>"Lists TTL"</td>
                                                <td>{format!("{} min", s.lists_ttl_secs / 60)}</td>
                                            </tr>
                                            <tr>
                                                <td>"Max entries per kind"</td>
                                                <td>{s.max_cache_size}</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                }
                                    .into_any()
                            }
                        }
                    }}
                    <section>
                        <h4>"Configuration"</h4>
                        <Field label="Service principal TTL (minutes, 1–1440)">
                            <Input value=sp_ttl_min />
                        </Field>
                        <Field label="Permissions TTL (minutes, 1–1440)">
                            <Input value=perm_ttl_min />
                        </Field>
                        <Field label="Audit TTL (minutes, 1–1440)">
                            <Input value=audit_ttl_min />
                        </Field>
                        <Field label="Lists TTL (minutes, 1–1440)">
                            <Input value=lists_ttl_min />
                        </Field>
                        <Field label="Max entries per kind (10–10000)">
                            <Input value=max_size />
                        </Field>
                        {move || {
                            config_error
                                .get()
                                .map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                        }}
                    </section>
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(toggle)
                        >
                            "Toggle enabled"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| clear(CacheKindDto::Lists))
                        >
                            "Clear lists"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| clear(CacheKindDto::All))
                        >
                            "Clear all"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(apply_config)
                        >
                            "Apply config"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| on_close.run(()))
                        >
                            "Close"
                        </Button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
