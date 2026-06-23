//! Target panel for SharePoint `Sites.Selected` scoping: collects the site URLs
//! to confine access to, plus the read/write role to grant on them. Pure
//! presentation (the caller owns the signals + the apply call) — the SharePoint
//! analogue of `ManagedScopeGroupPanel`, minus the live membership object
//! (SharePoint has no persistent scope group; access is per-site grants).

use leptos::prelude::*;
use thaw::{Body1, Field, Textarea};

#[component]
pub fn SiteSelectionPanel(
    /// Site URLs to grant on, one per line.
    site_urls: RwSignal<String>,
    /// `true` = write access, `false` = read.
    write: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <Field label="Site URLs (one per line)">
            <Textarea
                value=site_urls
                placeholder="https://contoso.sharepoint.com/sites/Marketing"
            />
        </Field>
        <div class="radio-row">
            <label class="radio-row">
                <input
                    type="radio"
                    name="site-access-role"
                    prop:checked=move || !write.get()
                    on:change=move |_| write.set(false)
                />
                <span>"Read"</span>
            </label>
            <label class="radio-row">
                <input
                    type="radio"
                    name="site-access-role"
                    prop:checked=move || write.get()
                    on:change=move |_| write.set(true)
                />
                <span>"Write"</span>
            </label>
        </div>
        <Body1 class="hint">
            "Grants Sites.Selected + the chosen access on just these sites, then removes any org-wide Sites.* grant so access is confined to them."
        </Body1>
    }
}
