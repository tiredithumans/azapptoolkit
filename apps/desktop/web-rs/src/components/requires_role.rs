//! Proactive "Requires: …" role label shown up front on a privileged surface,
//! before the user acts. Reads the capability catalog
//! (`azapptoolkit_core::capabilities`) so the role it names always matches the
//! reactive 403 hint and the readiness checklist — one source of truth. Pure
//! presentation; advisory only (it never gates the action). Generalizes the
//! inline "Requires … rights" text that `scope_panel` hardcodes.

use leptos::prelude::*;

use azapptoolkit_core::capabilities::capability;

#[component]
pub fn RequiresRole(#[prop(into)] capability_key: String) -> impl IntoView {
    // Unknown key → render nothing (the catalog is the allow-list).
    capability(&capability_key).map(|cap| {
        // Name the primary role (the label users recognise); the full list of
        // satisfying roles + what-to-do lives in the tooltip.
        let primary = cap.role_names().next().unwrap_or(cap.label);
        let tip = if cap.directory_roles_any.len() > 1 {
            format!(
                "Any of: {}.\n\n{}",
                cap.role_names().collect::<Vec<_>>().join(", "),
                cap.remediation
            )
        } else {
            cap.remediation.to_string()
        };
        view! {
            <span class="requires-role" title=tip>
                {format!("Requires: {primary}")}
            </span>
        }
    })
}
