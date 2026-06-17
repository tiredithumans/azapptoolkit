//! Identity-type chip used in list rows, detail-pane headers, search results,
//! and the permissions kind column. Renders an inline SVG glyph + colored
//! label so the three Azure identity object types are visually distinct at
//! every appearance.

use leptos::prelude::*;

use crate::components::icon::{Icon, IconName};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    AppRegistration,
    EnterpriseApp,
    ManagedIdentitySystem,
    ManagedIdentityUser,
    ManagedIdentityUnknown,
    /// Application permission (App role).
    PermissionApplication,
    /// Delegated permission (OAuth scope).
    PermissionDelegated,
    /// Permission of unknown kind.
    PermissionUnknown,
}

impl AppKind {
    fn modifier(self) -> &'static str {
        match self {
            AppKind::AppRegistration => "app",
            AppKind::EnterpriseApp => "ent",
            AppKind::ManagedIdentitySystem | AppKind::ManagedIdentityUnknown => "mi",
            AppKind::ManagedIdentityUser => "mi-user",
            AppKind::PermissionApplication => "perm-app",
            AppKind::PermissionDelegated => "perm-deleg",
            AppKind::PermissionUnknown => "perm-unknown",
        }
    }

    fn label(self) -> &'static str {
        match self {
            AppKind::AppRegistration => "App Reg",
            AppKind::EnterpriseApp => "Ent App",
            AppKind::ManagedIdentitySystem => "MI · System",
            AppKind::ManagedIdentityUser => "MI · User",
            AppKind::ManagedIdentityUnknown => "MI",
            AppKind::PermissionApplication => "Application",
            AppKind::PermissionDelegated => "Delegated",
            AppKind::PermissionUnknown => "Unknown",
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            AppKind::AppRegistration => {
                "App Registration — the application's definition in this tenant."
            }
            AppKind::EnterpriseApp => {
                "Enterprise Application — a service principal representing an app in this tenant (gallery, first-party, or consented foreign-tenant)."
            }
            AppKind::ManagedIdentitySystem => {
                "Managed Identity (system-assigned) — lifecycle is tied to a single Azure resource."
            }
            AppKind::ManagedIdentityUser => {
                "Managed Identity (user-assigned) — a standalone Azure resource that can be assigned to many resources."
            }
            AppKind::ManagedIdentityUnknown => "Managed Identity.",
            AppKind::PermissionApplication => {
                "Application permission — granted to the app itself; admin consent required."
            }
            AppKind::PermissionDelegated => {
                "Delegated permission — acts on behalf of a signed-in user."
            }
            AppKind::PermissionUnknown => "Permission of unknown kind (resource not in catalog).",
        }
    }
}

#[component]
pub fn TypeChip(kind: AppKind, #[prop(optional)] compact: bool) -> impl IntoView {
    let class = format!("type-chip type-chip--{}", kind.modifier());
    view! {
        <span class=class title=kind.tooltip()>
            {chip_icon(kind)}
            {(!compact).then(|| view! { <span class="type-chip__label">{kind.label()}</span> })}
        </span>
    }
}

fn chip_icon(kind: AppKind) -> impl IntoView {
    let icon = match kind {
        AppKind::AppRegistration => IconName::AppWindow,
        AppKind::EnterpriseApp => IconName::Building,
        AppKind::ManagedIdentitySystem => IconName::Server,
        AppKind::ManagedIdentityUser | AppKind::ManagedIdentityUnknown => IconName::ShieldCheck,
        AppKind::PermissionApplication => IconName::Lock,
        AppKind::PermissionDelegated => IconName::Key,
        AppKind::PermissionUnknown => IconName::Info,
    };
    view! { <span class="type-chip__icon"><Icon name=icon size=12 /></span> }
}
