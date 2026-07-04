//! Lucide-style inline SVG icon set. A single `<Icon>` component dispatches
//! on `IconName` so views can use icons without each defining their own SVG.
//! Stroke geometry follows Lucide (24×24 viewBox, stroke-width 1.5,
//! round joins/caps). Color via `currentColor`.

#![allow(dead_code)]

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconName {
    // Nav
    Home,
    AppWindow,
    Building,
    Server,
    ShieldCheck,
    ShieldAlert,
    Wrench,
    Database,
    Activity,
    // Actions
    Plus,
    Trash,
    Copy,
    Refresh,
    Download,
    Upload,
    Search,
    Close,
    More,
    Filter,
    // Status
    AlertTriangle,
    CheckCircle,
    Info,
    Key,
    Lock,
    Clock,
    // Affordances
    ChevronRight,
    ChevronDown,
    ExternalLink,
    LogOut,
    Maximize,
}

#[component]
pub fn Icon(
    name: IconName,
    #[prop(optional, default = 16)] size: u32,
    #[prop(optional, into)] class: String,
) -> impl IntoView {
    let class_attr = if class.is_empty() {
        "ui-icon".to_string()
    } else {
        format!("ui-icon {class}")
    };
    let inner = paths(name);
    view! {
        <svg
            class=class_attr
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            {inner}
        </svg>
    }
}

fn paths(name: IconName) -> AnyView {
    match name {
        IconName::Home => view! {
            <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>
            <path d="M9 22V12h6v10"></path>
        }
        .into_any(),
        IconName::AppWindow => view! {
            <rect x="2" y="4" width="20" height="16" rx="2"></rect>
            <path d="M2 9h20"></path>
            <path d="M6 6.5h.01M9 6.5h.01M12 6.5h.01"></path>
        }
        .into_any(),
        IconName::Building => view! {
            <path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18"></path>
            <path d="M2 22h20"></path>
            <path d="M10 6h4M10 10h4M10 14h4M10 18h4"></path>
        }
        .into_any(),
        IconName::Server => view! {
            <rect x="2" y="3" width="20" height="8" rx="2"></rect>
            <rect x="2" y="13" width="20" height="8" rx="2"></rect>
            <path d="M6 7h.01M6 17h.01"></path>
        }
        .into_any(),
        IconName::ShieldCheck => view! {
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="m9 12 2 2 4-4"></path>
        }
        .into_any(),
        IconName::ShieldAlert => view! {
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="M12 8v4"></path>
            <path d="M12 16h.01"></path>
        }
        .into_any(),
        IconName::Wrench => view! {
            <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L2 19l3 3 7.3-7.3a4 4 0 0 0 5.4-5.4l-3 3-2-2 3-3z"></path>
        }
        .into_any(),
        IconName::Database => view! {
            <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
            <path d="M3 5v6c0 1.7 4 3 9 3s9-1.3 9-3V5"></path>
            <path d="M3 11v6c0 1.7 4 3 9 3s9-1.3 9-3v-6"></path>
        }
        .into_any(),
        IconName::Activity => view! {
            <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
        }
        .into_any(),
        IconName::Plus => view! {
            <path d="M12 5v14M5 12h14"></path>
        }
        .into_any(),
        IconName::Trash => view! {
            <path d="M3 6h18"></path>
            <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path>
            <path d="M10 11v6M14 11v6"></path>
        }
        .into_any(),
        IconName::Copy => view! {
            <rect x="9" y="9" width="13" height="13" rx="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        }
        .into_any(),
        IconName::Refresh => view! {
            <path d="M21 12a9 9 0 1 1-3-6.7L21 8"></path>
            <path d="M21 3v5h-5"></path>
        }
        .into_any(),
        IconName::Download => view! {
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <path d="M7 10l5 5 5-5"></path>
            <path d="M12 15V3"></path>
        }
        .into_any(),
        IconName::Upload => view! {
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <path d="M17 8l-5-5-5 5"></path>
            <path d="M12 3v12"></path>
        }
        .into_any(),
        IconName::Search => view! {
            <circle cx="11" cy="11" r="7"></circle>
            <path d="m20 20-3-3"></path>
        }
        .into_any(),
        IconName::Close => view! {
            <path d="M18 6 6 18M6 6l12 12"></path>
        }
        .into_any(),
        IconName::More => view! {
            <circle cx="12" cy="12" r="1"></circle>
            <circle cx="19" cy="12" r="1"></circle>
            <circle cx="5" cy="12" r="1"></circle>
        }
        .into_any(),
        IconName::Filter => view! {
            <path d="M3 6h18M6 12h12M10 18h4"></path>
        }
        .into_any(),
        IconName::AlertTriangle => view! {
            <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"></path>
            <path d="M12 9v4M12 17h.01"></path>
        }
        .into_any(),
        IconName::CheckCircle => view! {
            <circle cx="12" cy="12" r="10"></circle>
            <path d="m9 12 2 2 4-4"></path>
        }
        .into_any(),
        IconName::Info => view! {
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M12 16v-4M12 8h.01"></path>
        }
        .into_any(),
        IconName::Key => view! {
            <circle cx="7.5" cy="15.5" r="5.5"></circle>
            <path d="m21 2-9.6 9.6"></path>
            <path d="m15.5 7.5 3 3L22 7l-3-3"></path>
        }
        .into_any(),
        IconName::Lock => view! {
            <rect x="3" y="11" width="18" height="11" rx="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        }
        .into_any(),
        IconName::Clock => view! {
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M12 6v6l4 2"></path>
        }
        .into_any(),
        IconName::ChevronRight => view! {
            <path d="m9 6 6 6-6 6"></path>
        }
        .into_any(),
        IconName::ChevronDown => view! {
            <path d="m6 9 6 6 6-6"></path>
        }
        .into_any(),
        IconName::ExternalLink => view! {
            <path d="M15 3h6v6"></path>
            <path d="M10 14 21 3"></path>
            <path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"></path>
        }
        .into_any(),
        IconName::LogOut => view! {
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <path d="m16 17 5-5-5-5"></path>
            <path d="M21 12H9"></path>
        }
        .into_any(),
        IconName::Maximize => view! {
            <path d="M8 3H5a2 2 0 0 0-2 2v3"></path>
            <path d="M21 8V5a2 2 0 0 0-2-2h-3"></path>
            <path d="M3 16v3a2 2 0 0 0 2 2h3"></path>
            <path d="M16 21h3a2 2 0 0 0 2-2v-3"></path>
        }
        .into_any(),
    }
}
