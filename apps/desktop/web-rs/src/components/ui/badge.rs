use leptos::prelude::*;

/// A [`Badge`]'s tone. Each non-neutral tone maps to a `badge--{modifier}`
/// rule in `styles.css` (pinned by `every_badge_tone_has_a_stylesheet_rule`),
/// so a tone with no stylesheet rule — how `badge--info` once shipped — can't
/// be spelled. Always qualify the variants (`BadgeTone::Ok`): a glob import
/// would shadow `Result::Ok`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BadgeTone {
    /// The bare `.badge` chrome: a label with no verdict.
    #[default]
    Neutral,
    /// Healthy / enabled / granted (green).
    Ok,
    /// Informational, not a verdict — e.g. a staged SAML signing certificate
    /// waiting to be activated (accent).
    Info,
    /// Needs attention soon (amber).
    Warning,
    /// Broken, expired or high risk (red outline).
    Danger,
    /// Critical risk (solid red), distinct from `Danger` in adjacent rows.
    Critical,
    /// Indeterminate — the state couldn't be determined (dashed outline).
    Unknown,
}

impl BadgeTone {
    /// Every tone, for the stylesheet-coverage test.
    pub const ALL: [Self; 7] = [
        Self::Neutral,
        Self::Ok,
        Self::Info,
        Self::Warning,
        Self::Danger,
        Self::Critical,
        Self::Unknown,
    ];

    /// The `badge--{modifier}` suffix; `""` for [`BadgeTone::Neutral`]. Also
    /// the suffix of the finding-group dot / Home posture classes, which share
    /// the risk vocabulary.
    pub const fn modifier(self) -> &'static str {
        match self {
            Self::Neutral => "",
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Danger => "danger",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }

    /// The full class list — the only place these strings are spelled.
    const fn class(self) -> &'static str {
        match self {
            Self::Neutral => "badge",
            Self::Ok => "badge badge--ok",
            Self::Info => "badge badge--info",
            Self::Warning => "badge badge--warning",
            Self::Danger => "badge badge--danger",
            Self::Critical => "badge badge--critical",
            Self::Unknown => "badge badge--unknown",
        }
    }
}

impl std::fmt::Display for BadgeTone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.modifier())
    }
}

/// A small status/risk pill in one [`BadgeTone`] (`Neutral` by default:
/// `Ok` | `Info` | `Warning` | `Danger` | `Critical` | `Unknown`); an unknown
/// tone is a compile error. An optional `title` renders as a hover tooltip.
/// This is the one place the `.badge` chrome is defined — risk/status helpers
/// return a `BadgeTone` and render through it instead of hand-writing
/// `<span class="badge …">` (pinned by `repo_invariants/commands.rs`).
#[component]
pub fn Badge(
    #[prop(into)] label: String,
    #[prop(optional)] tone: BadgeTone,
    #[prop(optional, into, default = String::new())] title: String,
    /// Extra class(es) appended to the tone classes, for the few callers that
    /// also position or size the pill (e.g. a certificate row's day count).
    /// Exists so "this one needs one more class" is never a reason to
    /// hand-roll the markup again.
    #[prop(optional, into, default = String::new())]
    class: String,
) -> impl IntoView {
    let class = if class.is_empty() {
        tone.class().to_string()
    } else {
        format!("{} {class}", tone.class())
    };
    let title = (!title.is_empty()).then_some(title);
    view! {
        <span class=class title=title>
            {label}
        </span>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STYLES: &str = include_str!("../../../styles.css");

    #[test]
    fn every_badge_tone_has_a_stylesheet_rule() {
        let styles = STYLES.replace("\r\n", "\n");
        for tone in BadgeTone::ALL {
            if tone == BadgeTone::Neutral {
                assert!(
                    styles.contains("\n.badge {"),
                    "the base `.badge` rule is missing"
                );
                continue;
            }
            let rule = format!("\n.badge--{} {{", tone.modifier());
            assert!(
                styles.contains(&rule),
                "BadgeTone::{tone:?} renders `badge--{}` but styles.css has no `{}` rule",
                tone.modifier(),
                rule.trim(),
            );
            assert!(
                tone.class()
                    .ends_with(&format!("badge--{}", tone.modifier())),
                "BadgeTone::{tone:?}'s class and modifier disagree"
            );
        }
    }
}
