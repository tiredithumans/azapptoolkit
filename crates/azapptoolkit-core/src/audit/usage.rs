//! Observed usage of the "no built-in scoping" communications permissions,
//! from Microsoft Graph activity logs.
//!
//! One static table of path families drives both halves: the KQL the audit
//! sends to Log Analytics ([`graph_usage_kql`]) and the Rust matcher
//! ([`family_for_path`]). A test compiles the generated regexes and checks
//! they agree with the matcher, path by path. Families are most-specific
//! first, so a transcripts call is never counted as an online-meetings call.
//!
//! Semantics: a call in a permission's family is one that permission COULD
//! have authorized (another held permission may be the one that did), so only
//! "no call seen" is evidence about the grant itself.

use std::collections::HashMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// How far back the audit's usage query looks (the table's default retention).
pub const USAGE_WINDOW_DAYS: u32 = 90;

/// One family of Graph request paths and the permissions that authorize them.
/// Patterns are lower-case segment lists after the `/v1.0` or `/beta` prefix:
/// `*` is any one segment, and the LAST segment also matches a function call
/// (`getalltranscripts(...)`). Only `a-z`, `*` and `/` appear, so they render
/// to a regex without escaping (pinned by test).
pub struct UsageFamily {
    pub key: &'static str,
    pub permissions: &'static [&'static str],
    pub patterns: &'static [&'static str],
}

/// The tracked families, most specific first.
pub static FAMILIES: &[UsageFamily] = &[
    UsageFamily {
        key: "meeting_transcripts",
        permissions: &["OnlineMeetingTranscript.Read.All"],
        patterns: &[
            "users/*/onlinemeetings/*/transcripts",
            "users/*/onlinemeetings/getalltranscripts",
            "communications/onlinemeetings/*/transcripts",
        ],
    },
    UsageFamily {
        key: "meeting_recordings",
        permissions: &["OnlineMeetingRecording.Read.All"],
        patterns: &[
            "users/*/onlinemeetings/*/recordings",
            "users/*/onlinemeetings/getallrecordings",
            "communications/onlinemeetings/*/recordings",
        ],
    },
    UsageFamily {
        key: "meeting_artifacts",
        permissions: &["OnlineMeetingArtifact.Read.All"],
        patterns: &[
            "users/*/onlinemeetings/*/attendancereports",
            "users/*/onlinemeetings/*/attendeereport",
            "communications/onlinemeetings/*/attendancereports",
        ],
    },
    UsageFamily {
        key: "online_meetings",
        permissions: &["OnlineMeetings.Read.All", "OnlineMeetings.ReadWrite.All"],
        patterns: &[
            "users/*/onlinemeetings",
            "me/onlinemeetings",
            "communications/onlinemeetings",
        ],
    },
    UsageFamily {
        key: "call_records",
        permissions: &["CallRecords.Read.All", "CallRecord-PstnCalls.Read.All"],
        patterns: &["communications/callrecords"],
    },
    UsageFamily {
        key: "calls",
        permissions: &["Calls.AccessMedia.All"],
        patterns: &["communications/calls"],
    },
    UsageFamily {
        key: "channel_messages",
        permissions: &["ChannelMessage.Read.All"],
        patterns: &[
            "teams/*/channels/*/messages",
            "teams/*/channels/getallmessages",
            "teams/*/channels/getallretainedmessages",
            "teams/getallmessages",
        ],
    },
    UsageFamily {
        key: "chats",
        permissions: &["Chat.Read.All", "Chat.ReadWrite.All"],
        patterns: &["chats", "users/*/chats"],
    },
];

/// Whole terms (KQL `has_any`, case-insensitive) at least one of which every
/// pattern names as a segment, so the prefilter drops only rows no family
/// could match — it cuts the 90-day scan to the communications traffic
/// before the per-row regexes run (pinned by test).
pub const USAGE_PREFILTER_TERMS: &[&str] = &["communications", "onlinemeetings", "chats", "teams"];

/// What the audit observed for one unscopable grant. Crosses IPC inside
/// `AuditItem` (internally tagged: `{"state": "not_seen", "since": ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GrantUsage {
    /// The latest call this permission could have authorized.
    Seen { at: Timestamp },
    /// No such call since `since` (the start of the logs actually read).
    NotSeen { since: Timestamp },
    /// The permission's request paths aren't tracked.
    NotTracked,
    /// The logs weren't read; `reason` says why.
    Unknown { reason: UsageUnknownReason },
}

impl Default for GrantUsage {
    fn default() -> Self {
        GrantUsage::Unknown {
            reason: UsageUnknownReason::NotChecked,
        }
    }
}

/// Why usage is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageUnknownReason {
    /// Not looked up (the scorer's placeholder before the runner's pass).
    NotChecked,
    /// The Log Analytics consent isn't granted.
    NoConsent,
    /// No readable workspace exports Microsoft Graph activity logs.
    NoWorkspace,
    /// The query didn't finish within the audit's budget.
    TimedOut,
    /// The workspace holds no Graph activity logs in the window.
    NoLogs,
    /// The logs stopped arriving (the newest row is too old to trust "no call").
    Stale,
    /// Any other failure.
    Failed,
}

/// The lower-case path segments after the API-version prefix, without the
/// query string; `None` for a path with no `/v1.0` or `/beta` prefix.
fn normalized_segments(path: &str) -> Option<Vec<String>> {
    let mut path = path
        .split('?')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    // The KQL collapses repeated slashes the same way (`replace_regex(@'/+')`).
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    let rest = path
        .strip_prefix("/v1.0/")
        .or_else(|| path.strip_prefix("/beta/"))?;
    Some(
        rest.split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Whether `pattern` prefixes `segs`. Only the last pattern segment may also
/// match a function call (`name(...)`), mirroring the KQL regex's tail.
fn pattern_matches(pattern: &str, segs: &[String]) -> bool {
    let pats: Vec<&str> = pattern.split('/').collect();
    if pats.len() > segs.len() {
        return false;
    }
    let last = pats.len() - 1;
    pats.iter().zip(segs).enumerate().all(|(i, (p, s))| {
        *p == "*" || s == p || (i == last && s.strip_prefix(p).is_some_and(|r| r.starts_with('(')))
    })
}

/// The family a Graph request path belongs to, most specific first.
pub fn family_for_path(path: &str) -> Option<&'static str> {
    let segs = normalized_segments(path)?;
    FAMILIES
        .iter()
        .find(|f| f.patterns.iter().any(|p| pattern_matches(p, &segs)))
        .map(|f| f.key)
}

/// The families whose calls `value` could authorize; empty when untracked.
pub fn families_for_permission(value: &str) -> &'static [&'static str] {
    FAMILIES
        .iter()
        .find(|f| f.permissions.contains(&value))
        .map_or(&[], |f| std::slice::from_ref(&f.key))
}

/// The KQL regex for one pattern: `^/(v1\.0|beta)/` + segments (`*` →
/// `[^/]+`) + a tail that allows a sub-path, a function call or the end.
fn pattern_regex(pattern: &str) -> String {
    let body = pattern
        .split('/')
        .map(|s| if s == "*" { "[^/]+" } else { s })
        .collect::<Vec<_>>()
        .join("/");
    format!(r"^/(v1\.0|beta)/{body}(/|\(|$)")
}

/// The audit's one usage query: the latest call per (app, family) over
/// [`USAGE_WINDOW_DAYS`]. Built only from [`FAMILIES`] — no input reaches it.
pub fn graph_usage_kql() -> String {
    let arms: Vec<String> = FAMILIES
        .iter()
        .map(|f| {
            let conds: Vec<String> = f
                .patterns
                .iter()
                .map(|p| format!("P matches regex @'{}'", pattern_regex(p)))
                .collect();
            format!("{}, \"{}\"", conds.join(" or "), f.key)
        })
        .collect();
    format!(
        "MicrosoftGraphActivityLogs \
         | where TimeGenerated > ago({USAGE_WINDOW_DAYS}d) \
         | where RequestUri has_any ({}) \
         | extend P = tolower(replace_regex(tostring(parse_url(RequestUri).Path), @'/+', '/')) \
         | extend Family = case({}, \"\") \
         | where isnotempty(Family) \
         | summarize LastSeen = max(TimeGenerated) by AppId, Family",
        USAGE_PREFILTER_TERMS
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", "),
        arms.join(", ")
    )
}

/// The span of the logs the usage query actually reads: `Since` (retention
/// can be shorter than the window) and `Until` (an export that stopped leaves
/// a gap no "no call" may cover).
pub fn graph_usage_window_kql() -> String {
    format!(
        "MicrosoftGraphActivityLogs \
         | where TimeGenerated > ago({USAGE_WINDOW_DAYS}d) \
         | summarize Since = min(TimeGenerated), Until = max(TimeGenerated)"
    )
}

/// One grant's usage from its app's per-family latest calls: the latest
/// across its families, else "not seen since `since`", or `NotTracked`.
pub fn grant_usage(
    value: &str,
    app_last_seen: &HashMap<&'static str, Timestamp>,
    since: Timestamp,
) -> GrantUsage {
    let families = families_for_permission(value);
    if families.is_empty() {
        return GrantUsage::NotTracked;
    }
    match families.iter().filter_map(|f| app_last_seen.get(f)).max() {
        Some(at) => GrantUsage::Seen { at: *at },
        None => GrantUsage::NotSeen { since },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn family_for_path_table() {
        let cases: [(&str, Option<&str>); 14] = [
            ("/v1.0/communications/callRecords/abc", Some("call_records")),
            (
                "/beta/communications/callRecords/getPstnCalls(fromDateTime=2026-01-01)",
                Some("call_records"),
            ),
            (
                "/v1.0/users/u1/onlineMeetings/m1/transcripts/t1/content",
                Some("meeting_transcripts"),
            ),
            (
                "/v1.0/users/u1/onlineMeetings/getAllTranscripts(meetingOrganizerUserId='u1')",
                Some("meeting_transcripts"),
            ),
            ("/v1.0/users/u1/onlineMeetings/m1", Some("online_meetings")),
            (
                "/v1.0/teams/t1/channels/c1/messages?$top=5",
                Some("channel_messages"),
            ),
            ("/v1.0/users/u1/chats", Some("chats")),
            ("/v1.0/users/u1/messages", None),
            ("/v1.0/communicationsx/callrecords", None),
            (
                "/v1.0/teams/t1/channels/getAllMessages",
                Some("channel_messages"),
            ),
            (
                "/v1.0/teams/t1/channels/getAllRetainedMessages",
                Some("channel_messages"),
            ),
            (
                "/v1.0/users/u1/onlineMeetings/m1/attendeeReport",
                Some("meeting_artifacts"),
            ),
            (
                "/v1.0/communications/onlineMeetings/m1/attendanceReports",
                Some("meeting_artifacts"),
            ),
            ("/v1.0//users/u1/chats", Some("chats")),
        ];
        for (path, want) in cases {
            assert_eq!(family_for_path(path), want, "{path}");
        }
    }

    #[test]
    fn every_family_has_a_permission_and_every_tracked_permission_is_risk_weighted() {
        for family in FAMILIES {
            assert!(!family.permissions.is_empty(), "{}", family.key);
            assert!(!family.patterns.is_empty(), "{}", family.key);
            for p in family.permissions {
                assert!(
                    crate::audit::risk_level_for_app_permission(p).is_some(),
                    "{p} is tracked but carries no risk weight"
                );
                assert!(families_for_permission(p).contains(&family.key), "{p}");
            }
        }
        assert!(families_for_permission("RoleManagement.ReadWrite.Directory").is_empty());
        for family in FAMILIES {
            for pat in family.patterns {
                assert!(
                    pat.chars()
                        .all(|c| c.is_ascii_lowercase() || c == '*' || c == '/'),
                    "{pat} needs regex escaping"
                );
            }
        }
    }

    #[test]
    fn graph_usage_kql_is_static_and_names_every_family() {
        let kql = graph_usage_kql();
        for family in FAMILIES {
            assert!(
                kql.contains(&format!("\"{}\"", family.key)),
                "{}",
                family.key
            );
        }
        assert!(kql.contains("ago(90d)"), "{kql}");
        assert!(
            kql.contains("summarize LastSeen = max(TimeGenerated) by AppId, Family"),
            "{kql}"
        );
        assert!(!kql.contains('{'), "no interpolation leftovers: {kql}");
        let window = graph_usage_window_kql();
        assert!(window.contains("Since = min(TimeGenerated)"), "{window}");
        assert!(window.contains("Until = max(TimeGenerated)"), "{window}");
    }

    /// The query that RUNS must agree with the matcher the tests exercise:
    /// every table path, normalized the way the KQL normalizes it, hits the
    /// same family through the generated regexes, first match in table order.
    #[test]
    fn generated_regexes_agree_with_the_matcher() {
        let paths = [
            "/v1.0/communications/callRecords/abc",
            "/beta/communications/callRecords/getPstnCalls(fromDateTime=2026-01-01)",
            "/v1.0/users/u1/onlineMeetings/m1/transcripts/t1/content",
            "/v1.0/users/u1/onlineMeetings/getAllTranscripts(meetingOrganizerUserId='u1')",
            "/v1.0/users/u1/onlineMeetings/m1",
            "/v1.0/teams/t1/channels/c1/messages",
            "/v1.0/teams/t1/channels/getAllMessages",
            "/v1.0/teams/t1/channels/getAllRetainedMessages",
            "/v1.0/users/u1/onlineMeetings/m1/attendeeReport",
            "/v1.0/communications/onlineMeetings/m1/attendanceReports",
            "/v1.0//users/u1/chats",
            "/v1.0/users/u1/messages",
            "/v1.0/communicationsx/callrecords",
            "/v1.0/me/onlineMeetings",
        ];
        let compiled: Vec<(&str, Vec<regex::Regex>)> = FAMILIES
            .iter()
            .map(|f| {
                (
                    f.key,
                    f.patterns
                        .iter()
                        .map(|p| regex::Regex::new(&pattern_regex(p)).unwrap())
                        .collect(),
                )
            })
            .collect();
        let slashes = regex::Regex::new("/+").unwrap();
        for path in paths {
            // KQL: tolower(replace_regex(parse_url(RequestUri).Path, @'/+', '/')).
            let normalized = slashes.replace_all(path, "/").to_lowercase();
            let by_kql = compiled
                .iter()
                .find(|(_, res)| res.iter().any(|r| r.is_match(&normalized)))
                .map(|(k, _)| *k);
            assert_eq!(by_kql, family_for_path(path), "{path}");
        }
    }

    #[test]
    fn kql_orders_specific_families_first_and_collapses_slashes() {
        let kql = graph_usage_kql();
        let at = |k: &str| kql.find(&format!("\"{k}\"")).unwrap();
        assert!(at("meeting_transcripts") < at("online_meetings"));
        assert!(at("meeting_artifacts") < at("online_meetings"));
        assert!(kql.contains("replace_regex("), "{kql}");
        assert!(kql.contains("@'/+'"), "{kql}");
    }

    /// The `has_any` prefilter must never drop a row a family could match:
    /// every pattern names at least one prefilter term as a whole segment.
    #[test]
    fn kql_prefilter_terms_cover_every_pattern() {
        let kql = graph_usage_kql();
        assert!(kql.contains("has_any ("), "{kql}");
        for family in FAMILIES {
            for pat in family.patterns {
                assert!(
                    pat.split('/')
                        .any(|seg| USAGE_PREFILTER_TERMS.contains(&seg)),
                    "{pat} names no prefilter term"
                );
            }
        }
        for term in USAGE_PREFILTER_TERMS {
            assert!(kql.contains(&format!("\"{term}\"")), "{term}");
        }
    }

    #[test]
    fn grant_usage_picks_latest_seen_else_not_seen_else_not_tracked() {
        let t = |s: &str| s.parse::<Timestamp>().unwrap();
        let since = t("2026-08-27T00:00:00Z");
        let mut seen: HashMap<&'static str, Timestamp> = HashMap::new();
        seen.insert("call_records", t("2026-11-20T10:00:00Z"));
        assert_eq!(
            grant_usage("CallRecords.Read.All", &seen, since),
            GrantUsage::Seen {
                at: t("2026-11-20T10:00:00Z")
            }
        );
        assert_eq!(
            grant_usage("Chat.Read.All", &seen, since),
            GrantUsage::NotSeen { since }
        );
        assert_eq!(
            grant_usage("RoleManagement.ReadWrite.Directory", &seen, since),
            GrantUsage::NotTracked
        );
        assert_eq!(
            GrantUsage::default(),
            GrantUsage::Unknown {
                reason: UsageUnknownReason::NotChecked
            }
        );
        let v = serde_json::to_value(GrantUsage::NotSeen { since }).unwrap();
        assert_eq!(v["state"], "not_seen");
    }
}
