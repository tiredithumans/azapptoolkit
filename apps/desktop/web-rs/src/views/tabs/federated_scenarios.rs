//! Pure subject/issuer builders for the federated-credential scenario picker.
//! Each mirrors what the Azure portal auto-builds for the matching
//! "Federated credential scenario" choice, so values stay byte-identical to
//! what the token's `sub`/`iss` claims must carry.

/// Issuer for every GitHub Actions workflow token.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The audience Entra recommends (and the portal defaults to) for workload
/// identity federation token exchange.
pub const DEFAULT_AUDIENCE: &str = "api://AzureADTokenExchange";

/// GitHub Actions "Entity type" — which workflow context the trust is pinned
/// to. The portal offers exactly these four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubEntity {
    Environment,
    Branch,
    PullRequest,
    Tag,
}

impl GithubEntity {
    /// Maps the `<option value>` key back to the entity (defaults to
    /// Environment, the portal's default).
    pub fn from_key(key: &str) -> Self {
        match key {
            "branch" => Self::Branch,
            "pull_request" => Self::PullRequest,
            "tag" => Self::Tag,
            _ => Self::Environment,
        }
    }

    /// Label for the entity's value input; `None` when the entity takes no
    /// value (Pull request).
    pub fn value_label(self) -> Option<&'static str> {
        match self {
            Self::Environment => Some("GitHub environment name"),
            Self::Branch => Some("GitHub branch name"),
            Self::PullRequest => None,
            Self::Tag => Some("GitHub tag name"),
        }
    }
}

/// Builds the GitHub Actions subject claim for an org/repo + entity, exactly
/// as GitHub mints it (and the portal pre-fills it). Pattern matching is not
/// supported by Entra — values must match the workflow configuration exactly.
pub fn github_subject(org: &str, repo: &str, entity: GithubEntity, value: &str) -> String {
    let prefix = format!("repo:{org}/{repo}");
    match entity {
        GithubEntity::Environment => format!("{prefix}:environment:{value}"),
        GithubEntity::Branch => format!("{prefix}:ref:refs/heads/{value}"),
        GithubEntity::PullRequest => format!("{prefix}:pull_request"),
        GithubEntity::Tag => format!("{prefix}:ref:refs/tags/{value}"),
    }
}

/// Builds the Kubernetes service-account subject claim
/// (`system:serviceaccount:{namespace}:{serviceAccount}`).
pub fn k8s_subject(namespace: &str, service_account: &str) -> String {
    format!("system:serviceaccount:{namespace}:{service_account}")
}

/// Issuer for tokens minted by this Entra tenant — what the "Customer managed
/// keys" / "Managed identity" scenarios trust (subject = the managed
/// identity's service-principal object id).
pub fn entra_issuer(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_subjects_cover_all_entity_types() {
        assert_eq!(
            github_subject("contoso", "app", GithubEntity::Environment, "production"),
            "repo:contoso/app:environment:production"
        );
        assert_eq!(
            github_subject("contoso", "app", GithubEntity::Branch, "main"),
            "repo:contoso/app:ref:refs/heads/main"
        );
        assert_eq!(
            github_subject("contoso", "app", GithubEntity::PullRequest, "ignored"),
            "repo:contoso/app:pull_request"
        );
        assert_eq!(
            github_subject("contoso", "app", GithubEntity::Tag, "v2"),
            "repo:contoso/app:ref:refs/tags/v2"
        );
    }

    #[test]
    fn entity_keys_round_trip_and_pull_request_takes_no_value() {
        assert_eq!(GithubEntity::from_key("branch"), GithubEntity::Branch);
        assert_eq!(
            GithubEntity::from_key("pull_request"),
            GithubEntity::PullRequest
        );
        assert_eq!(GithubEntity::from_key("tag"), GithubEntity::Tag);
        // Unknown/default keys fall back to the portal default.
        assert_eq!(GithubEntity::from_key(""), GithubEntity::Environment);
        assert!(GithubEntity::PullRequest.value_label().is_none());
        assert!(GithubEntity::Branch.value_label().is_some());
    }

    #[test]
    fn k8s_subject_and_entra_issuer_format() {
        assert_eq!(
            k8s_subject("erp8asle", "pod-identity-sa"),
            "system:serviceaccount:erp8asle:pod-identity-sa"
        );
        assert_eq!(
            entra_issuer("11111111-2222-3333-4444-555555555555"),
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
        );
    }
}
