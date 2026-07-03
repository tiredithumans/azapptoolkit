use super::*;

impl GraphClient {
    /// Resolves a SharePoint site by its browser URL (e.g.
    /// `https://contoso.sharepoint.com/sites/Marketing`) to a Graph site,
    /// whose composite `id` is needed for the permission endpoints. Reads via
    /// the SharePoint scope: `/sites/{id}/permissions` (the next calls) require
    /// `Sites.FullControl.All`, which the default read token lacks.
    pub async fn get_site_by_url(&self, site_url: &str) -> Result<Site> {
        let token = self.sharepoint_token()?;
        let url = format!("{}{}", self.base_url, site_lookup_path(site_url));
        self.scoped_get_retried(token, &url).await
    }

    /// Lists a site's application permissions, following `nextLink` until
    /// exhausted — a site whose grant list spans pages must not silently
    /// truncate (the sweep, the permission tester, and the Sites.Selected
    /// conversion all count on the full set).
    pub async fn list_site_permissions(&self, site_id: &str) -> Result<Vec<SitePermission>> {
        let token = self.sharepoint_token()?;
        let url = format!("{}/sites/{site_id}/permissions", self.base_url);
        let page: Paged<SitePermission> = self.scoped_get_retried(token, &url).await?;
        self.collect_pages_from(
            page,
            |u| async move { self.scoped_get_retried(token, &u).await },
        )
        .await
    }

    /// Enumerates the tenant's SharePoint sites via `GET /sites?search=*`,
    /// following `nextLink` until exhausted or `max` is reached. Rides the
    /// SharePoint scope like the permission endpoints (`Sites.FullControl.All`
    /// covers the read), so the whole site-permission sweep needs one consent.
    ///
    /// Boundary: the delegated search endpoint returns team/communication site
    /// collections and subsites — personal (OneDrive) sites are not included,
    /// and `/sites/getAllSites` (which is) is application-permission-only, so
    /// it is out of reach by design for this delegated-only app.
    pub async fn list_all_sites(&self, max: usize) -> Result<Vec<Site>> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites?search=*&$select=id,displayName,webUrl&$top=200",
            self.base_url
        );
        let mut page: Paged<Site> = self.scoped_get_retried(token, &url).await?;
        let mut out = Vec::new();
        out.append(&mut page.items);

        const MAX_PAGES: usize = 200;
        let mut pages = 1usize;

        while out.len() < max {
            let Some(next) = page.next_link.take() else {
                break;
            };
            if !same_origin(&self.base_url, &next) {
                return Err(GraphError::Protocol(
                    "refusing to follow nextLink to a different origin".into(),
                ));
            }
            if pages >= MAX_PAGES {
                return Err(GraphError::Protocol(
                    "site paging exceeded the page limit".into(),
                ));
            }
            page = self.scoped_get_retried(token, &next).await?;
            out.append(&mut page.items);
            pages += 1;
        }
        out.truncate(max);
        Ok(out)
    }

    /// Grants an application the given `roles` (e.g. `["read"]` / `["write"]`)
    /// on a site via the Sites.Selected model.
    pub async fn grant_site_permission(
        &self,
        site_id: &str,
        app_id: &str,
        app_display_name: &str,
        roles: &[String],
    ) -> Result<SitePermission> {
        let token = self.sharepoint_token()?;
        let url = format!("{}/sites/{site_id}/permissions", self.base_url);
        let body = serde_json::json!({
            "roles": roles,
            "grantedToIdentities": [
                { "application": { "id": app_id, "displayName": app_display_name } }
            ]
        });
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    pub async fn remove_site_permission(&self, site_id: &str, permission_id: &str) -> Result<()> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/permissions/{permission_id}",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }
}

/// Translates a user-supplied SharePoint URL into the Graph `/sites/...`
/// lookup path used by [`GraphClient::get_site_by_url`].
///
/// A clean site URL (`https://contoso.sharepoint.com/sites/Marketing`) maps to
/// `/sites/{host}:/sites/Marketing`, and the bare tenant root to `/sites/{host}`.
/// But "Copy link" in SharePoint hands users a *document* URL that embeds an app
/// token segment (`/:x:/r/` for Excel, `:w:` Word, `:b:` PDF, `:f:` folder, …),
/// a redirect marker, the document library, the file, and a query string — e.g.
/// `https://contoso.sharepoint.com/:x:/r/sites/Marketing/Shared%20Documents/Book.xlsx?d=w..&web=1`.
/// Passing that through verbatim makes Graph reject the `:x:` segment with
/// `Resource not found for the segment ':x:'`. When an app token is present we
/// strip the decoration and keep only the site collection (managed path + name),
/// which is what the permissions endpoints operate on. URLs without an app token
/// are passed through unchanged so subsite paths keep resolving as before.
fn site_lookup_path(site_url: &str) -> String {
    let trimmed = site_url.trim().trim_end_matches('/');
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    // Drop any query string / fragment (sharing links carry ?d=..&csf=1&web=1&e=..).
    let without_query = without_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let (host, rest) = match without_query.split_once('/') {
        Some((h, p)) => (h, p),
        None => (without_query, ""),
    };
    let mut segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    // A leading `:x:`-style app token marks a document "Copy link" URL.
    if segs
        .first()
        .is_some_and(|s| s.len() >= 2 && s.starts_with(':') && s.ends_with(':'))
    {
        segs.remove(0);
        // Drop the `r` (redirect) / `s` (share) marker that follows the token.
        if segs.first().is_some_and(|s| matches!(*s, "r" | "s")) {
            segs.remove(0);
        }
        // The remaining path runs past the site collection into the document
        // library + file; keep only the managed path and site/personal name.
        if let Some(i) = segs
            .iter()
            .position(|s| matches!(*s, "sites" | "teams" | "personal"))
        {
            segs.truncate(i + 2);
        }
    }
    let rel = segs.join("/");
    if rel.is_empty() {
        format!("/sites/{host}")
    } else {
        format!("/sites/{host}:/{rel}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_lookup_path_handles_clean_root_and_subsite_urls() {
        // Clean site collection URL.
        assert_eq!(
            site_lookup_path("https://contoso.sharepoint.com/sites/Marketing"),
            "/sites/contoso.sharepoint.com:/sites/Marketing"
        );
        // Trailing slash is tolerated.
        assert_eq!(
            site_lookup_path("https://contoso.sharepoint.com/sites/Marketing/"),
            "/sites/contoso.sharepoint.com:/sites/Marketing"
        );
        // Bare tenant root has no relative path.
        assert_eq!(
            site_lookup_path("https://contoso.sharepoint.com"),
            "/sites/contoso.sharepoint.com"
        );
        // Subsite paths (no app token) are preserved verbatim.
        assert_eq!(
            site_lookup_path("https://contoso.sharepoint.com/sites/Marketing/Team"),
            "/sites/contoso.sharepoint.com:/sites/Marketing/Team"
        );
    }

    #[test]
    fn site_lookup_path_strips_document_copy_link_decoration() {
        // The "Copy link" form that produced `Resource not found for the
        // segment ':x:'`: app token + redirect + library + file + query string.
        assert_eq!(
            site_lookup_path(
                "https://contoso.sharepoint.com/:x:/r/sites/Marketing/Shared%20Documents/Book.xlsx?d=w123&csf=1&web=1&e=abc"
            ),
            "/sites/contoso.sharepoint.com:/sites/Marketing"
        );
        // Word doc on a Teams-provisioned site.
        assert_eq!(
            site_lookup_path(
                "https://contoso.sharepoint.com/:w:/r/teams/Sales/Docs/Plan.docx?web=1"
            ),
            "/sites/contoso.sharepoint.com:/teams/Sales"
        );
        // OneDrive (personal) sharing link.
        assert_eq!(
            site_lookup_path(
                "https://contoso-my.sharepoint.com/:b:/r/personal/user_contoso_com/Documents/Report.pdf?csf=1"
            ),
            "/sites/contoso-my.sharepoint.com:/personal/user_contoso_com"
        );
    }
}
