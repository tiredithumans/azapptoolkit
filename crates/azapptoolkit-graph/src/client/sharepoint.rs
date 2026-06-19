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
