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

    /// Batched [`Self::list_site_permissions`]: resolves many sites' application
    /// permissions in `$batch` POSTs of 20 instead of one GET per site, and
    /// returns one `Result` per input site **in order**.
    ///
    /// This is what makes the tenant-wide sweep affordable: at the sweep's
    /// 5000-site cap it turns 5000 requests into 250, on the endpoint family the
    /// transport documents as the throttle-happiest.
    ///
    /// A sub-response that still carries an `@odata.nextLink` is followed
    /// outside the batch by [`Self::finish_paged_batch`], so a site whose grant
    /// list spans pages is never silently truncated — the same contract the
    /// single-site path guarantees.
    pub async fn batch_list_site_permissions(
        &self,
        site_ids: &[String],
    ) -> Result<Vec<Result<Vec<SitePermission>>>> {
        let token = self.sharepoint_token()?;
        let urls: Vec<String> = site_ids
            .iter()
            .map(|id| format!("/sites/{id}/permissions"))
            .collect();
        let pages: Vec<Result<Paged<SitePermission>>> =
            self.batch_get_json_scoped(token, &urls).await?;
        self.finish_paged_batch(pages).await
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

    /// Resolves an operator-pasted SharePoint URL to the securable a Selected
    /// grant would address: the site itself, a list / document library, or an
    /// item inside one.
    ///
    /// Three reads in the common case — a site URL costs one, a library two, a
    /// folder three. The URL may be a clean browser address or a "Copy link"
    /// share URL; both normalise through [`site_relative_path`].
    ///
    /// Note it starts from [`site_collection_url`], **not** the pasted URL:
    /// [`site_lookup_path`] passes a clean deep path through verbatim, so
    /// `.../sites/Finance/Shared Documents/Invoices` would be handed to Graph as
    /// a site address and 404. Only the share-link form was ever truncated,
    /// because only share links reached that code path before.
    ///
    /// Subsites are found by walking outward from the site collection
    /// ([`Self::resolve_within_or_descend`]) rather than by probing the pasted
    /// path inward, which would spend a 404 per segment on every ordinary URL.
    ///
    /// **Boundary:** items are resolved through the site's *drives*, so an item
    /// inside a plain (non-document) list resolves only as far as the list. That
    /// is the honest answer rather than a guess: `Files.SelectedOperations.Selected`
    /// cannot reach such an item anyway, and `ListItems.*` addressing needs an
    /// item id this path has no way to derive from a URL.
    pub async fn resolve_sharepoint_resource(
        &self,
        target_url: &str,
    ) -> Result<ResolvedSharePointResource> {
        let site = self
            .get_site_by_url(&site_collection_url(target_url))
            .await?;
        self.resolve_within_or_descend(site, target_url).await
    }

    /// Resolves `target_url` inside `site`, descending into a subsite when the
    /// site itself holds nothing matching.
    ///
    /// A tenant with `/sites/Finance/Reports/Shared Documents/...` has the
    /// library on the **subsite**, whose drives the parent's `/drives` listing
    /// never returns. Each step consumes one path segment, so the walk is
    /// bounded by the URL's own depth and costs nothing on the common path.
    async fn resolve_within_or_descend(
        &self,
        site: Site,
        target_url: &str,
    ) -> Result<ResolvedSharePointResource> {
        let mut site = site;
        loop {
            let (outcome, site_back) = self.resolve_within(site, target_url).await?;
            match outcome {
                Some(resolved) => return Ok(resolved),
                None => {
                    let Some(next_url) = descend_one_segment(&site_back, target_url) else {
                        return Err(GraphError::Protocol(format!(
                            "{target_url} did not resolve to a list, library or item in this site"
                        )));
                    };
                    match self.get_site_by_url(&next_url).await {
                        Ok(next) => site = next,
                        // Not a subsite either — the path names nothing this
                        // toolkit can grant against.
                        Err(_) => {
                            return Err(GraphError::Protocol(format!(
                                "{target_url} did not resolve to a list, library or item in this site"
                            )));
                        }
                    }
                }
            }
        }
    }

    /// One level of [`Self::resolve_within_or_descend`]. Returns `Ok((None, site))`
    /// when nothing in `site` matches, handing the site back so the caller can
    /// descend without re-reading it.
    async fn resolve_within(
        &self,
        site: Site,
        target_url: &str,
    ) -> Result<(Option<ResolvedSharePointResource>, Site)> {
        let site_url = site.web_url.clone().ok_or_else(|| {
            GraphError::Protocol("SharePoint returned a site with no webUrl".into())
        })?;
        let site_name = site.display_name.clone();
        let base = ResolvedSharePointResource {
            level: SelectedScopeLevel::Site,
            site_id: site.id.clone(),
            site_url: Some(site_url.clone()),
            site_name: site_name.clone(),
            list_id: None,
            list_name: None,
            item_id: None,
            drive_id: None,
            is_folder: false,
            display_path: site_name.clone().unwrap_or_else(|| site_url.clone()),
        };

        // Not inside this site at all — the caller can still try a subsite,
        // whose webUrl extends this one.
        let Some(rel) = site_relative_path(&site_url, target_url) else {
            return Ok((None, site));
        };
        if rel.is_empty() {
            return Ok((Some(base), site));
        }

        // Longest match wins. Segment-wise comparison already rejects a sibling
        // library whose name merely shares a prefix, so this only decides
        // between a library and something nested under it.
        let drives = self.list_site_drives(&site.id).await?;
        let best = drives
            .iter()
            .filter_map(|d| {
                let web = d.web_url.as_deref()?;
                let inner = site_relative_path(web, target_url)?;
                Some((d, web.len(), inner))
            })
            .max_by_key(|(_, len, _)| *len);

        let Some((drive, _, inner)) = best else {
            // No library matched: the URL may still name a plain list, or sit in
            // a subsite this site knows nothing about.
            let hit = self.resolve_site_list(&base, target_url).await?;
            return Ok((hit, site));
        };

        if inner.is_empty() {
            let list = self.get_drive_list(&drive.id).await?;
            let list_name = list.label().map(str::to_string);
            return Ok((
                Some(ResolvedSharePointResource {
                    level: SelectedScopeLevel::List,
                    display_path: join_path(&[
                        base.display_path.as_str(),
                        name_or(&list_name, "list"),
                    ]),
                    list_id: Some(list.id),
                    list_name,
                    drive_id: Some(drive.id.clone()),
                    ..base
                }),
                site,
            ));
        }

        let item = self.get_drive_item_by_path(&drive.id, &inner).await?;
        let ids = item.sharepoint_ids.clone().unwrap_or_default();
        let (Some(list_id), Some(item_id)) = (ids.list_id, ids.list_item_id) else {
            // Without both ids there is no listItem address to grant against,
            // and guessing one would grant somewhere the operator didn't ask.
            return Err(GraphError::Protocol(format!(
                "SharePoint returned no list/item ids for {target_url}; \
                 the grant endpoint cannot be addressed"
            )));
        };
        let drive_name = drive.name.clone();
        let drive_id = drive.id.clone();
        Ok((
            Some(ResolvedSharePointResource {
                // An item reached through a drive is by construction inside a
                // document library, which is exactly the reach `Files.*`
                // describes.
                level: SelectedScopeLevel::File,
                display_path: join_path(&[
                    base.display_path.as_str(),
                    name_or(&drive_name, "library"),
                    &inner.replace('/', " / "),
                ]),
                list_id: Some(list_id),
                list_name: drive_name,
                item_id: Some(item_id),
                drive_id: Some(drive_id),
                is_folder: item.is_folder(),
                ..base
            }),
            site,
        ))
    }

    /// Fallback for a URL that names a plain list rather than a document
    /// library. Split out so [`Self::resolve_sharepoint_resource`] reads as the
    /// hierarchy walk it is.
    async fn resolve_site_list(
        &self,
        base: &ResolvedSharePointResource,
        target_url: &str,
    ) -> Result<Option<ResolvedSharePointResource>> {
        let lists = self.list_site_lists(&base.site_id).await?;
        let hit = lists
            .iter()
            .filter_map(|l| {
                let web = l.web_url.as_deref()?;
                let inner = site_relative_path(web, target_url)?;
                inner.is_empty().then_some((l, web.len()))
            })
            .max_by_key(|(_, len)| *len);
        let Some((list, _)) = hit else {
            return Ok(None);
        };
        let list_name = list.label().map(str::to_string);
        Ok(Some(ResolvedSharePointResource {
            level: SelectedScopeLevel::List,
            display_path: join_path(&[base.display_path.as_str(), name_or(&list_name, "list")]),
            list_id: Some(list.id.clone()),
            list_name,
            ..base.clone()
        }))
    }

    // ---- Sub-site Selected scopes (Lists./ListItems./Files.SelectedOperations.Selected) ----
    //
    // Everything below grants against a securable *inside* a site collection.
    // Two things differ from the site endpoints above and neither is optional:
    //
    // 1. The request body carries **`grantedToV2`** (a single identity set), not
    //    `grantedToIdentities` (an array). Graph's driveItem reference states
    //    outright that the array forms are not accepted here.
    // 2. A grant at any of these levels **breaks permission inheritance** on the
    //    target and consumes one of the library's unique permission scopes, so
    //    the caller is expected to have warned the operator first.

    /// Lists a site's document libraries. `web_url` is the field the resource
    /// resolver prefix-matches an operator's pasted URL against.
    pub async fn list_site_drives(&self, site_id: &str) -> Result<Vec<Drive>> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/drives?$select=id,name,webUrl&$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let page: Paged<Drive> = self.scoped_get_retried(token, &url).await?;
        self.collect_pages_from(
            page,
            |u| async move { self.scoped_get_retried(token, &u).await },
        )
        .await
    }

    /// Lists a site's lists — document libraries *and* ordinary lists, which is
    /// what makes `Lists.SelectedOperations.Selected` reachable for a list that
    /// has no drive behind it.
    pub async fn list_site_lists(&self, site_id: &str) -> Result<Vec<SiteList>> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists?$select=id,name,displayName,webUrl&$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let page: Paged<SiteList> = self.scoped_get_retried(token, &url).await?;
        self.collect_pages_from(
            page,
            |u| async move { self.scoped_get_retried(token, &u).await },
        )
        .await
    }

    /// The list backing a document library.
    ///
    /// Used instead of matching `webUrl`s between `/drives` and `/lists`: a
    /// library-root grant needs the **list** id, and this join is exact where a
    /// URL comparison is a guess.
    pub async fn get_drive_list(&self, drive_id: &str) -> Result<SiteList> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/drives/{drive_id}/list?$select=id,name,displayName,webUrl",
            self.base_url
        );
        self.scoped_get_retried(token, &url).await
    }

    /// Resolves a library-relative path (`Invoices/2026`) to a driveItem.
    ///
    /// `rel_path` must already be percent-encoded — [`site_relative_path`]
    /// produces it that way by routing through `url::Url`, so a hand-typed URL
    /// with literal spaces and a browser-copied one with `%20` both arrive here
    /// in the single form Graph accepts.
    ///
    /// Note the trailing `:` before the query string: without it Graph reads
    /// `?$select=` as part of the addressed path and 400s.
    pub async fn get_drive_item_by_path(
        &self,
        drive_id: &str,
        rel_path: &str,
    ) -> Result<DriveItem> {
        let token = self.sharepoint_token()?;
        let select = "id,name,webUrl,folder,file,sharepointIds";
        let url = if rel_path.is_empty() {
            format!("{}/drives/{drive_id}/root?$select={select}", self.base_url)
        } else {
            format!(
                "{}/drives/{drive_id}/root:/{rel_path}:?$select={select}",
                self.base_url
            )
        };
        self.scoped_get_retried(token, &url).await
    }

    /// Lists the application permissions on a list.
    pub async fn list_list_permissions(
        &self,
        site_id: &str,
        list_id: &str,
    ) -> Result<Vec<SelectedPermission>> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists/{list_id}/permissions?$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let page: Paged<SelectedPermission> = self.scoped_get_retried(token, &url).await?;
        self.collect_pages_from(
            page,
            |u| async move { self.scoped_get_retried(token, &u).await },
        )
        .await
    }

    /// Lists the application permissions on a list item (a folder or a file).
    pub async fn list_list_item_permissions(
        &self,
        site_id: &str,
        list_id: &str,
        item_id: &str,
    ) -> Result<Vec<SelectedPermission>> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists/{list_id}/items/{item_id}/permissions?$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let page: Paged<SelectedPermission> = self.scoped_get_retried(token, &url).await?;
        self.collect_pages_from(
            page,
            |u| async move { self.scoped_get_retried(token, &u).await },
        )
        .await
    }

    /// Grants an application `roles` on a whole list / document library —
    /// the `Lists.SelectedOperations.Selected` model.
    pub async fn grant_list_permission(
        &self,
        site_id: &str,
        list_id: &str,
        app_id: &str,
        app_display_name: &str,
        roles: &[String],
    ) -> Result<SelectedPermission> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists/{list_id}/permissions",
            self.base_url
        );
        let body = granted_to_v2_body(app_id, app_display_name, roles);
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    /// Grants an application `roles` on a single list item — the model behind
    /// `ListItems.SelectedOperations.Selected` and, for an item in a document
    /// library, `Files.SelectedOperations.Selected`.
    ///
    /// The listItem endpoint is used for files as well as folders: Microsoft
    /// documents it as *the* form for a folder, and a file is a list item, so
    /// one call site covers both rather than branching on the facet.
    pub async fn grant_list_item_permission(
        &self,
        site_id: &str,
        list_id: &str,
        item_id: &str,
        app_id: &str,
        app_display_name: &str,
        roles: &[String],
    ) -> Result<SelectedPermission> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists/{list_id}/items/{item_id}/permissions",
            self.base_url
        );
        let body = granted_to_v2_body(app_id, app_display_name, roles);
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    pub async fn remove_list_permission(
        &self,
        site_id: &str,
        list_id: &str,
        permission_id: &str,
    ) -> Result<()> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists/{list_id}/permissions/{permission_id}",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }

    pub async fn remove_list_item_permission(
        &self,
        site_id: &str,
        list_id: &str,
        item_id: &str,
        permission_id: &str,
    ) -> Result<()> {
        let token = self.sharepoint_token()?;
        let url = format!(
            "{}/sites/{site_id}/lists/{list_id}/items/{item_id}/permissions/{permission_id}",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }
}

/// The request body every **sub-site** permission endpoint takes.
///
/// Kept apart from the site body built inline in [`GraphClient::grant_site_permission`]
/// on purpose: that one sends `grantedToIdentities` (an array), and these
/// endpoints accept only `grantedToV2` (a single identity set). Sharing one
/// builder between them would make the wrong shape a one-character mistake.
fn granted_to_v2_body(app_id: &str, app_display_name: &str, roles: &[String]) -> serde_json::Value {
    serde_json::json!({
        "roles": roles,
        "grantedToV2": {
            "application": { "id": app_id, "displayName": app_display_name }
        }
    })
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
    let decorated = segs_of(rest);
    let was_decorated = decorated.len() != undecorated_segments(&decorated).len()
        || decorated
            .first()
            .is_some_and(|s| s.len() >= 2 && s.starts_with(':') && s.ends_with(':'));
    let mut segs = undecorated_segments(&decorated);
    if was_decorated {
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

/// Joins the parts of an operator-facing resource path.
fn join_path(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" / ")
}

/// The name Graph gave the resource, or a generic noun when it gave none — an
/// unnamed library must still render as something an operator can read.
fn name_or<'a>(name: &'a Option<String>, fallback: &'a str) -> &'a str {
    name.as_deref().unwrap_or(fallback)
}

/// Splits a server-relative path into its non-empty segments.
fn segs_of(rest: &str) -> Vec<&str> {
    rest.split('/').filter(|s| !s.is_empty()).collect()
}

/// Strips the `/:x:/r/` app-token decoration a SharePoint "Copy link" URL
/// carries, leaving the real server-relative segments.
///
/// Shared by the two consumers that disagree about what to do next:
/// [`site_lookup_path`] truncates the result to the site collection (all the
/// site permission endpoints operate on), while [`site_relative_path`] keeps the
/// whole path, because the library and folder *below* the site are precisely
/// what an item-level grant is addressing.
fn undecorated_segments<'a>(segs: &[&'a str]) -> Vec<&'a str> {
    let mut out = segs.to_vec();
    // A leading `:x:`-style app token marks a document "Copy link" URL
    // (`:x:` Excel, `:w:` Word, `:b:` PDF, `:f:` folder, …).
    if out
        .first()
        .is_some_and(|s| s.len() >= 2 && s.starts_with(':') && s.ends_with(':'))
    {
        out.remove(0);
        // Drop the `r` (redirect) / `s` (share) marker that follows the token.
        if out.first().is_some_and(|s| matches!(*s, "r" | "s")) {
            out.remove(0);
        }
    }
    out
}

/// Parses a user-supplied URL into `(lowercase host, undecorated path segments)`
/// with every segment percent-encoded the way Graph's path addressing expects.
///
/// Routing through `url::Url` is what makes the encoding question disappear: a
/// hand-typed `.../Shared Documents/Q1 Invoices` and a browser-copied
/// `.../Shared%20Documents/Q1%20Invoices` both normalise to the same encoded
/// segments, so callers never hand-roll a percent codec. A missing scheme is
/// tolerated because operators paste bare hostnames.
fn url_host_and_segments(raw: &str) -> Option<(String, Vec<String>)> {
    let trimmed = raw.trim();
    let absolute = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&absolute).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let raw_segs = segs_of(parsed.path());
    let segs = undecorated_segments(&raw_segs)
        .into_iter()
        .map(str::to_string)
        .collect();
    Some((host, segs))
}

/// The site-collection root of `target_url`:
/// `https://contoso.sharepoint.com/sites/Finance` for anything under that site,
/// or the bare host when the URL carries no managed path.
///
/// Exists because [`site_lookup_path`] only truncates the "Copy link" share
/// form — a clean deep URL is passed through verbatim, which Graph answers with
/// a 404 because `.../Shared Documents/Invoices` is not a site address. Every
/// SharePoint URL an operator can paste starts at a site collection, and that is
/// the one address the site endpoints accept, so the resolver always begins
/// here and walks down from it.
fn site_collection_url(target_url: &str) -> String {
    let Some((host, segs)) = url_host_and_segments(target_url) else {
        return target_url.trim().to_string();
    };
    // `/sites/Finance`, `/teams/Sales`, `/personal/user_contoso_com` — the three
    // managed paths, each followed by exactly one name segment.
    let root: Vec<&str> = match segs
        .iter()
        .position(|s| matches!(s.as_str(), "sites" | "teams" | "personal"))
    {
        Some(i) if segs.len() > i + 1 => segs[..=i + 1].iter().map(String::as_str).collect(),
        // A root-site URL (`https://contoso.sharepoint.com/Shared Documents/…`)
        // has no managed path; the tenant root *is* the site collection.
        _ => Vec::new(),
    };
    if root.is_empty() {
        format!("https://{host}")
    } else {
        format!("https://{host}/{}", root.join("/"))
    }
}

/// The URL of `site` extended by one segment of `target_url` — the next
/// candidate when a target isn't in `site` but may be in a subsite of it.
///
/// `None` once the walk has consumed the whole path, which ends the descent.
fn descend_one_segment(site: &Site, target_url: &str) -> Option<String> {
    let site_url = site.web_url.as_deref()?;
    let rel = site_relative_path(site_url, target_url)?;
    let next = rel.split('/').find(|s| !s.is_empty())?;
    Some(format!("{}/{next}", site_url.trim_end_matches('/')))
}

/// The path of `target_url` relative to the site collection at `site_url`,
/// percent-encoded for Graph's `root:/{path}` addressing — or `None` when the
/// target isn't inside that site.
///
/// An empty string means "the site itself", which is how the resolver tells a
/// site-level target apart from one that reaches into a library.
///
/// Comparison is case-insensitive because SharePoint treats its paths that way,
/// and segment-wise rather than by string prefix so that a sibling site whose
/// name merely starts with the same characters (`/sites/Finance-Archive` under
/// `/sites/Finance`) is correctly rejected.
fn site_relative_path(site_url: &str, target_url: &str) -> Option<String> {
    let (site_host, site_segs) = url_host_and_segments(site_url)?;
    let (target_host, target_segs) = url_host_and_segments(target_url)?;
    if site_host != target_host || target_segs.len() < site_segs.len() {
        return None;
    }
    if !site_segs
        .iter()
        .zip(&target_segs)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return None;
    }
    Some(target_segs[site_segs.len()..].join("/"))
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

    const SITE: &str = "https://contoso.sharepoint.com/sites/Finance";

    #[test]
    fn site_relative_path_normalises_encoding_from_either_input_shape() {
        // A browser-copied URL arrives percent-encoded...
        assert_eq!(
            site_relative_path(
                SITE,
                "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Invoices/2026"
            ),
            Some("Shared%20Documents/Invoices/2026".to_string())
        );
        // ...and a hand-typed one with literal spaces must produce the same
        // address, because Graph only accepts the encoded form.
        assert_eq!(
            site_relative_path(
                SITE,
                "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices/2026"
            ),
            Some("Shared%20Documents/Invoices/2026".to_string())
        );
        // Non-ASCII names encode too, rather than being passed through raw.
        assert_eq!(
            site_relative_path(
                SITE,
                "https://contoso.sharepoint.com/sites/Finance/Documents/Rapports/Été"
            ),
            Some("Documents/Rapports/%C3%89t%C3%A9".to_string())
        );
    }

    #[test]
    fn site_relative_path_reports_the_site_itself_as_empty() {
        assert_eq!(site_relative_path(SITE, SITE), Some(String::new()));
        // Trailing slash and case differences are SharePoint-insignificant.
        assert_eq!(
            site_relative_path(SITE, "https://contoso.sharepoint.com/sites/finance/"),
            Some(String::new())
        );
        // A missing scheme is tolerated — operators paste bare hostnames.
        assert_eq!(
            site_relative_path(SITE, "contoso.sharepoint.com/sites/Finance/Documents"),
            Some("Documents".to_string())
        );
    }

    #[test]
    fn site_relative_path_rejects_targets_outside_the_site() {
        // Different site collection.
        assert_eq!(
            site_relative_path(SITE, "https://contoso.sharepoint.com/sites/HR/Documents"),
            None
        );
        // Different tenant host.
        assert_eq!(
            site_relative_path(
                SITE,
                "https://fabrikam.sharepoint.com/sites/Finance/Documents"
            ),
            None
        );
        // The comparison is segment-wise, so a sibling site whose name merely
        // starts with the same characters is NOT inside it. A string prefix
        // check would wrongly accept this and grant against the wrong site.
        assert_eq!(
            site_relative_path(
                SITE,
                "https://contoso.sharepoint.com/sites/Finance-Archive/Documents"
            ),
            None
        );
        // Shorter than the site path.
        assert_eq!(
            site_relative_path(SITE, "https://contoso.sharepoint.com/sites"),
            None
        );
    }

    #[test]
    fn site_relative_path_keeps_the_full_path_of_a_copy_link_url() {
        // `site_lookup_path` truncates a share link to the site collection,
        // which is right for the site endpoints. The item resolver needs the
        // opposite: the library and folder below the site are the target.
        assert_eq!(
            site_lookup_path(
                "https://contoso.sharepoint.com/:f:/r/sites/Finance/Shared%20Documents/Invoices?csf=1&web=1"
            ),
            "/sites/contoso.sharepoint.com:/sites/Finance"
        );
        assert_eq!(
            site_relative_path(
                SITE,
                "https://contoso.sharepoint.com/:f:/r/sites/Finance/Shared%20Documents/Invoices?csf=1&web=1"
            ),
            Some("Shared%20Documents/Invoices".to_string())
        );
    }

    #[test]
    fn site_collection_url_truncates_a_deep_url_to_its_site_root() {
        // The bug this exists for: `site_lookup_path` passes a clean deep URL
        // through verbatim, so Graph is asked to resolve
        // `/sites/Finance/Shared Documents/Invoices` as a *site* and 404s. Only
        // the share-link form was ever truncated.
        assert_eq!(
            site_lookup_path(
                "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Invoices"
            ),
            "/sites/contoso.sharepoint.com:/sites/Finance/Shared%20Documents/Invoices",
            "the site lookup itself is unchanged — this is why the resolver must truncate first"
        );
        for url in [
            "https://contoso.sharepoint.com/sites/Finance",
            "https://contoso.sharepoint.com/sites/Finance/",
            "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents",
            "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices/2026",
            "https://contoso.sharepoint.com/:f:/r/sites/Finance/Shared%20Documents/Invoices?csf=1",
        ] {
            assert_eq!(
                site_collection_url(url),
                "https://contoso.sharepoint.com/sites/Finance",
                "{url}"
            );
        }
        // The other two managed paths.
        assert_eq!(
            site_collection_url("https://contoso.sharepoint.com/teams/Sales/Docs/Plan.docx"),
            "https://contoso.sharepoint.com/teams/Sales"
        );
        assert_eq!(
            site_collection_url(
                "https://contoso-my.sharepoint.com/personal/user_contoso_com/Documents/Report.pdf"
            ),
            "https://contoso-my.sharepoint.com/personal/user_contoso_com"
        );
        // A root-site URL has no managed path — the tenant root is the site.
        assert_eq!(
            site_collection_url("https://contoso.sharepoint.com/Shared%20Documents/Budget.xlsx"),
            "https://contoso.sharepoint.com"
        );
    }

    #[test]
    fn descend_one_segment_walks_outward_one_level_at_a_time() {
        let site = |url: &str| Site {
            id: "site-1".to_string(),
            display_name: None,
            web_url: Some(url.to_string()),
        };
        // A library inside a subsite: the parent's `/drives` never returns it,
        // so the resolver descends rather than giving up.
        let target = "https://contoso.sharepoint.com/sites/Finance/Reports/Shared%20Documents/Q1";
        assert_eq!(
            descend_one_segment(
                &site("https://contoso.sharepoint.com/sites/Finance"),
                target
            ),
            Some("https://contoso.sharepoint.com/sites/Finance/Reports".to_string())
        );
        assert_eq!(
            descend_one_segment(
                &site("https://contoso.sharepoint.com/sites/Finance/Reports"),
                target
            ),
            Some(
                "https://contoso.sharepoint.com/sites/Finance/Reports/Shared%20Documents"
                    .to_string()
            )
        );
        // Once the walk has consumed the path there is nowhere left to descend,
        // which is what ends the loop instead of spinning.
        assert_eq!(descend_one_segment(&site(target), target), None);
        // A site the target isn't under at all yields nothing.
        assert_eq!(
            descend_one_segment(&site("https://contoso.sharepoint.com/sites/HR"), target),
            None
        );
    }

    #[test]
    fn granted_to_v2_body_never_emits_the_site_endpoints_array_form() {
        let body = granted_to_v2_body("app-1", "Contoso Reader", &["read".to_string()]);
        // The sub-site endpoints accept `grantedToV2` only — Graph's driveItem
        // reference rejects `grantedToIdentities` and `grantedTo` outright.
        assert_eq!(body["grantedToV2"]["application"]["id"], "app-1");
        assert_eq!(
            body["grantedToV2"]["application"]["displayName"],
            "Contoso Reader"
        );
        assert!(
            body.get("grantedToIdentities").is_none(),
            "the array form belongs to the site endpoint and is rejected here"
        );
        assert!(body.get("grantedTo").is_none());
        assert_eq!(body["roles"][0], "read");
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
