//! Effective mailbox scoping, read-only: resolves each mail permission's
//! verdict (org-wide / scoped / legacy AAP) from `Test-ServicePrincipalAuthorization`
//! rows, cached per principal.

use super::*;

// ---------------- Effective mailbox scoping (read-only) ----------------

/// True when a `Test-ServicePrincipalAuthorization` row is *not* confined to a
/// recipient scope — i.e. the grant reaches every mailbox in the tenant. The
/// `ScopeType` enum returned by EXO uses values like `OrganizationConfig` /
/// `NotApplicable` for org-wide; a custom management scope reports its name in
/// `AllowedResourceScope` with a `*RecipientScope` type. We treat an empty /
/// "Not Applicable" `AllowedResourceScope` as org-wide too, and default to
/// org-wide (the conservative, never-under-report choice) when unsure.
/// Resolves whether a legacy Application Access Policy confines `app_id`'s
/// mailbox access. An AAP applies to the whole application (not per-permission),
/// so a single lookup covers every permission. Only a `RestrictAccess` policy
/// *scopes* access to its group; a `DenyAccess` policy is a blocklist (access to
/// everything *except* the group), which is still effectively org-wide, so it is
/// not reported as scoped. Returns `None` on any Exchange error (the RBAC
/// verdict — org-wide — then stands, never under-reporting risk).
pub(super) async fn legacy_aap_scope(
    exo: &ExchangeClient,
    app_id: &str,
) -> Option<MailPermissionScope> {
    let policies = exo.get_application_access_policies().await.ok()?;
    aap_verdict_for(&policies, app_id)
}

/// Mailbox permission **values** that `sp_object_id` holds as **org-wide Entra
/// app-role grants** — across Microsoft Graph (mail/calendar/contacts) *and* the
/// legacy Office 365 Exchange Online resource (the EWS `full_access_as_app`
/// scope). `Test-ServicePrincipalAuthorization` deliberately *excludes* these —
/// it reports only the Exchange RBAC layer — so a scoped RBAC verdict must be
/// reconciled against them: per Microsoft's RBAC-for-Applications guidance, an
/// un-stripped org-wide grant *unions* with the scoped role to reach every
/// mailbox ("remove the assignment … in Microsoft Entra ID. Otherwise, the union
/// … results in no effective resource scoping"). A legacy Application Access
/// Policy, by contrast, genuinely confines an org-wide grant, so it is *not*
/// reconciled away (see [`verdict_from_rows`] / [`aap_verdict_for`]).
///
/// Reading Graph alone here was an under-report: a surviving org-wide EWS grant
/// reaches every mailbox, but the verdict still read `Scoped`.
///
/// Best-effort: any read failure yields an empty set (no reconciliation) rather
/// than fabricating an org-wide verdict from a transient error.
pub(crate) async fn held_orgwide_mail_grants(
    graph: &GraphClient,
    sp_object_id: &str,
) -> HashSet<String> {
    let Ok(resources) = mailbox_resource_roles(graph).await else {
        return HashSet::new();
    };
    let Ok(assignments) = graph.list_app_role_assignments(sp_object_id).await else {
        return HashSet::new();
    };
    assignments
        .iter()
        // Resolve each grant against the resource it was made on, so an appRole
        // id collision across APIs can't match the wrong permission.
        // Keep the RESOURCE the grant was made on. `resolve_grant` already
        // resolved it; discarding it here and testing the value alone answered
        // `true` for Office 365 Exchange Online's own `Mail.*` appRoles, which
        // RBAC for Applications cannot confine — so an org-wide legacy grant
        // was counted as scopable mailbox reach it could never actually get.
        .filter_map(|a| resolve_grant(&resources, &a.resource_id, &a.app_role_id))
        .filter(|(resource, _, value)| {
            is_scopable_exchange_resource_permission(Some(resource), value)
        })
        .map(|(_, _, value)| value.to_string())
        .collect()
}

/// Resolves the effective Exchange mailbox scoping for each Exchange-scopable
/// permission in `graph_perms`. Primary source: `Test-ServicePrincipalAuthorization`,
/// which reports the **Exchange RBAC layer only** — it deliberately *excludes*
/// permissions granted separately in Microsoft Entra ID. A scoped RBAC verdict is
/// therefore reconciled against `orgwide_granted` (the mail permissions the
/// principal still holds as org-wide Entra app-role grants — see
/// [`held_orgwide_mail_grants`]): an un-stripped org-wide grant *unions* with the
/// scoped role to reach every mailbox, so that permission is reported `OrgWide`,
/// which is what actually catches "scope created but org-wide grant never removed".
/// When the probe *fails*, the verdict depends on why: a
/// principal Exchange can't resolve (a managed identity isn't in its SP store)
/// has no RBAC scope, so it resolves to `OrgWide` — or to `Scoped` if a legacy
/// Application Access Policy confines it; only a genuine 403/consent failure
/// degrades to a propagated error (caller surfaces `Unknown` + a reason). When
/// `enrich` is set, a `Scoped` verdict is augmented with the scope's recipient
/// filter + group count via `Get-ManagementScope` (cached per distinct scope),
/// and the legacy-AAP fallback is consulted; the audit path leaves both off
/// since only the org-wide/scoped distinction affects the score (and `OrgWide`
/// scores identically to a propagated/`Unknown` failure there).
pub(crate) async fn resolve_mail_scopes(
    exo: &ExchangeClient,
    app_id: &str,
    graph_perms: &[String],
    orgwide_granted: &HashSet<String>,
    enrich: bool,
) -> Result<HashMap<String, MailPermissionScope>, ExchangeError> {
    // Callers vet the resource before reaching here — `targets_from_declared`
    // for the manifest paths, the (resource, value) gate in
    // `get_mail_scopes_for_principal` for the held-permission path — and what
    // that vetting proves is that these are Microsoft Graph mail permissions,
    // since the legacy Office 365 Exchange Online namesakes are not confinable.
    // Naming the resource here says so, rather than re-deriving it from the
    // value and getting the legacy ones wrong.
    let scopable: Vec<(&String, &'static str)> = graph_perms
        .iter()
        .filter_map(|p| {
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, p).map(|role| (p, role))
        })
        .collect();
    if scopable.is_empty() {
        return Ok(HashMap::new());
    }

    // Resolve the legacy Application Access Policy up front (detail views only).
    // It serves two roles: the org-wide override on the Ok path below, AND — keyed
    // only on appId, via an independent cmdlet — the authoritative fallback when
    // the probe can't resolve the principal (the managed-identity case). One
    // lookup per app covers every permission; the bulk audit (`enrich == false`)
    // skips it to avoid an extra admin-API call per app.
    let aap_override = if enrich {
        legacy_aap_scope(exo, app_id).await
    } else {
        None
    };

    // Authoritative RBAC-for-Applications verdict.
    let rows = match exo.test_service_principal_authorization(app_id, None).await {
        Ok(rows) => rows,
        Err(err) => {
            // Log a concise code, not the raw body — an Exchange 403 can return a
            // NUL-padded blob that otherwise floods the log.
            tracing::info!(%app_id, code = err.ui_code(), "exchange scoping unavailable");
            // Audit path: propagate so the caller's `unwrap_or_default` scores
            // org-wide (never under-reporting) — byte-for-byte the prior behavior.
            if !enrich {
                return Err(err);
            }
            // Detail path: a legacy AAP can still answer, and a principal Exchange
            // can't resolve simply has no RBAC scope (=> org-wide). Only a genuine
            // 403/consent failure propagates so the UI can offer "Grant consent".
            let fallback = scope_from_rbac_error(err, aap_override)?;
            return Ok(scopable
                .into_iter()
                .map(|(perm, _role)| (perm.clone(), fallback.clone()))
                .collect());
        }
    };

    let mut out = HashMap::new();
    // scope name → (group_count, recipient_filter); `None` = unresolved scope.
    let mut scope_cache: HashMap<String, Option<(u32, String)>> = HashMap::new();
    for (perm, role) in scopable {
        // A composite role (`Application Mail Full Access`, `Application Exchange
        // Full Access`) confers this permission without carrying its role name,
        // so match the granted-permission list too.
        let matching: Vec<&ExoAuthorizationResult> = rows
            .iter()
            .filter(|r| row_grants_permission(r, role, perm))
            .collect();
        let mut verdict = verdict_from_rows(&matching);
        // Apply the legacy-AAP fallback only when RBAC shows org-wide.
        if matches!(verdict, MailPermissionScope::OrgWide)
            && let Some(aap) = &aap_override
        {
            verdict = aap.clone();
        }
        // Reconcile a scoped RBAC verdict against an un-stripped org-wide Entra
        // grant (the probe can't see Entra grants).
        verdict = reconcile_orgwide_grant(verdict, perm, orgwide_granted);
        // Enrich an RBAC management scope with its recipient filter + group
        // count (display only). Legacy-AAP scopes carry no management scope, so
        // they are matched out here.
        if enrich
            && let MailPermissionScope::Scoped {
                scope_name: Some(name),
                mechanism: ScopeMechanism::Rbac,
                ..
            } = &verdict
        {
            let name = name.clone();
            let resolved = match scope_cache.get(&name) {
                Some(hit) => hit.clone(),
                None => {
                    let r = exo
                        .get_management_scope(&name)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|s| s.recipient_filter)
                        .map(|f| (count_member_of_group(&f) as u32, f));
                    scope_cache.insert(name.clone(), r.clone());
                    r
                }
            };
            if let Some((count, filter)) = resolved {
                verdict = MailPermissionScope::Scoped {
                    scope_name: Some(name),
                    recipient_filter: Some(filter),
                    group_count: Some(count),
                    mechanism: ScopeMechanism::Rbac,
                };
            }
        }
        out.insert(perm.clone(), verdict);
    }
    Ok(out)
}

/// Cached, lean (audit-path) mailbox-scope resolution: the same probe as
/// `resolve_mail_scopes(..., enrich=false)` but memoized under a distinct
/// `audit|{app_id}|{perms}` discriminator, so a security-audit **re-run**
/// within the cache TTL skips the per-app `Test-ServicePrincipalAuthorization`
/// round trip (1–5s each — minutes across a mail-heavy tenant).
///
/// The key is intentionally **separate** from the Permissions tab's `held|` /
/// `declared|` verdicts. The lean (`enrich=false`) probe skips the legacy-AAP
/// override, so a permission confined *only* by a legacy Application Access
/// Policy resolves org-wide here but scoped on the enriched detail path —
/// sharing one key would make either surface's verdict depend on the other's
/// cache warmth. Both live under the `{tenant}|mail_scopes|` prefix, so a
/// single `invalidate_app_details` sweep drops them together. Errors are never
/// cached (the audit trips its Exchange breaker on an auth failure, and a
/// transient failure must not pin org-wide for the TTL).
pub(crate) async fn resolve_mail_scopes_audit_cached(
    cache: &Cache,
    tenant_id: &str,
    exo: &ExchangeClient,
    app_id: &str,
    graph_perms: &[String],
    orgwide_granted: &HashSet<String>,
) -> Result<HashMap<String, MailPermissionScope>, ExchangeError> {
    // Nothing scopable ⇒ no probe and no cache entry (matches
    // `resolve_mail_scopes` and the Permissions-tab commands).
    // Pre-vetted by the audit's `declared_values` (resource-aware). See
    // `resolve_mail_scopes`.
    let mut scopable: Vec<&str> = graph_perms
        .iter()
        .filter(|p| exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, p).is_some())
        .map(String::as_str)
        .collect();
    if scopable.is_empty() {
        return Ok(HashMap::new());
    }
    scopable.sort_unstable();
    let key = mail_scopes_key(tenant_id, &format!("audit|{app_id}|{}", scopable.join(",")));
    if let Some(hit) = cache.get::<HashMap<String, MailPermissionScope>>(CacheKind::Lists, &key) {
        return Ok(hit);
    }
    let scopes = resolve_mail_scopes(exo, app_id, graph_perms, orgwide_granted, false).await?;
    cache.put(CacheKind::Lists, key, &scopes);
    Ok(scopes)
}

/// Cache key for a principal's resolved per-permission mailbox scopes:
/// `{tenant}|mail_scopes|{discriminator}`. The discriminator carries
/// `declared|{object_id}` (Permissions tab, manifest), `held|{app_id}|{perms}`
/// (Permissions tab, bare principal), and `audit|{app_id}|{perms}` (the lean
/// security-audit verdict) so the three surfaces never collide. The whole
/// `{tenant}|mail_scopes|` prefix is dropped by
/// `applications::invalidate_app_details`.
pub(crate) fn mail_scopes_key(tenant_id: &str, discriminator: &str) -> String {
    format!("{tenant_id}|mail_scopes|{discriminator}")
}

/// Per-permission effective mailbox scoping for an app's declared
/// mail/calendar/contacts permissions. Drives the Permissions-tab "Scope"
/// column. Degrades gracefully:
/// when the caller is not an Exchange admin (or `Exchange.Manage` is not
/// consented) every entry is `Unknown` rather than a hard error.
#[tauri::command]
pub async fn get_mail_permission_scopes(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<Vec<MailScopeEntry>, UiError> {
    // Resolution rides several Exchange admin-API cmdlets (each a proxied
    // PowerShell invocation, seconds apiece), so successful verdicts are
    // cached — otherwise every Permissions-tab visit re-pays the full round
    // trip. Busted by `invalidate_app_details` (any app/scope mutation) and
    // the TTL; errors are never cached.
    let cache_key = mail_scopes_key(&tenant_id, &format!("declared|{object_id}"));
    // A cache hit returns before any client is built, so the `graph_for` below is
    // NOT a session proof for that path — prove it here, ahead of the read.
    // Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    if let Some(cached) = state
        .cache
        .get::<Vec<MailScopeEntry>>(CacheKind::Lists, &cache_key)
    {
        return Ok(cached);
    }
    let graph = state.graph_for(&tenant_id);
    // The app manifest read and the resource role indexes are independent —
    // overlap them instead of paying serial round trips on a cold Permissions tab.
    let (app, resources) = futures::future::try_join(
        async {
            graph
                .get_application(&object_id)
                .await
                .map_err(UiError::from)
        },
        mailbox_resource_roles(&graph),
    )
    .await?;

    // Declared, Exchange-scopable permissions on this app (Graph mail/calendar/
    // contacts plus the EWS `full_access_as_app` scope).
    let scopable: Vec<String> = targets_from_declared(&app, &resources)
        .into_iter()
        .map(|t| t.graph_value)
        .collect();
    if scopable.is_empty() {
        state
            .cache
            .put(CacheKind::Lists, cache_key, &Vec::<MailScopeEntry>::new());
        return Ok(Vec::new());
    }

    // Mail permissions the SP still holds as org-wide Entra grants — used to
    // reconcile a scoped RBAC verdict (the probe can't see Entra grants).
    // Best-effort: a lookup miss leaves the set empty (no reconciliation).
    let orgwide = match graph.get_service_principal_by_app_id(&app.app_id).await {
        Ok(Some(sp)) => held_orgwide_mail_grants(&graph, &sp.id).await,
        _ => HashSet::new(),
    };

    // Propagate Exchange failures (consent_required / 403 / …) so the UI can
    // show an actionable banner + "Grant consent" button, rather than silently
    // painting every row "Unknown" with no explanation.
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let scopes = resolve_mail_scopes(&exo, &app.app_id, &scopable, &orgwide, true).await?;

    // `scopable` is `targets_from_declared` output — already resource-vetted.
    let entries: Vec<MailScopeEntry> = scopable
        .into_iter()
        .filter_map(|p| {
            let role = exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, &p)?;
            let scope = scopes
                .get(&p)
                .cloned()
                .unwrap_or(MailPermissionScope::Unknown);
            Some(MailScopeEntry {
                graph_permission: p,
                exchange_role: role.to_string(),
                scope,
            })
        })
        .collect();
    state.cache.put(CacheKind::Lists, cache_key, &entries);
    Ok(entries)
}

/// Effective mailbox scoping for an arbitrary service principal identified by
/// its `app_id`, given the Graph permission values it holds. Unlike
/// [`get_mail_permission_scopes`] this takes the permissions directly rather
/// than reading an app registration's manifest, so it works for principals with
/// no `Application` object — notably **managed identities**, whose mail
/// permissions are *granted* app-role assignments. Same graceful degradation:
/// `Unknown` (never under-reported) when Exchange is unavailable.
#[tauri::command]
pub async fn get_mail_scopes_for_principal(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    permissions: Vec<PrincipalPermission>,
) -> Result<Vec<MailScopeEntry>, UiError> {
    // Resolve each held permission against the resource that exposes it, and
    // keep only the confinable ones. The value-only gate this replaces would
    // accept an Office 365 Exchange Online `Mail.Read` — a permission no
    // management scope can confine — and go on to report a mailbox scoping
    // verdict for it. Both callers already filtered this way client-side, but a
    // command is only as safe as its own gate.
    let scopable: Vec<(String, &'static str)> = permissions
        .iter()
        .filter_map(|p| {
            exchange_role_for_resource_permission(&p.resource_app_id, &p.value)
                .map(|role| (p.value.clone(), role))
        })
        .collect();
    // Nothing scopable ⇒ no Exchange call (and no needless consent prompt).
    if scopable.is_empty() {
        return Ok(Vec::new());
    }

    // Same cache as `get_mail_permission_scopes`, keyed on the *held* permission
    // set (caller-supplied), so the same app viewed as an app registration
    // (declared manifest) and as a bare principal can't collide. Keyed on
    // resource|value pairs now, so two principals differing only in which
    // resource exposes a same-named permission get different entries.
    let cache_key = {
        let mut sorted: Vec<String> = permissions
            .iter()
            .map(|p| format!("{}|{}", p.resource_app_id, p.value))
            .collect();
        sorted.sort();
        mail_scopes_key(&tenant_id, &format!("held|{app_id}|{}", sorted.join(",")))
    };
    // A cache hit returns before any client is built, so the `graph_for` below is
    // NOT a session proof for that path — prove it here, ahead of the read.
    // Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    if let Some(cached) = state
        .cache
        .get::<Vec<MailScopeEntry>>(CacheKind::Lists, &cache_key)
    {
        return Ok(cached);
    }

    // Reconcile a scoped RBAC verdict against the principal's un-stripped
    // org-wide Entra grants (best-effort; empty set ⇒ no reconciliation).
    let graph = state.graph_for(&tenant_id);
    let orgwide = match graph.get_service_principal_by_app_id(&app_id).await {
        Ok(Some(sp)) => held_orgwide_mail_grants(&graph, &sp.id).await,
        _ => HashSet::new(),
    };

    let exo = exchange_client_checked(&state, &tenant_id).await?;
    // The vetted values only. Value-keyed output is unambiguous here because the
    // two confinable sets are disjoint: Microsoft Graph contributes the `Mail.*`
    // / `Calendars.*` / `Contacts.*` / `MailboxSettings.*` family, Office 365
    // Exchange Online contributes `full_access_as_app` and nothing else.
    let values: Vec<String> = scopable.iter().map(|(v, _)| v.clone()).collect();
    let scopes = resolve_mail_scopes(&exo, &app_id, &values, &orgwide, true).await?;

    let entries: Vec<MailScopeEntry> = scopable
        .into_iter()
        .map(|(value, role)| {
            let scope = scopes
                .get(&value)
                .cloned()
                .unwrap_or(MailPermissionScope::Unknown);
            MailScopeEntry {
                graph_permission: value,
                exchange_role: role.to_string(),
                scope,
            }
        })
        .collect();
    state.cache.put(CacheKind::Lists, cache_key, &entries);
    Ok(entries)
}
