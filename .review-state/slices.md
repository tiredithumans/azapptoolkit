# The 26 finder slices already run (key → scope)

## backend-crates
- core-audit: crates/azapptoolkit-core/src/audit/** (scoring, permissions, types, credentials, tests)
- core-infra-a: core/src/{cache.rs, cache/, http_retry.rs, http_error.rs, settings.rs, private_file.rs, token.rs, net.rs, defaults.rs, constants.rs, lib.rs}
- core-infra-b: core/src/{models.rs, scoping.rs, capabilities.rs, federation.rs, cloud.rs, azure_roles.rs, identity.rs, reauth.rs, redirect.rs, thumbprint.rs, restore_plan.rs}
- auth: crates/azapptoolkit-auth/** + src-tauri/src/token_adapter.rs + commands/{auth,session,consent}.rs
- graph: crates/azapptoolkit-graph/**
- exchange: crates/azapptoolkit-exchange/**
- small-crates: crates/azapptoolkit-{keyvault,arm,permissions}/**
- toolchain-runner: ran cargo test/clippy(pedantic)/tree/machete on shared crates + web-rs host tests + wasm check

## backend-app (apps/desktop/src-tauri)
- cmd-apps: commands/applications/**, commands/{credentials,expose_api,app_roles,permissions,search,guid,progress,mod}.rs
- cmd-audit: commands/{audit,bulk,remediation,readiness,dispatch,throttle,graph_err}.rs
- cmd-scoping: commands/exchange/**, commands/sharepoint.rs, commands/permission_tester.rs
- cmd-sso-ent: commands/sso/**, commands/{enterprise_application,managed_identity,graph_roles,gallery,keyvault,keyvault_rbac,usage,activity,conditional_access}.rs
- cmd-platform: src/{lib,main,state,dto,cert,build,build_support}.rs, commands/{backup,restore,export,diagnostics,updater,config,defaults}.rs, tauri.conf.json, capabilities/, updater-build.json, Cargo.toml
- invariants-dto-ipc: src-tauri/tests/**, crates/azapptoolkit-dto/**, IPC parity generate_handler! ↔ bindings

## frontend (apps/desktop/web-rs)
- fe-core: src/{lib,main,constants,util}.rs, state/**, hooks/**, components/ui/**, ~20 small components, views/{shell,sign_in,config_screen,pairing}.rs, styles.css
- fe-apps: views/{application_list,applications_view,application_detail_pane}.rs, views/tabs/**, most dialogs, components/{uri_list_editor,owner_picker,directory_search,permission_picker,group_autocomplete,vault_picker}.rs, bindings/applications etc.
- fe-enterprise: enterprise app list/detail pane/**, managed_identities/**, sso_certificates_dashboard, claims_editor, sso_summary, sso_wizard_dialog, gallery_dialog, bindings
- fe-security: views/audit_view/**, security_view, consent/app-permission grant views, credentials_dashboard, bulk_actions_view, bulk_action_bar, scope_wizard, scoping components, scope_remediation dialog, bindings
- fe-tools: home_dashboard, dr, settings_view, key_vault_view, permission_tester_view, readiness_view, resource_access/**, global_search, cache_diagnostics_dialog, remaining bindings
- fe-tests: tests/** (GUI shards), ipc_mock/**, demo/**, test_support/**, build.rs, build_support.rs, Trunk.toml, index.html, Cargo.toml features/profiles
- fe-a11y-ux: cross-cutting accessibility + UX consistency over web-rs

## cross-cutting
- tooling: justfile, .github/workflows/*, dependabot, codeql, deny.toml, audit.toml, scripts/setup.*, .claude/hooks|skills|rules|settings, Cargo profiles/lints, rust-toolchain, .gitignore
- docs-drift: README, DEVELOPMENT.md, AGENTS.md, CLAUDE.md, docs/architecture/*, CONTRIBUTING, SECURITY, templates, docs/operator-rbac/*, CHANGELOG structure
- security: cross-cutting defensive review (logs, at-rest, injection, SSRF, Tauri surface, auth flow, supply chain, least privilege)
- deps-hygiene: all Cargo.toml/Cargo.lock, unused deps, duplicate majors, features, tauri-sys pin, advisory ignores
- graph-api-currency: endpoints/api-versions vs Microsoft Learn; unused newer Graph capabilities
- product-gaps: feature-gap analysis vs README/issues #109 #110; partially built features
