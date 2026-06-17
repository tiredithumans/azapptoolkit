# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's
[security advisory flow](https://github.com/tiredithumans/azapptoolkit/security/advisories/new),
so a fix can be prepared and released before the issue is disclosed. Please
include reproduction steps and the affected version (see Help → About, or the
installer filename) where you can.

We aim to acknowledge a report within a few days and to keep you updated as a
fix is developed and shipped via the in-app updater.

## Supported versions

This project is pre-1.0; only the latest released version receives security
fixes. Update to the newest release (the app auto-updates from its configured
endpoint) before reporting.

## Scope

In scope: the desktop app and the workspace crates in this repository —
authentication / token handling, the Graph / Exchange / Key Vault clients,
local data handling, and the update/signing path.

Out of scope: vulnerabilities in Microsoft Entra ID, Microsoft Graph, or other
upstream services (report those to Microsoft); and issues that require a
already-compromised workstation or OS keyring.

## How this app handles your credentials

The security model and the defensive choices behind it (PKCE + CSRF on a
loopback redirect, resource-scoped bearer tokens, same-origin `nextLink`
enforcement, incremental write-scope consent, OS-keyring token storage, and
the dependency-audit gates) are described in the
[Security section of the README](../README.md#security).
