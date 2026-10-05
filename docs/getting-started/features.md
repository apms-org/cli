# Features

This page lists the capabilities that are implemented in the current codebase.

## Personal vault

- Local encrypted vault stored as `APMVAULT`, current format v4
- 25 structured personal secret types
- Spaces for compartmentalizing entries inside one vault
- Interactive search, details, editing, deletion, and TOTP access
- Password generation, audit logging, trust scoring, and health scoring

## Crypto and profiles

- Built-in profiles: `standard`, `hardened`, `paranoid`, `legacy`
- Cipher support: `aes-gcm` and `xchacha20-poly1305`
- Versioned header metadata for vault crypto parameters
- `pm cinfo` and `pm profile` for inspection and tuning

## Sessions and automation

- Standard unlock sessions with expiry and inactivity controls
- Read-only session mode
- Shell-scoped sessions via `APM_SESSION_ID`
- Ephemeral delegated sessions via `pm session issue`
- Shell injection with `pm inject` and `.apminject`

## Recovery and auth

- Recovery email registration with SMTP verification
- Recovery key generated during setup and shown once
- One-time recovery codes
- Recovery passkey registration and verification
- Quorum share setup and trustee-based recovery
- Security alert level controls and recovery-related status commands

## Cloud sync

- Google Drive sync
- GitHub sync
- Dropbox sync
- Provider diff and selective merge flow
- Provider-specific `.apmignore` filtering before upload

## Browser extension

- Loopback bridge on `127.0.0.1:41417`, served by the desktop app or `pm extension serve`, with pairing; with `pm extension link`, the browser starts `pm` itself when the app is closed
- Fill logins and one-time codes, save new logins, and create and use passkeys stored in the vault
- Several websites per login (`website` plus `urls`), with "Fill and remember" to add the current site
- Website logos fetched only from each site itself and cached locally, with a `siteIcons` switch

## AI access

- Built-in MCP server with permission-scoped tokens

## Team edition

The separate `pm-team` module adds:

- organizations
- departments
- roles and permission overrides
- approval workflows
- shared entry management
