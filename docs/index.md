# APM Documentation

APM is a Go-based password manager with two binaries:

- `pm` for personal vaults
- `pm-team` for shared organizational vaults

The source tree implements more than a basic password CLI. It includes sessions, recovery, cloud sync, MCP access, Windows autofill, shell injection alongside the core encrypted vault.

## What APM currently does

- Stores 25 personal secret types in one encrypted vault.
- Uses explicit unlock sessions with expiry and inactivity controls.
- Supports delegated ephemeral sessions for automation and AI-agent access.
- Syncs encrypted vault blobs to Google Drive, GitHub, and Dropbox.
- Exposes a built-in MCP server with scoped tokens and mutation previews.
- Offers Windows autofill and autocomplete support plus shell-side secret injection.
- Serves the APM browser extension (logins, one-time codes, passkeys) from the desktop app, or, after `pm extension link`, from `pm` started by the browser itself when the app is closed.
- Provides a separate team edition with departments, approvals, roles, and shared entries.

## Quick start

```bash
go build -o pm .
pm setup
pm unlock
pm add
pm get github
pm lock
```

Team edition:

```bash
cd team
go build -o pm-team .
```

## Documentation map

### [Getting Started](getting-started/index.md)

- [Installation](getting-started/installation.md)
- [First steps](getting-started/first-steps.md)
- [Features](getting-started/features.md)
- [Getting help](getting-started/help.md)

### [Guides](guides/index.md)

- [Vault management](guides/vault-management.md)
- [Cloud synchronization](guides/cloud-sync.md)
- [Using `.apmignore`](guides/apmignore.md)
- [Injecting secrets into your shell](guides/inject.md)
- [Generating TOTP codes](guides/totp.md)
- [Managing sessions](guides/sessions.md)
- [MCP integration](guides/mcp-integration.md)
- [Team edition](guides/team-edition.md)
- [Import and export](guides/import-export.md)


### [Concepts](concepts/index.md)

- [Architecture](concepts/architecture.md)
- [Encryption](concepts/encryption.md)
- [Vault format](concepts/vault-format.md)
- [Secret types](concepts/secret-types.md)
- [Security profiles](concepts/security-profiles.md)
- [Policy engine](concepts/policy-engine.md)
- [Sessions](concepts/sessions.md)
- [Cloud sync](concepts/cloud-sync.md)
- [MCP](concepts/mcp.md)
- [Recovery](concepts/recovery.md)

### [Reference](reference/index.md)

- [CLI reference](reference/cli.md)
- [Storage](reference/storage.md)
- [Environment variables](reference/environment-variables.md)
- [MCP tools](reference/mcp-tools.md)
- [Policies](reference/policies.md)
- [`.apmignore`](reference/apmignore.md)

### [Team](team/index.md)

- [RBAC and roles](team/rbac.md)
- [Departments](team/departments.md)
- [Approval workflows](team/approvals.md)

## Important implementation notes

- The current personal vault format is `APMVAULT` v4.
- Built-in profiles are `standard`, `hardened`, `paranoid`, and `legacy`.
- Personal `pm add` supports 25 entry types; team `pm-team add` currently supports 22 shared entry types.
