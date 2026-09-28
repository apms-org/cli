# CLI Reference

This reference reflects the command trees defined in the current source.

## Personal binary: `pm`

### Core vault flow

- `pm setup`
- `pm unlock`
- `pm readonly <mins>`
- `pm lock`
- `pm mode`
- `pm cinfo`
- `pm info`

### Entries and retrieval

- `pm add [type]`
- `pm get [query]`
- `pm gen`
- `pm totp [entry_name]`
- `pm import <file>`
- `pm export`

`pm add` currently supports 25 types. `pm get` is the main interactive search and management flow.

### Sessions

- `pm session issue`
- `pm session list`
- `pm session revoke <id>`

Ephemeral sessions can be bound to host, PID, and agent identity.

### Recovery and auth

- `pm auth email [address]`
- `pm auth recover`
- `pm auth reset`
- `pm auth change`
- `pm auth alerts`
- `pm auth level [1-3]`
- `pm auth quorum-setup`
- `pm auth quorum-recover`
- `pm auth passkey register`
- `pm auth passkey verify`
- `pm auth passkey disable`
- `pm auth codes generate`
- `pm auth codes status`

### Profiles, spaces, and policy

- `pm profile list`
- `pm profile current`
- `pm profile set <name>`
- `pm profile edit [name]`
- `pm profile create <name>`
- `pm space create [name]`
- `pm space switch [name]`
- `pm space list`
- `pm policy load [name]`
- `pm policy show`
- `pm policy clear`

### Cloud

- `pm cloud init [gdrive|github|dropbox|all]`
- `pm cloud sync [gdrive|github|dropbox]`
- `pm cloud auto-sync`
- `pm cloud get [gdrive|github|dropbox] [retrieval_key|repo]`
- `pm cloud diff [gdrive|github|dropbox]`
- `pm cloud delete [gdrive]`
- `pm cloud reset`

Notes:

- Google Drive and Dropbox support `APM_PUBLIC` and `self_hosted` modes.
- GitHub uses token-based auth and a repository target.
- `cloud get` can work with provider identifiers such as repo, file ID, or Dropbox path.

### MCP

- `pm mcp config`
- `pm mcp token`
- `pm mcp list`
- `pm mcp revoke [name_or_token]`
- `pm mcp serve`

### Auditing and diagnostics

- `pm health`
- `pm trust`
- `pm audit`
- `pm loaded`
- `pm compromise`
- `pm update`

### Optional command trees

Depending on build and runtime state, `pm` also exposes:

- `pm inject ...`

## Team binary: `pm-team`

### Session and identity

- `pm-team init <org_name> <admin_username>`
- `pm-team login <username>`
- `pm-team whoami`
- `pm-team logout`

### Departments

- `pm-team dept list`
- `pm-team dept create <name>`
- `pm-team dept switch <username> <dept_id>`

### Users

- `pm-team user list`
- `pm-team user add <username>`
- `pm-team user remove <username>`
- `pm-team user promote <username> <role>`
- `pm-team user roles`
- `pm-team user permission grant <username> <permission>`
- `pm-team user permission revoke <username> <permission>`

### Shared vault operations

- `pm-team add`
- `pm-team list`
- `pm-team get [query]`
- `pm-team gen`
- `pm-team edit <entry_name>`
- `pm-team delete <entry_name>`

Implementation notes:

- `pm-team list` currently prints only some shared entry categories.
- `pm-team get` is the main search path for broader retrieval.
- `pm-team edit` is only fully implemented for a smaller subset of entry types.

### Approvals and reporting

- `pm-team approvals list`
- `pm-team approvals approve <idx>`
- `pm-team approvals deny <idx>`
- `pm-team export`
- `pm-team audit`
- `pm-team health`
- `pm-team info`

### Type-specific shared namespaces

The team binary also registers type-focused command groups with `add`, `list`, and `get` subcommands:

- `pm-team password`
- `pm-team totp`
- `pm-team apikey`
- `pm-team token`
- `pm-team note`
- `pm-team ssh`
- `pm-team cert`
- `pm-team wifi`
- `pm-team recovery`
- `pm-team banking`
- `pm-team doc`
- `pm-team gov`
- `pm-team medical`
- `pm-team travel`
- `pm-team contact`
- `pm-team cloud`
- `pm-team k8s`
- `pm-team docker`
- `pm-team ssh-config`
- `pm-team cicd`
- `pm-team license`
- `pm-team legal`
