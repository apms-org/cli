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
- `pm export compare <file>`

`pm add` currently supports 25 types. `pm get` is the main interactive search and management flow.

### Import, export and compare

`pm import <file>` detects the format, compares the file with your vault and imports only what you choose. It reads:

| Source | Files | Passkeys |
| --- | --- | --- |
| APM | export `.json` (plain or encrypted), `vault.dat` and backups, v1 `.json`, `.csv`, `.txt` | Yes |
| Bitwarden | `.json`, password protected `.json` (PBKDF2-SHA256 or Argon2id), `.zip`, `.csv` | Yes, from `.json` |
| 1Password | `.1pux`, `.csv` | No. 1Password leaves passkeys out of its exports |
| KeePass and KeePassXC | XML export, `.csv` | Yes, KeePassXC passkeys from XML |
| FIDO Credential Exchange (CXF 1.0) | `.json` (full header or a bare account) | Yes |
| Chrome, Edge, Brave, Firefox, Safari | passwords `.csv` | No |
| Authenticator apps | `.txt` with `otpauth://` links | No |

Every row gets a status: new, already in your vault, conflict (same name, different contents), possible duplicate (the same login, key or passkey under another name) or can't be imported (with the reason). Conflicts and duplicates take one of four actions: skip, merge (fill empty fields, add websites, notes and passkeys, keep your values), replace (take the file's values; your old values stay in the item's history) or keep both. The suggested action never loses a passkey or an account.

- `--dry-run` shows the comparison and stops. `--show-secrets` shows secret values in it. `--json` prints the plan or the result.
- `--on-conflict` and `--on-duplicate` take `skip`, `merge`, `replace`, `keep-both` or `ask`. `-y` imports without asking.
- `--space <name>` imports into a space. `--keep-spaces` turns Bitwarden folders, 1Password vaults, KeePass groups and APM spaces into spaces.
- `-p` gives the export password; on a terminal APM asks for it when needed.
- Logins' one-time codes become linked authenticator items. Codes APM cannot generate (Steam, HOTP, 8 digits, non-30s, SHA-256) are listed as can't be imported.
- Password history becomes item history. One import is one vault commit, so `pm lgit undo` reverts it.
- `pm import --formats` lists every format and how to export it from the other app.

`pm export` writes `--format apm` (default: everything, including passkeys, spaces, favorites and, with `--files`, documents and media; encrypted with Argon2id and AES-256-GCM when you set a password), `cxf` (FIDO Credential Exchange, passkeys included), `bitwarden` (Bitwarden `.json` with passkeys; password protected with `-p` or `--encrypt`), `csv` or `txt`. On a terminal it offers to encrypt.

- `--type`, `--space` and `--no-passkeys` narrow the export. `--without-password` leaves secrets out of `csv` and `txt`.
- `--dry-run` shows what would be exported and what the format leaves out, for example "CSV cannot hold passkeys".
- It never overwrites a file without `--force` or a confirmation. Files are written with mode 0600.
- CXF 1.0 only allows passkeys whose sign counter is 0. APM keeps a counter at 0 when it starts there, as synced passkeys do, so passkeys you create or import stay exportable.

`pm export compare <file>` compares the vault with an earlier export or backup: only in the file, changed, the same, and only in your vault.

### Sessions

- `pm unlock [--timeout 1h] [--inactivity 15m]`
- `pm lock`
- `pm autolock [--idle 15m|never] [--max 1h|never] [--sleep on|off]`
- `pm session issue`
- `pm session list`
- `pm session revoke <id>`

`pm autolock` shows or changes when the vault locks itself. The policy is saved in the vault and shared by the desktop app (Settings, Sessions, Auto-lock), `pm` sessions and the browser extension. Durations take Go syntax (`15m`, `4h`) or a number of minutes, and round up to whole minutes; `never` turns a limit off and prints a warning. `pm unlock` uses the policy unless you pass `--timeout` or `--inactivity`. With `--sleep on`, a `pm` session also ends once the computer has slept (macOS and Linux).

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

### Browser extension

- `pm extension link [--browser chrome,edge] [--id <extension id>] [--no-wait]`
- `pm extension status`
- `pm extension unlink`
- `pm bridge serve [--port N] [--locked] [--idle 15m]`
- `pm bridge status [--port N]`
- `pm bridge token [--show]`
- `pm bridge rotate`
- `pm passkeys list [query]`
- `pm passkeys rename <credentialId|rpId> <label>`
- `pm passkeys rm <credentialId|rpId> [--yes]`
- `pm totp link <entry> <domain>`
- `pm totp unlink <entry> [domain]`

`pm extension link` lets the extension work without the desktop app. It registers `pm` as a native messaging host (`dev.apm.bridge`) with every Chromium browser it finds (Chrome, Edge, Brave, Arc, Vivaldi, Chromium), allowed only for the APM extension, then waits in the terminal. If the extension is not paired yet it shows a code; check that the terminal shows the same one and answer `y`. You do this once. From then on, whenever the app is closed, the browser starts `pm` on its own and the extension sends the same requests over stdio. `pm` holds the key only while it runs, locks on the vault's auto-lock policy, and exits when the browser closes. While the app is running, the extension uses the app. `pm extension unlink` removes the registration; `pm bridge rotate` revokes the pairing.

`pm bridge serve` serves the same loopback API as the desktop app, for CLI-only use. Pair a browser by approving the code it shows, or paste the token from `pm bridge token --show`. It locks on the vault's auto-lock policy unless you pass `--idle`.

A login can hold several websites: `website` plus `urls` ("Other websites" in the desktop app). The extension offers the login on any of them, and can add the site you are on to a login.

While the vault is unlocked, the desktop app and `pm bridge serve` fetch each login's logo from the site itself (never from a third-party service) and cache it under `icons/` in the APM config directory. Turn this off with the `siteIcons` vault setting ("Show website icons" in the desktop app), or set `APM_ICONS_OFFLINE=1`. See [Storage](storage.md#browser-bridge-and-website-icons) for the cache layout.

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
