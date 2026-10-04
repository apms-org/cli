# Storage Reference

File locations and data layout for all APM artifacts.

---

## Vault File

| Item          | Location                                  |
| :------------ | :---------------------------------------- |
| Default vault | `./vault.dat` (current working directory) |
| Override      | `APM_VAULT_PATH` environment variable     |

The vault is a single binary file in [V4 format](../concepts/vault-format.md) containing all encrypted entries, configuration, cloud tokens, MCP tokens, and telemetry.

---

## Session Files

| File                                 | Purpose                  |
| :----------------------------------- | :----------------------- |
| `$TEMP/pm_session_global.json`       | Global session (default) |
| `$TEMP/pm_session_{SESSION_ID}.json` | Shell-scoped session     |

Session files contain:

- Session ID
- Unlock/expiry timestamps
- Inactivity timeout
- Read-only flag
- Hashed master password

---

## Ephemeral Session Store

| File                                 | Purpose                |
| :----------------------------------- | :--------------------- |
| `$TEMP/.apm_ephemeral_sessions.json` | All ephemeral sessions |

Contains an array of ephemeral session objects with IDs, bindings, expiry, and revocation status.

---

## Audit Log

| File                       | Purpose                  |
| :------------------------- | :----------------------- |
| `~/.config/apm/audit.json` | Tamper-evident audit log |

Append-only log of vault interactions with timestamps, actions, users, and hostnames.

---

## Autofill State

| File                             | Purpose                     |
| :------------------------------- | :-------------------------- |
| `$TEMP/.apm_autofill_state.json` | Daemon PID, port, and token |

Created when the autofill daemon starts. Contains the PID, loopback address, bearer token, and start time.

---

## Browser Bridge and Website Icons

These live in the APM config directory: `~/Library/Application Support/apm/` on macOS, `~/.config/apm/` on Linux, `%AppData%\apm\` on Windows. `pm extension link` also writes `dev.apm.bridge.json` into each browser's `NativeMessagingHosts` folder (on Windows, into `native-messaging\` here, with a registry key under `HKCU\Software\<browser>\NativeMessagingHosts`).

| File                    | Purpose                                                           |
| :---------------------- | :---------------------------------------------------------------- |
| `bridge_token`          | Pairing token the browser extension sends with every bridge call  |
| `native_host.json`      | What `pm extension link` registered: the vault, the `pm` binary, the browsers |
| `extension_link.json`   | A pairing request waiting for `pm extension link` to answer; removed once answered |
| `extension_seen.json`   | When a paired extension last reached `pm` over native messaging   |
| `icons/<sha256>.img`    | A cached website logo, named by the SHA-256 of its host           |
| `icons/<sha256>.json`   | Its host, image type, fetch time and whether the fetch worked     |

The icon cache holds at most 2000 sites and drops the oldest first. Files are written with mode `0600` in a `0700` directory. The cache is not encrypted and each `.json` file names its host, so treat the folder as a list of sites that have logos. Delete the folder, or choose "Clear icon cache" in the desktop app, to empty it. A logo is fetched only from the site itself, over HTTPS, while the vault is unlocked; failures are retried after 3 days and logos refresh after 30 days.

---

## Cloud Configuration

Cloud provider credentials (OAuth tokens, PATs) are stored **inside the encrypted vault** — not in separate files. This ensures they're protected by the same encryption and travel with the vault during sync.

---

## .apmignore

| Location                     | Purpose           |
| :--------------------------- | :---------------- |
| Same directory as vault file | Primary location  |
| Current working directory    | Fallback location |

---

## Policy Files

Policy files are loaded on demand from a user-specified directory. They are not persisted in the vault.

```bash
pm policy load ./policies/
```

---

## Temporary Files

| Pattern                | Purpose                |
| :--------------------- | :--------------------- |
| `$TEMP/apm_export_*`   | Export files           |
| `$TEMP/apm_recovery_*` | Recovery ceremony data |

Temporary files are cleaned up after use.