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