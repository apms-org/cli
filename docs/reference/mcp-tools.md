# MCP Tools Reference

Complete reference for every tool exposed by the APM MCP server, including schemas, required permissions, and transaction behavior.

---

## Read Tools

### `list_entries`

List all entries in the vault (metadata only).

**Required scope:** `read`

**Returns:** Array of entry summaries with IDs, names, types, spaces, and creation dates. Sensitive fields (passwords, keys) are not included.

---

### `search_entries`

Search entries by query string.

**Required scope:** `read`

**Parameters:**

| Parameter | Type     | Required | Description          |
| :-------- | :------- | :------: | :------------------- |
| `query`   | `string` |    ✅     | Search query (fuzzy) |
| `space`   | `string` |    ❌     | Filter by space      |
| `type`    | `string` |    ❌     | Filter by entry type |

**Returns:** Matching entries with relevance scoring.

---

### `get_entry`

Get a specific entry by ID or name.

**Required scope:** `read` (metadata) or `secrets` (sensitive fields)

**Parameters:**

| Parameter        | Type     | Required | Description              |
| :--------------- | :------- | :------: | :----------------------- |
| `id`             | `string` |    ❌     | Entry UUID               |
| `name`           | `string` |    ❌     | Entry name (fuzzy match) |
| `include_secret` | `bool`   |    ❌     | Include sensitive fields |

**Notes:** If `include_secret` is true, the `secrets` scope is required. Without it, passwords, keys, and tokens are redacted.

---

## Secret Tools

### `decrypt_entry`

Retrieve the full entry including all sensitive fields.

**Required scope:** `secrets`

**Parameters:**

| Parameter | Type     | Required | Description |
| :-------- | :------- | :------: | :---------- |
| `id`      | `string` |    ✅     | Entry UUID  |

---

### `get_totp`

Generate a TOTP code for a specific entry.

**Required scope:** `secrets`

**Parameters:**

| Parameter | Type     | Required | Description       |
| :-------- | :------- | :------: | :---------------- |
| `account` | `string` |    ✅     | TOTP account name |

**Returns:** Current 6-digit TOTP code and seconds remaining.

---

## Write Tools

All write tools use [transaction guardrails](../concepts/mcp.md#transaction-guardrails).

### `add_entry`

Add a new entry to the vault.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description                  |
| :-------- | :------- | :------: | :--------------------------- |
| `type`    | `string` |    ✅     | Entry type                   |
| `fields`  | `object` |    ✅     | Entry fields (type-specific) |
| `space`   | `string` |    ❌     | Target space                 |

**Transaction flow:**

1. The call queues a pending request and returns its `tx_id`. Nothing is written yet.
2. You approve or reject the request in the desktop app (**Settings → AI access**). The assistant cannot approve it.

---

### `edit_entry`

Edit an existing entry.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description    |
| :-------- | :------- | :------: | :------------- |
| `id`      | `string` |    ✅     | Entry UUID     |
| `fields`  | `object` |    ✅     | Updated fields |

---

### `delete_entry`

Delete an entry.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description    |
| :-------- | :------- | :------: | :------------- |
| `id`      | `string` |    ✅     | Entry UUID     |

---

### `manage_spaces`

Create, switch, or remove spaces.

**Required scope:** `write`

**Parameters:**

| Parameter | Type     | Required | Description                     |
| :-------- | :------- | :------: | :------------------------------ |
| `action`  | `string` |    ✅     | `create`, `switch`, or `remove` |
| `name`    | `string` |    ✅     | Space name                      |

---

### `cloud_sync`

Trigger a cloud synchronization.

**Required scope:** `write`

---

## Admin Tools

### `manage_profiles`

View or change the encryption profile.

**Required scope:** `admin`

---

### `cloud_config`

View or modify cloud provider configuration.

**Required scope:** `admin`

---

### `get_history`

Retrieve vault modification history.

**Required scope:** `admin`

---

### `get_audit_logs`

Read the audit log.

**Required scope:** `admin`

---

## Transaction Guardrails Summary

| Tool            | Uses Transaction | Call returns            | Commit                          |
| :-------------- | :--------------: | :---------------------- | :------------------------------ |
| `add_entry`     |        ✅         | Pending request + tx_id | When you approve it in the app  |
| `edit_entry`    |        ✅         | Pending request + tx_id | When you approve it in the app  |
| `delete_entry`  |        ✅         | Pending request + tx_id | When you approve it in the app  |
| `manage_spaces` |        ❌         | —                       | Executes immediately            |
| All read tools  |        ❌         | —                       | Executes immediately            |

---

## Error Codes

| Code                  | Description                        |
| :-------------------- | :--------------------------------- |
| `PERMISSION_DENIED`   | Token lacks required scope         |
| `SESSION_REQUIRED`    | No active APM session              |
| `ENTRY_NOT_FOUND`     | Entry ID/name not found            |
| `TRANSACTION_EXPIRED` | Request expired before you approved it |
| `INVALID_PARAMETERS`  | Missing or malformed parameters    |
| `VAULT_LOCKED`        | Vault is not unlocked              |