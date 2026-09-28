# MCP Integration

APM ships with a built-in MCP server under `pm mcp`. The current implementation is token-based, permission-scoped, and requires either an active unlock session or a delegated ephemeral session.

## Generate a token

```bash
pm mcp token
```

The setup flow asks for:

- a token name
- expiry in minutes, where `0` means no expiry
- one or more permission scopes

The scopes exposed by the current code are:

- `read`
- `secrets`
- `write`
- `admin`

## Run the server

```bash
pm mcp serve --token YOUR_TOKEN
```

`pm mcp serve` is intended to be launched by an MCP client over stdio.

Related commands:

- `pm mcp config`
- `pm mcp token`
- `pm mcp list`
- `pm mcp revoke <name_or_token>`

## Session requirements

The server does not unlock the vault by itself. It expects one of these:

- a normal unlocked session from `pm unlock`
- an ephemeral delegated session provided through `APM_EPHEMERAL_ID`

Ephemeral sessions can also be bound to an agent name through `APM_EPHEMERAL_AGENT`.

## Mutation guardrails

Write tools are not single-shot commits. The code uses a preview transaction flow:

1. First call creates a pending transaction and returns a `tx_id`.
2. Second call repeats the tool with `tx_id` and `approve: true`.
3. Successful commits return a receipt string.

This applies to mutation tools such as entry add, edit, and delete operations.

## Tool categories

The MCP implementation covers more than simple vault reads. The current server code includes tooling for:

- entry listing and search
- secret retrieval and TOTP access
- entry mutation
- spaces
- profiles
- cloud sync and cloud config
- audit or history access

See the MCP tools reference for the exact schemas in this repo.

## Client configuration

`pm mcp config` prints a first-run config snippet. `pm mcp token --auto` also tries to update known client config locations automatically.

The code searches common config paths for tools such as:

- Claude Desktop
- Cursor
- VS Code / Cline-style MCP settings

For manual configuration, the server entry is still `pm mcp serve --token ...`.

## Recommended flow

```bash
pm unlock
pm mcp token
pm mcp list
```

Then point your MCP client at the generated tokenized `serve` command.
