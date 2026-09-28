# Architecture

APM is structured as a **three-layer architecture** that separates concerns between user interaction, domain logic, and external integrations.

---

## Layer Diagram

```mermaid
graph TB
    subgraph CLI["Layer 1: CLI"]
        A[main.go — Cobra command tree]
    end

    subgraph Domain["Layer 2: Domain"]
        B[vault.go — Vault & Entries]
        C[session.go — Sessions]
        D[security.go — Profiles & Alerts]
        E[policy.go — Policy Engine]
        F[trust.go — Trust Scoring]
        G[health.go — Health Dashboard]
        H[audit.go — Audit Log]
        I[anomaly.go — Anomaly Detection]
        K[portability.go — Import/Export]
        L[apmignore.go — Ignore Rules]
        N[recovery_*.go — Recovery Subsystem]
        O[ephemeral_session.go — Delegated Sessions]
    end

    subgraph Integration["Layer 3: Integration"]
        P[cloud.go — GDrive/GitHub/Dropbox]
        Q[mcp.go — MCP Server]
        R[autofill/ — Windows Daemon]
    end

    CLI --> Domain
    CLI --> Integration
    Integration --> Domain
```

---

## Layer 1: CLI

**File:** `main.go` (~3,600 lines)

The CLI layer uses [Cobra](https://github.com/spf13/cobra) to define the entire command tree. It handles:

- User input parsing and validation
- Interactive prompts (password input, menus, confirmations)
- Output formatting (colored terminal output via `fatih/color`)
- Delegation to domain and integration layers

### Key Design Decisions

- **Single binary** — All commands live in one file for straightforward distribution
- **Interactive by default** — Most commands use interactive prompts rather than requiring flags
- **Explicit session checks** — Every sensitive command verifies an active session before proceeding

---

## Layer 2: Domain

**Directory:** `src/`

The domain layer contains all business logic. It operates entirely in memory after vault decryption:

| File                   | Responsibility                                   |
| :--------------------- | :----------------------------------------------- |
| `vault.go`             | Vault struct, entry types, encrypt/decrypt logic |
| `session.go`           | Shell-scoped session management                  |
| `ephemeral_session.go` | Delegated sessions with host/PID/agent binding   |
| `security.go`          | Profile management, alerts, email masking        |
| `policy.go`            | YAML policy loading and enforcement              |
| `trust.go`             | Per-secret trust scoring (telemetry + risk)      |
| `health.go`            | Vault health scoring algorithm                   |
| `audit.go`             | Tamper-evident audit logging                     |
| `anomaly.go`           | Unusual activity time detection                  |
| `portability.go`       | JSON, CSV, TXT import/export                     |
| `apmignore.go`         | Ignore rule parsing and filtering                |
| `recovery_passkey.go`  | WebAuthn passkey recovery                        |
| `quorum_recovery.go`   | Shamir secret sharing (quorum recovery)          |
| `recovery_codes.go`    | One-time recovery codes                          |

---

## Layer 3: Integration

| Component  | File(s)         | Protocol            | Purpose                     |
| :--------- | :-------------- | :------------------ | :-------------------------- |
| Cloud Sync | `cloud.go`      | REST / OAuth2 / PAT | Multi-provider vault sync   |
| MCP Server | `mcp.go`        | stdio (JSON-RPC)    | AI assistant vault access   |
| Autofill   | `autofill/*.go` | HTTP (loopback)     | Windows keystroke injection |

### Cloud Provider Architecture

Each cloud provider follows the same interface:

1. **Init** → Configure OAuth/PAT credentials
2. **Sync** → Upload encrypted vault blob
3. **Get** → Download remote vault blob
4. **Reset** → Clear provider configuration

Credentials are stored encrypted inside the vault itself.

### MCP Server Architecture

The MCP server is spawned as a subprocess by AI clients. It:

1. Accepts stdio transport
2. Validates bearer tokens against the vault's token store
3. Routes tool calls to domain layer (vault read/write)
4. Enforces permission scope checks per tool
5. Manages transaction state for write operations

### Autofill Architecture

The autofill daemon is a local HTTP server that:

1. Listens on a random port on loopback
2. Stores a shared bearer token for IPC
3. Captures active window context via Windows APIs
4. Matches credentials against vault profiles
5. Injects keystrokes via `SendInput` (Windows)

---

## Data Flow: Vault Unlock → Save

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Session
    participant Vault

    User->>CLI: pm unlock
    CLI->>Vault: Load encrypted bytes from disk
    Vault->>Vault: Parse header (magic, version, profile, salt)
    Vault->>Vault: Derive 96 bytes via Argon2id(password, salt)
    Note over Vault: key[0:32] = encryption key<br/>key[32:64] = auth key<br/>key[64:96] = validator
    Vault->>Vault: Verify HMAC-SHA256(auth_key, metadata)
    Vault->>Vault: Decrypt AEAD(enc_key, ciphertext)
    Vault->>Vault: Verify validator matches stored validator
    Vault-->>CLI: Decrypted Vault struct
    CLI->>Session: Create session file
    CLI-->>User: "Vault unlocked"

    Note over User: ... user performs operations ...

    User->>CLI: pm add (adds entry to in-memory vault)
    CLI->>Vault: Generate new salt
    Vault->>Vault: Derive keys from password + new salt
    Vault->>Vault: Serialize vault to JSON
    Vault->>Vault: Encrypt with AEAD(enc_key, json)
    Vault->>Vault: Compute HMAC-SHA256(auth_key, metadata)
    Vault->>Vault: Write header + ciphertext + HMAC to disk
    Vault-->>CLI: Save complete
```

---

## Security Boundaries

| Boundary         | Inside                      | Outside                  |
| :--------------- | :-------------------------- | :----------------------- |
| Vault encryption | All entry data, credentials | Master password, keys    |
| Session boundary | Decrypted vault (in memory) | Persisted data (on disk) |
| Cloud boundary   | Encrypted blob (APMVAULT)   | Plaintext entries        |
| MCP boundary     | Permitted data (per scope)  | Unauthorized data        |

---

## Next Steps

- **[Encryption](encryption.md)** — Detailed cryptographic design
- **[Vault Format](vault-format.md)** — Binary format specification
