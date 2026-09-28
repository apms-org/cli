# Concepts

Deep technical explanations of how APM works under the hood. Each page covers the theory, design decisions, and internal mechanics of a core subsystem.

---

<div class="apm-feature-grid" markdown>

<div class="apm-feature-card" markdown>

### [Architecture](architecture.md)

The four-layer design of APM: CLI layer, domain layer, integration layer, and extension layer.

</div>

<div class="apm-feature-card" markdown>

### [Encryption](encryption.md)

Argon2id key derivation, AES-GCM and XChaCha20-Poly1305 support, HMAC-SHA256 integrity, nonce handling, and the DEK recovery slot.

</div>

<div class="apm-feature-card" markdown>

### [Vault Format](vault-format.md)

The V4 binary format specification: `APMVAULT` header, encrypted body, HMAC signature, and recovery metadata.

</div>

<div class="apm-feature-card" markdown>

### [Secret Types](secret-types.md)

All 25+ structured entry types with their field schemas, validation, and display logic.

</div>

<div class="apm-feature-card" markdown>

### [Security Profiles](security-profiles.md)

Standard, Hardened, Paranoid, and Legacy profiles — their Argon2id parameters, hardware requirements, and auto-detection.

</div>

<div class="apm-feature-card" markdown>

### [Policy Engine](policy-engine.md)

YAML-based password and rotation policies with classification levels and enforcement.

</div>

<div class="apm-feature-card" markdown>

### [Sessions](sessions.md)

Shell-scoped sessions, ephemeral delegated sessions, and their security boundaries.

</div>

<div class="apm-feature-card" markdown>

### [Cloud Synchronization](cloud-sync.md)

Provider comparison, OAuth2 vs PAT, retrieval key mechanics, metadata consent, and end-to-end encryption guarantees.

</div>

<div class="apm-feature-card" markdown>

### [MCP Server](mcp.md)

Model Context Protocol internals — permission scopes, transaction guardrails, and token lifecycle.

</div>

<div class="apm-feature-card" markdown>

### [Recovery](recovery.md)

Multi-factor recovery: email OTP, recovery keys, Shamir secret sharing, WebAuthn passkeys, and recovery codes.

</div>

</div>
