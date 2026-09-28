<div align="center">

# APM

**A better local password manager for everyone.**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/github/license/aaravmaloo/apm?style=flat)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-aaravmaloo.github.io%2Fapm-blue?style=flat)](https://aaravmaloo.github.io/apm)

[![CI](https://img.shields.io/github/actions/workflow/status/aaravmaloo/apm/ci.yml?branch=master&label=CI&style=flat)](https://github.com/aaravmaloo/apm/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/aaravmaloo/apm?style=flat)](https://github.com/aaravmaloo/apm/releases/latest)
[![Stars](https://img.shields.io/github/stars/aaravmaloo/apm?style=flat)](https://github.com/aaravmaloo/apm/stargazers)
[![Issues](https://img.shields.io/github/issues/aaravmaloo/apm?style=flat)](https://github.com/aaravmaloo/apm/issues)

</div>
APM is a fast, zero-knowledge CLI password manager written in Go and Rust. It stores **25+ structured secret types** in a single encrypted vault — from passwords and TOTP codes to SSH keys, medical records, photos, and binary files. Two binaries ship from this repo: `pm` for personal use and `pm-team` for shared organizational vaults.

---

### Why APM?

- **Fast & easy to learn** — no memorizing commands or flags. APM prompts you for whatever it needs. CLI flags are also available for power users who want maximum speed.
- **Zero-knowledge** — your master password is never stored. Three separate 32-byte keys are derived using Argon2id. No one but you can decrypt your vault.
- **Dual encryption** — choose AES-256-GCM or XChaCha20-Poly1305. Double-layer integrity via HMAC-SHA256 on top of AEAD authentication.
- **Portable** — one vault file, one binary. Take your vault anywhere.
- **Optional cloud** — sync to Google Drive, GitHub, or Dropbox. Fully opt-in; no account required to use APM.
- **AI-ready** — native MCP server with scoped tokens so Claude, Cursor, or any MCP-compatible agent can access your vault safely.
- **Team-ready** — full RBAC, departments, approval workflows, and shared vaults in `pm-team`.

---

### Quick Start

```sh
go build -o pm .
pm setup       # initialize vault and choose security profile
pm unlock      # start a session
pm add         # add a secret (interactive)
pm get github  # fuzzy search and retrieve
pm lock        # end session
```

**Team edition:**
```sh
cd team
go build -o pm-team .
```

---

### Secret Types

APM supports **25 structured secret types** with validated fields and type-specific display logic:

| # | Type | # | Type |
|---|------|---|------|
| 1 | Password | 14 | Docker Registry |
| 2 | TOTP | 15 | CI/CD Secret |
| 3 | Government ID | 16 | Secure Note |
| 4 | Medical Record | 17 | Recovery Codes |
| 5 | Travel Info | 18 | Certificate |
| 6 | Contact | 19 | Banking |
| 7 | Wi-Fi | 20 | Document |
| 8 | API Key | 21 | Software License |
| 9 | Token | 22 | Legal Contract |
| 10 | SSH Key | 23 | Photo |
| 11 | SSH Config | 24 | Audio |
| 12 | Cloud Credentials | 25 | Video |
| 13 | Kubernetes | | |

---

### Features

**Security**
- Zero-knowledge Argon2id key derivation — master password never stored
- Dual AEAD ciphers: AES-256-GCM and XChaCha20-Poly1305
- HMAC-SHA256 double-layer integrity check
- Four tunable security profiles: `standard`, `hardened`, `paranoid`, `legacy`
- Per-secret trust scoring (0–100) based on age, access, and privilege level
- Tamper-evident audit log stored outside the vault

**Vault**
- Single encrypted vault file — portable across any device
- Spaces for logical compartmentation (like folders)
- Fuzzy search with interactive browser and keyboard navigation
- Metadata inspector: creation date, last access, access count, trust score

**TOTP**
- Live countdown timers in an interactive list
- Persistent custom ordering
- Direct copy: `pm totp github`
- Autofill daemon integration for auto-injecting 2FA codes

**Cloud Sync**
- Google Drive (OAuth2 PKCE), GitHub (PAT), Dropbox (OAuth2 PKCE)
- End-to-end encrypted — providers never see plaintext
- `.apmignore` to filter entries per provider
- Conflict resolution: overwrite, keep local, or cancel
- Background auto-sync

**Sessions**
- Explicit unlock/lock with configurable expiry and inactivity timeout
- Delegated ephemeral sessions for automation and AI-agent access

**MCP Server**
- Native Model Context Protocol server
- Scoped permission tokens: `read`, `secrets`, `write`, `admin`
- Transaction guardrails for write ops: preview → approve → receipt
- Works with Claude Desktop, Cursor, Windsurf, and any MCP client



**Recovery**
| Factor | Command |
|--------|---------|
| Email OTP | `pm auth email` |
| Recovery Key | `pm auth recover` |
| Quorum Shares (Shamir) | `pm auth quorum-setup` |
| WebAuthn Passkey | `pm auth passkey register` |
| One-time Recovery Codes | `pm auth codes generate` |

**Import / Export**

| Format | Import | Export |
|--------|--------|--------|
| JSON | `pm import json` | `pm export json` |
| CSV | `pm import csv` | `pm export csv` |
| TXT | `pm import txt` | `pm export txt` |

**Policy Engine**
```yaml
name: corporate-standard
password_policy:
  min_length: 14
  require_uppercase: true
  require_numbers: true
  require_symbols: true
rotation_policy:
  rotate_every_days: 90
  notify_before_days: 14
```
```sh
pm policy load ./policies/
```

**Team Edition (`pm-team`)**
- RBAC with multiple roles
- Departments with isolated encryption domains
- Approval workflows for sensitive entries
- Shared vaults for multi-user credential sharing

---

### Security Profiles

| Profile | Argon2 Memory | Iterations | Parallelism | Use Case |
|---------|--------------|------------|-------------|----------|
| `standard` | 64 MB | 3 | 2 | Most machines |
| `hardened` | 256 MB | 5 | 4 | Workstations (≥8 GB RAM) |
| `paranoid` | 512 MB | 6 | 4 | Servers (≥16 GB RAM) |
| `legacy` | PBKDF2 | 600,000 | 1 | Backward compatibility |

APM auto-detects your CPU cores and RAM to recommend the optimal profile during `pm setup`.


### Development Status and history
(This note is from the owner)
As of 30th March 2026, I am currently working on the GUI for APM. At first it started as a CLI application. The issue #38 explains everything in detail. Overall, I want APM to reach 
an even larger demographic. I will keep the GUI separate in a apm-gui repo or create a organization and move both the repos there. 

I started APM as a truly personal project. It started at a random evening, when I wanted to create my own password manager. I was sick of zoho password, since I used it for TOTPs. It was incredibly slow to ever function, and I used plaintext files for my tokens, which is not secure. 

As of now, I DO NOT plan to abandon/retire the project. It will remain functional for a long time. I try to make it better everyday and use it everyday. Sometimes, the repo may be inactive, and that is when I test and experiment with the application.

---

### Release Structure

| Tier | Stable? | Vault Safe? | Purpose |
|------|---------|-------------|---------|
| Canary | ❌ | ❌ | Earliest feature preview — can corrupt vaults |
| Alpha | ❌ | ✅ | Unstable features, vault integrity preserved |
| Beta | ✅ | ✅ | Fully tested features, careful rollout |
| Stable | ✅ | ✅ | Production-ready releases |

> Always back up your vault before trying Canary releases.
P.S. For some releases, some tiers may not be released depending on how fast and easy they are to ship without creating more than necessary tiers.
---

### Documentation

Full documentation at **[aaravmaloo.github.io/apm](https://aaravmaloo.github.io/apm)**

- [Installation](https://aaravmaloo.github.io/apm/getting-started/installation/)
- [First Steps](https://aaravmaloo.github.io/apm/getting-started/first-steps/)
- [CLI Reference](https://aaravmaloo.github.io/apm/reference/cli/)
- [Architecture](https://aaravmaloo.github.io/apm/concepts/architecture/)
- [Encryption](https://aaravmaloo.github.io/apm/concepts/encryption/)
- [Team Edition](https://aaravmaloo.github.io/apm/guides/team-edition/)
- [MCP Integration](https://aaravmaloo.github.io/apm/guides/mcp-integration/)
- [Contributing](https://aaravmaloo.github.io/apm/contributing/)

---

### Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://aaravmaloo.github.io/apm/contributing/) for guidelines.

---

### License

[GPL-3.0 License](LICENSE) © Aarav Maloo
