# Vault Format

APM uses a custom binary format called **Vault V4** for storing encrypted data on disk. This page describes the exact byte layout, integrity mechanisms, and backward compatibility.

---

## File Signature

Every APM vault file begins with the ASCII magic bytes:

```
APMVAULT
```

This 8-byte signature identifies the file as an APM vault and enables format detection by other tools.

---

## V4 Binary Layout

```
APMVAULT
version (1 byte)
profile_len (2 bytes)
profile_json (variable)
recovery_len (2 bytes)
recovery_json (variable)
salt (profile-defined length)
validator (32 bytes)
nonce (profile-defined length)
master_slot (32 bytes + AEAD tag)
ciphertext (variable)
hmac_sha256 (32 bytes)
```

### Header Fields

| Field             | Size       | Description                                                                 |
| :---------------- | :--------- | :-------------------------------------------------------------------------- |
| **Magic**         | 8 bytes    | Fixed `APMVAULT` ASCII string                                               |
| **Version**       | 1 byte     | Format version (currently `4`)                                              |
| **Profile JSON**  | Variable   | Serialized `CryptoProfile`, including KDF, salt length, nonce length, cipher |
| **Recovery JSON** | Variable   | Unencrypted recovery metadata used for recovery and alert coordination       |
| **Salt**          | Variable   | Random salt for key derivation, sized by the active profile                 |
| **Validator**     | 32 bytes   | Validator bytes used for fast wrong-password detection                      |
| **Nonce**         | Variable   | AEAD nonce for the vault payload                                            |
| **Master Slot**   | 48 bytes   | Encrypted DEK slot for V4 vaults (32-byte DEK + AEAD tag)                   |
| **Ciphertext**    | Variable   | AEAD-encrypted vault payload                                                |
| **HMAC**          | 32 bytes   | HMAC-SHA256 over the entire unsigned payload                                |

### Profile Metadata

The profile block is JSON, not a numeric profile ID. That allows APM to persist:

- KDF selection
- Time, memory, and parallelism
- Salt length
- Nonce length
- Encryption method (`aes-gcm` or `xchacha20-poly1305`)

Older vaults that do not store a cipher are treated as `aes-gcm` when loaded.

### Encrypted Payload

The payload uses the AEAD defined by the profile metadata. The nonce is stored separately before the master slot and ciphertext.

### HMAC Signature

The final 32 bytes are an **HMAC-SHA256 signature** computed using the authentication key over:

- Version byte
- Profile JSON block
- Recovery metadata block
- Salt
- Validator bytes
- Nonce
- Master slot
- Entire encrypted payload

This provides **pre-decryption tamper detection**.

---

## Encrypted Vault Contents

The decrypted JSON payload contains the full `Vault` struct:

```json
{
  "entries": [
    {
      "id": "uuid-v4",
      "username": "...",
      "password": "...",
      "account": "...",
      "space": "...",
      "entry_type": "password",
      "custom_fields": {},
      "created_at": "2026-01-15T10:30:00Z",
      "updated_at": "2026-01-15T10:30:00Z"
    }
  ],
  "totp_entries": [...],
  "totp_order": ["entry1", "entry2"],
  "notes": [...],
  "api_keys": [...],
  "tokens": [...],
  "ssh_keys": [...],
  "ssh_configs": [...],
  "cloud_credentials": [...],
  "k8s_secrets": [...],
  "docker_registries": [...],
  "cicd_secrets": [...],
  "recovery_codes_entries": [...],
  "certificates": [...],
  "banking_entries": [...],
  "documents": [...],
  "software_licenses": [...],
  "legal_contracts": [...],
  "gov_ids": [...],
  "medical_records": [...],
  "travel_entries": [...],
  "contacts": [...],
  "wifi_entries": [...],
  "photos": [...],
  "audio_entries": [...],
  "video_entries": [...],
  "recovery_email": "...",
  "recovery_hash": "...",
  "recovery_salt": "...",
  "alerts_enabled": true,
  "alert_email": "...",
  "security_level": 2,
  "current_space": "default",
  "spaces": ["default", "Work", "Personal"],
  "cloud_config": {...},
  "mcp_tokens": [...],
  "secret_telemetry": {...},
  "history": [...],
  "current_profile_params": {...}
}
```

---

## Version History

| Version | Changes                                                                    |
| :------ | :------------------------------------------------------------------------- |
| V1      | Simple AES-CBC encryption                                                  |
| V2      | Added HMAC integrity                                                       |
| V3      | Migrated to AES-GCM, added Argon2id profiles                                |
| **V4**  | Added `APMVAULT` magic, JSON profile metadata, recovery metadata, DEK slot  |

---

## Backward Compatibility

APM detects older vault formats automatically:

1. **V4** — Full `APMVAULT` header with magic bytes
2. **Pre-V4** — Falls back to legacy decryption (`decryptOldVault`) which uses hardcoded Argon2 parameters

!!! warning "Legacy Vaults"
    Legacy vaults (pre-V4) are supported for reading but **cannot receive new features** like recovery or trust scoring. You should re-encrypt with `pm profile` to upgrade to V4.

---

## File Locations

| Platform | Default Vault Path                |
| :------- | :-------------------------------- |
| All      | `./vault.dat` (current directory) |
| Override | `APM_VAULT_PATH` env variable     |

---

## Next Steps

- **[Encryption](encryption.md)** — How keys are derived and data is encrypted
- **[Secret Types](secret-types.md)** — All entry type schemas
