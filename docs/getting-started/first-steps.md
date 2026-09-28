# First Steps

This walkthrough follows the code paths that exist in the current `pm` binary.

## 1. Build and run setup

```bash
go build -o pm .
pm setup
```

`pm setup` is the guided onboarding flow for:

- creating the vault if one does not exist
- choosing or changing the active crypto profile
- selecting the cipher for new vaults
- creating spaces
- configuring cloud sync

The default vault path is `vault.dat` beside the binary unless `APM_VAULT_PATH` is set.

## 2. Choose a profile

The built-in profiles in the code today are:

| Profile | KDF metadata | Memory | Time | Parallelism | Default nonce |
| :-- | :-- | --: | --: | --: | --: |
| `standard` | `argon2id` | 64 MB | 3 | 2 | 12 |
| `hardened` | `argon2id` | 256 MB | 5 | 4 | 12 |
| `paranoid` | `argon2id` | 512 MB | 6 | 4 | 24 |
| `legacy` | `pbkdf2` metadata | 0 | 600000 | 1 | 12 |

The setup flow can also switch between `aes-gcm` and `xchacha20-poly1305`.

## 3. Unlock the vault

```bash
pm unlock
```

Unlock creates a session with:

- a session duration
- an inactivity timeout
- optional read-only access

Normal sessions are stored in temp files and encrypted with a per-user key in the config directory. If you set `APM_SESSION_ID`, you can keep multiple shell-scoped sessions.

## 4. Add an entry

```bash
pm add
```

The current interactive add flow supports 25 entry types:

- Password
- TOTP
- Token
- Secure note
- API key
- SSH key
- Wi-Fi
- Recovery codes
- Certificate
- Banking item
- Document
- Government ID
- Medical record
- Travel document
- Contact
- Cloud credential
- Kubernetes secret
- Docker registry
- SSH config
- CI/CD secret
- Software license
- Legal contract
- Audio
- Video
- Photo

You can also call `pm add <type>` directly with aliases such as `password`, `totp`, `note`, `apikey`, `sshkey`, `cloudcredentials`, `kubernetes`, or `photo`.

## 5. Search and inspect

```bash
pm get github
pm totp
pm gen
```

Useful early commands:

- `pm get [query]` for interactive search and entry actions
- `pm totp [entry_name]` for one-off TOTP retrieval
- `pm gen` for password generation
- `pm cinfo` for vault crypto parameters
- `pm loaded` to inspect loaded policies and `.apmignore`

## 6. Lock when done

```bash
pm lock
```

`pm lock` removes the active unlock session and also tries to lock the autofill daemon if it is running.

## 7. Optional next steps

### Cloud sync

```bash
pm cloud init
pm cloud sync
```

Supported providers:

- Google Drive
- GitHub
- Dropbox

Google Drive and Dropbox each support `APM_PUBLIC` and `self_hosted` modes. GitHub uses a token plus `owner/repo`.

### Delegated sessions

```bash
pm session issue
pm session list
pm session revoke <id>
```

Ephemeral sessions are useful for AI tools and automation. They can be bound to host, PID, and agent name.

### Recovery

```bash
pm auth email you@example.com
pm auth codes generate
pm auth quorum-setup
```

Registering a recovery email also generates and displays the vault recovery key once.

### Windows autofill

```powershell
pm autocomplete enable
pm autofill start
```

The Windows daemon uses a global hotkey and loopback-only local IPC.
