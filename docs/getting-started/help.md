# Getting Help

APM provides multiple ways to get assistance, from built-in documentation to community support.

---

## Inline Help

Every command and subcommand supports the `--help` flag:

```bash
# Top-level help
pm --help

# Command-specific help
pm add --help
pm cloud --help
pm cloud init --help
pm mcp --help
pm auth --help
```

This displays usage syntax, available flags, and a brief description of each command.

---

## System Information

View your current APM installation details:

```bash
pm info
```

This displays:

- APM version
- Go version and build info
- OS and architecture
- Vault file path
- Install directory

For cryptographic parameters of your vault:

```bash
pm cinfo
```

This shows:

- Active encryption profile
- Active cipher
- Argon2id parameters (memory, time, parallelism)
- Nonce size
- Vault format version

---

## Reporting Issues

If you encounter a bug or have a feature request:

1. **Check existing issues**: [github.com/aaravmaloo/apm/issues](https://github.com/aaravmaloo/apm/issues)
2. **Open a new issue** with:
    - APM version (`pm info`)
    - OS and architecture
    - Steps to reproduce
    - Expected vs. actual behavior

!!! warning "Security Vulnerabilities"
    If you discover a security vulnerability, **do not open a public issue**. Instead, email **aaravmaloo06@gmail.com** directly with details of the vulnerability.

---

## Contact

- **Primary Maintainer**: Aarav Maloo
- **Security Alerts**: aaravmaloo06@gmail.com
- **GitHub**: [aaravmaloo/apm](https://github.com/aaravmaloo/apm)
