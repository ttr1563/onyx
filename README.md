# Onyx

Onyx is a lightweight command guard that detects risky operations on Linux servers and requires approval from a separate TOTP authenticator before execution.

> [!IMPORTANT]
> Onyx v0.1 protects only commands launched through `onyx run -- ...`. It is a safety boundary for operator mistakes and constrained automation, not a host-wide EDR. A user who can bypass Onyx or an attacker with root access can disable this protection.
>
> TOTP does not provide meaningful resistance to code running as the operating-system identity that owns the Onyx state: that identity can read the verifier seed. Use a dedicated, constrained identity to limit impact. Administrator-owned verification and hardware-backed asymmetric approval require the planned broker design and are not claimed by v0.1.

## What it does

- evaluates a command before execution;
- blocks built-in high-risk patterns and creates an event;
- approves one exact command digest with a six-digit TOTP code;
- expires approvals after 30 seconds and consumes each approval once;
- rejects reuse of a TOTP code in the same time step;
- writes redacted, one-record-per-line JSON audit logs locally;
- stores state with owner-only permissions and rejects symbolic links to sensitive state files.

Onyx does not upload logs or require an AWS, Google, or other cloud account. Google Authenticator, 1Password, Aegis, and other RFC 6238-compatible applications can scan its enrollment URI.

## Current platform support

- Protection target: Linux, including Linux distributions running inside WSL 2
- Authenticator: any RFC 6238-compatible TOTP application on Linux, macOS, Android, iOS, or Windows
- Rust: 1.91 or later when building from source

Native macOS and Windows command protection, OpenSSH/FIDO security keys, eBPF enforcement, and a privileged daemon are not part of v0.1. On Windows, Onyx protects only Linux commands launched through `onyx run` inside WSL; it does not intercept PowerShell, Command Prompt, or native Windows processes.

## Install

### Amazon Linux 2023 with DNF

Import the dedicated Onyx package-signing key and install the repository configuration once:

```console
sudo rpm --import https://ttr1563.github.io/onyx/rpm/RPM-GPG-KEY-ONYX
sudo dnf install https://ttr1563.github.io/onyx/rpm/onyx-release-1-1.noarch.rpm
```

The signing-key fingerprint is `E9E3 C123 DEDF B3E9 AEA1 F3A9 CD2E 615D BC32 CF0C`. Verify it before trusting the key. The release RPM installs only the repository definition and public key. Inspect its contents before installation when required by local policy. Install and upgrade Onyx with:

```console
sudo dnf install onyx
sudo dnf upgrade onyx
```

The initial repository publishes an `x86_64` package built and tested on Amazon Linux 2023. Other RPM distributions and `aarch64` are not yet verified. Package removal leaves `/var/lib/onyx` state and audit evidence intact; remove retained data only after reviewing incident and retention requirements.

### Debian or Ubuntu with APT

Install the repository key after verifying its fingerprint, then install the scoped deb822 repository definition:

```console
curl -fsSLO https://ttr1563.github.io/onyx/apt/onyx.asc
gpg --show-keys --with-fingerprint onyx.asc
# Expected: E9E3 C123 DEDF B3E9 AEA1 F3A9 CD2E 615D BC32 CF0C
sudo install -D -m0644 onyx.asc /etc/apt/keyrings/onyx.asc

curl -fsSLO https://ttr1563.github.io/onyx/apt/onyx.sources
sudo install -m0644 onyx.sources /etc/apt/sources.list.d/onyx.sources
rm onyx.asc onyx.sources

sudo apt-get update
sudo apt-get install onyx
```

The initial APT repository supports `amd64` on Debian 12 and Ubuntu 22.04 or later. `Signed-By` limits this repository to the dedicated Onyx key. Upgrade with `sudo apt-get update && sudo apt-get install --only-upgrade onyx`. Removing the package intentionally preserves `/var/lib/onyx` state and audit evidence.

### Homebrew on Linux or macOS

```console
brew tap ttr1563/onyx https://github.com/ttr1563/onyx.git
brew install ttr1563/onyx/onyx
```

The Formula builds Onyx from the checksummed release source. Linux is the supported protection target. The CLI is expected to build on macOS, but macOS command protection is not verified in v0.1.

Upgrade an existing Homebrew installation with:

```console
brew update
brew upgrade ttr1563/onyx/onyx
```

### Install from a release tag with Cargo

Use an immutable release tag instead of the mutable default branch:

```console
cargo install \
  --git https://github.com/ttr1563/onyx.git \
  --tag v0.1.2 \
  --locked
```

This requires Rust 1.91 or later and the platform build toolchain.

### Clone for development

```console
git clone --branch v0.1.2 --depth 1 https://github.com/ttr1563/onyx.git
cd onyx
cargo install --path . --locked
```

### Windows x64 through WSL 2

Onyx is not a native Windows command guard. The published APT package is `amd64`, so this path currently targets x64 Windows. From an elevated PowerShell session, install WSL and restart if Windows requests it:

```powershell
wsl --install
```

Open the installed Ubuntu terminal and follow the APT instructions above. Run protected commands inside that terminal:

```console
onyx init --account windows-wsl
onyx run -- rm -rf /example
```

Only commands inside WSL and explicitly launched through `onyx run` are protected. PowerShell, `cmd.exe`, `.exe` processes started outside WSL, and Windows services remain outside the protection boundary. See the [installation guide](https://ttr1563.github.io/onyx/install.html) for prerequisites, updates, uninstall behavior, and platform boundaries.

## Initialize

Run Onyx as the same operating-system identity that will run protected commands. For a system-owned installation, initialize it as root and restrict who may invoke the wrapper.

```console
onyx init --account production-web-01
```

Onyx prints a terminal QR code and an `otpauth://` URI exactly during initialization. Scan either with a TOTP authenticator. The TOTP seed is not written to the audit log.

Default state paths:

| Context | Path |
| --- | --- |
| root | `/var/lib/onyx` |
| regular user | `$XDG_STATE_HOME/onyx` or `~/.local/state/onyx` |
| explicit override | `onyx --state-dir /path ...` or `ONYX_STATE_DIR` |

The state directory is mode `0700`; configuration, events, authentication state, locks, and audit files are mode `0600`.

## Protect a command

Safe commands run immediately and preserve the child process exit code:

```console
onyx run -- systemctl status nginx
```

A matching high-risk command is not executed:

```console
$ onyx run -- rm -rf /var/www/old-release
BLOCKED by Onyx
Event: 24eb36a1-90d5-4e09-918f-c37ebbc63cb1
Rules: destructive-recursive-delete
Approve: onyx approve 24eb36a1-90d5-4e09-918f-c37ebbc63cb1
Then rerun the exact command within the approval window.
```

Review and approve the event from an interactive terminal:

```console
onyx approve 24eb36a1-90d5-4e09-918f-c37ebbc63cb1
```

The authenticator code is read without terminal echo. After approval, rerun the exact command within 30 seconds:

```console
onyx run -- rm -rf /var/www/old-release
```

Changing any argument creates a different digest and requires a new approval. The permit is consumed before the child process starts, so a failed spawn does not leave a reusable approval.

## Inspect without executing

```console
onyx check -- rm -rf /var/www/old-release
onyx status
onyx logs --limit 50
```

`onyx check` does not require initialization and does not create an event.

## Built-in policy

The initial policy blocks:

- recursive forced deletion of an absolute path or `.` / `..`;
- filesystem formatting and signature removal (`mkfs*`, `wipefs`);
- `dd` writes to `/dev/*`;
- host shutdown and reboot commands;
- all commands launched through `sudo`;
- shell command strings passed with `sh -c`, `bash -c`, and common equivalents;
- `find` deletion below an absolute path;
- recursive ownership or permission changes at `/`;
- common transfer tools referencing `.env`, SSH keys, `/etc/shadow`, credentials, or sudoers;
- shell expressions that combine base64 decoding and `eval`.

These rules are intentionally small and auditable. They are not behavioral malware detection and cannot understand arbitrary interpreter code. Wrapper commands such as `sudo` and shell `-c` strings are therefore treated conservatively and may require approval even when the nested operation is harmless.

### Add a site-specific rule

Custom rules match an executable basename and require every supplied argument fragment to occur. Adding a rule can only increase enforcement; v0.1 deliberately provides no unauthenticated CLI command to remove or weaken one.

```console
onyx policy add \
  --id production-terraform \
  --executable terraform \
  --argument-contains apply \
  --argument-contains production \
  --risk critical \
  --reason "production infrastructure change"

onyx policy list
onyx check -- terraform apply production.tfplan
```

Rules are stored as readable JSON in the owner-only `policy.json`; the file is not encrypted, so do not put credentials in rule fields. Each `--argument-contains` value is a literal substring, not a regular expression. Directly editing or deleting the policy file is outside the protected CLI boundary and requires the same operating-system controls as the rest of Onyx state.

## Audit log

Audit records are JSON Lines in `audit.jsonl`. Records include UTC time, action, event ID, command digest, redacted command summary, matched rule IDs, and child exit status where applicable.

Onyx does not record stdout, stderr, environment variables, file contents, TOTP seeds, or submitted TOTP codes. Arguments containing common secret markers such as `password`, `token`, or `api_key` are redacted. Avoid placing secrets in command-line arguments regardless; other operating-system facilities may still record them.

External collection is deliberately out of scope. Operators may forward the file with their existing `logrotate`, journald, Vector, Fluent Bit, or SIEM configuration.

For a root-owned installation, the repository includes a conservative example at [`ops/logrotate/onyx`](ops/logrotate/onyx): rotate at 10 MiB, retain seven generations, and compress older records. Review the path, owner, retention, and compliance requirements before installing it as `/etc/logrotate.d/onyx`.

For deployment checks, monitoring, encrypted backup/restore, upgrade, rollback, authenticator loss, and incident handling, use the [operations runbook](docs/operations.md).
Package maintainers should also use the [RPM repository runbook](docs/package-repository.md) and [APT repository runbook](docs/apt-repository.md) for signing, publication, rotation, and rollback.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Onyx operation or child command succeeded |
| child code | An allowed child command exited with that code |
| `77` | A policy blocked the command |
| `1` | Initialization, state, authentication, or execution error |

## Authentication failure behavior

- TOTP period: 30 seconds
- accepted clock window: previous, current, or next step
- one successful use per TOTP counter
- event lifetime before approval: 10 minutes
- permit lifetime after approval: 30 seconds
- temporary lock: 60 seconds after five failed attempts

Keep server time synchronized. TOTP is a shared-secret mechanism and is not phishing-resistant. If an attacker obtains the server-side seed, they can generate valid codes.

## Recovery and removal

Onyx does not provide an unauthenticated reset command. If the authenticator is lost, an operating-system administrator must securely archive or remove the state directory and initialize a new TOTP enrollment. This invalidates all pending events and permits.

Back up the enrollment seed only in an access-controlled secret manager or offline recovery record. Never commit it to Git or include it in support logs.

To uninstall:

```console
cargo uninstall onyx-guard
# or, for an RPM installation:
sudo dnf remove onyx
# or, for an APT installation:
sudo apt-get remove onyx
```

After confirming that no audit retention requirement applies, an administrator may separately remove the known Onyx state directory. Package removal intentionally does not delete security logs or enrollment state.

## Security model

Read [SECURITY.md](SECURITY.md) and [the architecture document](docs/architecture.md) before production use. Important boundaries:

- commands not launched with `onyx run` are outside protection;
- the same OS identity that owns writable state can replace or delete it;
- root can bypass, modify, or remove this user-space guard;
- local-only logs can be deleted by a sufficiently privileged attacker;
- policy matching cannot detect every equivalent or obfuscated operation.

Run automation under a dedicated constrained service account and keep ordinary workloads unprivileged. Do not treat v0.1 as a security boundary against that account itself; administrator-owned verification requires the future broker design.

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
```

Tests use temporary directories and a fake `rm` executable; they do not execute destructive system commands.

## License

[MIT](LICENSE)
