# Osmanthus

Osmanthus is a Linux server guard that blocks configured destructive filesystem
operations below protected directories. Normal commands do not need an
`osmanthus run` prefix. A privileged daemon keeps the policy boundary active, writes
local JSONL evidence, and grants short, scoped maintenance windows after TOTP
authentication.

> The enforced daemon described below is under development on
> `feature/enforced-shell-monitoring`. The latest public Onyx v0.1.3 packages
> contain the earlier compatibility wrapper. They are not Osmanthus packages
> and do not provide this enforced backend.

## What it does

- Denies delete, rename/move (including exchange), open-time and direct truncate,
  opt-in non-truncating writes,
  ownership changes, and mode changes
  below administrator-selected roots using Linux BPF LSM hooks.
- Applies the filesystem boundary host-wide, including alternate interpreters,
  scheduled jobs, and services.
- Records kernel denials and `execve`/`execveat` events for enrolled UIDs in
  `/var/log/osmanthus/audit.jsonl`.
- Can supervise an enrolled interactive shell through a PTY and record its
  input/output without changing command syntax.
- Allows a root administrator with the policy TOTP to create a maintenance
  lease for one path, selected operation classes, duration, and caller cgroup.
- Keeps BPF enforcement pinned if `osmanthusd` crashes or restarts. Maintenance
  leases are memory-only and disappear on restart.
- Rejects hard links into or out of a protected tree and refuses to enroll a
  tree that already contains hard-linked non-directory entries.

Osmanthus does not protect a host after root, the kernel, or the boot trust chain is
compromised. It does not hide policy values: integrity comes from root ownership,
read-only files, a SHA-256 companion digest, and authenticated CLI mutations.
Secrets must never be stored in rule values.

## Architecture

```text
normal shell / service / script
        │
        ├── execve events for enrolled UID ───────┐
        │                                         │
        └── destructive filesystem syscall        │
                         │                        │
                  Linux BPF LSM                   │
                  │            │                  │
            unprotected      protected            │
              allow       deny before change      │
                               │                  │
                               └──── ring buffer ──┤
                                                  ▼
                                             root osmanthusd
                                                  │
                                  /var/log/osmanthus/audit.jsonl
```

The final decision is `protected root × operation class`; executable names and
shell strings are not the enforcement boundary. Thus Python, Node.js, or a
renamed binary cannot bypass a protected delete by avoiding the `rm` name.

See [architecture](docs/architecture.md), the authoritative
[enforcement requirements](docs/enforcement-requirements.md), the
[operations runbook](docs/operations.md), and the dedicated
[AWS SSM entry-point procedure](docs/ssm.md).

## Build from source

The current enforced backend targets native Linux x86-64 and ARM64 builds with a kernel that enables
BPF LSM and the `bpf_loop` helper. Building requires Rust, clang/LLVM, libelf, zlib, and libbpf headers;
the produced binaries embed the BPF object and do not require clang at runtime.

```bash
git clone https://github.com/ttr1563/osmanthus-shell.git
cd osmanthus-shell
git checkout feature/enforced-shell-monitoring
cargo build --release --locked
sudo install -m 0755 target/release/osmanthus /usr/bin/osmanthus
sudo install -m 0755 target/release/osmanthusd /usr/bin/osmanthusd
sudo install -m 0755 target/release/osmanthus-shell /usr/bin/osmanthus-shell
sudo install -m 0644 ops/systemd/osmanthusd.service /usr/lib/systemd/system/osmanthusd.service
sudo install -m 0644 ops/logrotate/osmanthus /etc/logrotate.d/osmanthus
sudo install -D -m 0644 ops/ssm/osmanthus-session.json /usr/share/osmanthus/ssm/osmanthus-session.json
```

RPM and deb build scripts are available for release engineering:

```bash
scripts/build-rpm.sh 0.1.3 dist/rpm
scripts/build-deb.sh 0.1.3 dist/deb
scripts/test-rpm.sh 0.1.3 dist/rpm/x86_64
scripts/test-deb.sh 0.1.3 dist/deb
```

The local tests inspect the package payload and CLI without requiring a public
repository. They do not replace a clean-host install, daemon, login-shell,
upgrade, or uninstall test. The public DNF/APT repositories are not updated by
these commands.
The deb builder maps native Linux `x86_64` to Debian `amd64` and `aarch64` to
`arm64`; it deliberately rejects cross-packaging and unsupported hosts. Native
ARM64 build, package install, kernel enforcement, scoped maintenance, audit,
decommission, and uninstall have been verified on Ubuntu 24.04 with kernel 6.8.
Each other advertised distribution and architecture still requires its own
installed-package integration result.
The legacy Homebrew formula installs Onyx v0.1.3, not Osmanthus.

### Migrating from Onyx

Do not run the pre-release Onyx and Osmanthus kernel backends together. Before
installing Osmanthus, restore every account whose login shell is
`/usr/bin/onyx-shell` and use the matching Onyx binary to decommission any
`/sys/fs/bpf/onyx` pins. The Osmanthus daemon and package pre-install checks
refuse to continue while either remains.

Legacy Onyx state below `~/.local/state/onyx`, `/var/lib/onyx`, or `/etc/onyx`
is retained for audit and rollback but is not imported. Initialize the new
root-owned Osmanthus policy explicitly after installation.

## Initial setup

Initialize the root-owned policy and enroll its administrator TOTP:

```bash
sudo osmanthus policy init --account production-policy-admin
sudo systemctl daemon-reload
sudo systemctl enable --now osmanthusd
osmanthus daemon status
```

The QR/URI is displayed only during initialization. Store it in an RFC
6238-compatible authenticator controlled separately from the protected account.
Rotate it while the current authenticator is available with
`sudo osmanthus policy auth rotate`; the previous secret is invalid immediately.

Add a real directory and the destructive actions to protect:

```bash
sudo osmanthus policy protect add --path /srv/production \
  --action delete \
  --action rename \
  --action truncate \
  --action change-permissions
```

Add `--action write` only where ordinary writes must also be denied. It covers
write syscalls and new writable shared mappings, so enabling it on an application
data directory will also stop legitimate application writes until maintenance
is granted.

Each policy mutation requires root and the policy-administrator TOTP. The CLI
writes a validated replacement and asks the daemon to reload it. If daemon
reload or audit fails, it restores the previous policy.
Protected roots must not contain hard-linked non-directory entries. Osmanthus
checks this recursively during activation and keeps hard-link topology changes
blocked even during maintenance, because an external alias would outlive a
temporary lease.

Enroll a non-root UID for process evidence and select its real shell:

```bash
sudo osmanthus policy monitor add 1001 --shell /bin/bash
sudo osmanthus policy list
```

When `--shell` is present, Osmanthus verifies that it is the account's current shell,
stores it for rollback, and changes the account to `/usr/bin/osmanthus-shell`. Removing
the monitored UID restores the recorded real shell. Omitting `--shell` enrolls
exec evidence only and does not change the login account.

AWS SSM does not necessarily enter through the account login shell. Use the
custom Session document and IAM restrictions in [docs/ssm.md](docs/ssm.md) to
obtain PTY evidence for SSM sessions. The protected-root kernel boundary remains
active even when a remote entry point is not enrolled for transcript capture.

## Normal operation

No wrapper is needed for filesystem enforcement:

```bash
rm -rf /srv/production/releases/old
# rm: cannot remove ...: Operation not permitted
```

The process can start, but the protected resource operation is denied before
the target changes. Destructive work outside configured roots remains usable.

`osmanthus check -- ...` and `osmanthus run -- ...` remain compatibility and diagnostic
commands. They are not required by, and do not prove, kernel enforcement.

## Temporary maintenance

The default is five minutes and the initial maximum is thirty minutes. Both are
shown by `policy list`; change them, up to the hard 24-hour limit, through the
authenticated policy command:

```bash
sudo osmanthus policy maintenance set --default 15m --maximum 12h
```

Grant only the required path and operation classes:

```bash
sudo osmanthus maintenance grant \
  --path /srv/production/releases/old \
  --action delete \
  --for 5m

sudo osmanthus maintenance list
sudo osmanthus maintenance revoke LEASE_ID
```

For a long data migration, pause every configured action below one protected
path without unloading enforcement:

```bash
sudo osmanthus maintenance pause --path /srv/production/database --for 8h
```

A lease never disables logging, is lost when the daemon restarts, and cannot
authorize another path or action class. `maintenance pause` is still scoped to
one protected path and the cgroup from which the authenticated request was
made; another SSH/login cgroup remains blocked. Every process already sharing
that cgroup receives the lease. For SSM or another entry point that may share a
service cgroup, first enter a dedicated transient systemd service as described
in [the operations runbook](docs/operations.md).
Hard-link creation across a protected boundary is not an operation class and is
never enabled by a maintenance lease.

## Local evidence

The enforced daemon writes one JSON object per line to
`/var/log/osmanthus/audit.jsonl`. The default logrotate policy keeps rotation local.
Shipping to S3, CloudWatch, a SIEM, or another service is intentionally external
to Osmanthus.

The packaged systemd sandbox keeps policy files read-only. Its only writable
exception below `/etc/osmanthus` is `/etc/osmanthus/admin`, where the daemon
atomically updates TOTP replay-prevention and lockout state.

## Data and database protection

Filesystem protection alone does not prevent credential theft or data
exfiltration. Keep database files, credential files, database connections, and
general outbound traffic as separate policy boundaries. The current release
implements filesystem integrity; read restrictions and destination-aware
network controls are designed but not yet advertised as enforced features. See
[data protection](docs/data-protection.md).

## Current Linux release gates

This branch is not ready for a production release until all of the following
are completed and tested from packages:

- x86_64/amd64 packaged daemon, PTY transcript, crash, upgrade, rollback, and
  audit-failure tests;
- a documented break-glass restore test for a lost policy-administrator authenticator;
- packaged verification of opt-in non-truncating writes and long maintenance;
- signed RPM and deb repository metadata with install and rollback verification.

These gates apply to the Linux release. A native Windows Server service/backend
and Windows Server tests are a separate platform track; Windows support is not
advertised until they pass. macOS native enforcement is deferred. WSL is Linux
enforcement and is not a substitute for Windows Server support.

## Development checks

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
sudo ./target/debug/examples/bpf-smoke
```

The BPF smoke test uses a temporary directory under `/var/tmp`; do not run it on a
host whose kernel capabilities and workload impact have not been reviewed.

## License

[MIT](LICENSE)
