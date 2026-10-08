# Operations runbook

This runbook describes the enforced Linux branch. It is not a production
release procedure until every gate in the README is closed.

## Prerequisites

- Linux x86-64 with BTF, BPF LSM enabled and active, and the `bpf_loop` helper.
- systemd and a mounted bpffs at `/sys/fs/bpf`.
- root access for installation and policy changes.
- a separate RFC 6238 authenticator controlled by the policy administrator.
- a tested console/recovery path before changing any login entry point.

Confirm the kernel capabilities before installation:

```bash
test -r /sys/kernel/btf/vmlinux
grep -qw bpf /sys/kernel/security/lsm
mountpoint /sys/fs/bpf
sudo bpftool feature probe kernel | grep -A200 'program type lsm' | grep -w bpf_loop
```

## Bootstrap

```bash
sudo osmanthus policy init --account production-policy-admin
sudo systemctl enable --now osmanthusd
osmanthus daemon status
```

Initialization prints the TOTP enrollment once. While the current authenticator
is available, rotate it and issue a new QR/URI with:

```bash
sudo osmanthus policy auth rotate
```

The previous secret becomes invalid immediately. If every enrolled copy is
lost, do not edit state by hand; restore `/etc/osmanthus/admin` from a tested,
root-restricted backup. A packaged break-glass restore test remains a release
gate.

Add one existing canonical directory at a time:

```bash
sudo osmanthus policy protect add /srv/application \
  --action delete --action rename --action truncate \
  --action change-permissions
```

Use `--action write` only when ordinary application writes must be stopped too.
This is suitable for immutable release or credential directories, but normally
not for a live database data directory.

Verify both sides of the boundary with disposable files. Never select `/`, a
symlink, or an untested production root for the first check.

```bash
mkdir -p /srv/application/osmanthus-check /tmp/osmanthus-check
touch /srv/application/osmanthus-check/blocked /tmp/osmanthus-check/allowed
rm /srv/application/osmanthus-check/blocked   # expected: denied
rm /tmp/osmanthus-check/allowed               # expected: allowed
test -e /srv/application/osmanthus-check/blocked
```

## Status and evidence

```bash
osmanthus daemon status
sudo osmanthus policy list
sudo osmanthus maintenance list
sudo systemctl status osmanthusd
sudo tail -n 50 /var/log/osmanthus/audit.jsonl
sudo find /sys/fs/bpf/osmanthus -maxdepth 1 -printf '%m %u:%g %f\n'
```

Daemon failure is not evidence that protection detached: pinned LSM links stay
active. Conversely, do not infer that shell transcripts are still being written
while the daemon is down. Treat a daemon/audit outage as an incident and restore
the service before normal operator work continues.

## Login and AWS SSM onboarding

Registering a real shell changes only the selected non-root account and records
its original shell for rollback. Both the real shell and `osmanthus-shell` must be
root-owned executable files that are not group/world writable:

```bash
getent passwd operator
sudo osmanthus policy monitor add "$(id -u operator)" --shell /bin/bash
```

Keep a tested console/recovery path. `policy monitor remove UID` restores the
recorded shell and refuses to overwrite unexpected concurrent shell changes.

AWS SSM starts `sh` by default and can bypass the account login shell. Follow
[`docs/ssm.md`](ssm.md) to create a custom Session document that executes
`/usr/bin/osmanthus-shell`, and constrain IAM to that document. Osmanthus does not mutate
AWS documents or IAM policy during package installation.

## Scoped maintenance

Set the normal default and the maximum accepted duration through authenticated
policy mutation. The hard limit is 24 hours:

```bash
sudo osmanthus policy maintenance set --default 15m --maximum 12h
```

Grant the smallest path, operation set, and duration:

```bash
sudo osmanthus maintenance grant \
  --path /srv/application/releases/old \
  --action delete --for 5m
```

Check the lease, perform the task, then revoke it early:

```bash
sudo osmanthus maintenance list
sudo osmanthus maintenance revoke LEASE_ID
```

For a long migration that needs every configured operation below one path, use
a scoped pause. It creates one ordinary in-memory lease and does not stop the
daemon or detach BPF:

```bash
sudo osmanthus maintenance pause --path /srv/application/database --for 8h
```

A restart clears all leases. A lease does not stop audit collection and does not
authorize other actions or parent/sibling paths. Osmanthus rejects a new lease when
its path is equal to, above, or below an active lease and their operation sets
overlap; revoke the earlier lease or use a non-overlapping operation class.

An already-existing writable shared memory mapping can continue changing its
file after `write` protection is activated. Stop or restart writers before
activating that action, then verify denial with a disposable file. New writes,
new writable shared mappings, and attempts to make a shared mapping writable
are denied after activation.

## Policy change failure

The CLI saves a candidate, requests daemon reload, and records an audit entry.
If reload or audit fails, it restores the prior policy and asks the daemon to
restore the prior map contents. After any reported rollback error, stop changes
and compare:

```bash
sudo sha256sum -c /etc/osmanthus/policy.sha256
osmanthus daemon status
sudo osmanthus policy list
```

Do not directly edit `policy.json`, its digest, or pinned maps.

## Logs

`/var/log/osmanthus/audit.jsonl` is root-only JSONL. The packaged logrotate rule
rotates it locally. Configure any S3, CloudWatch, SIEM, or backup shipping in a
separate root-controlled service and alert on write/forwarding failures.

PTY records contain base64-encoded raw terminal input and output. They can
therefore contain passwords, tokens, or application output typed or printed in
the session. Limit root access, retention, backups, and forwarding accordingly;
Osmanthus does not redact arbitrary terminal content.

## Upgrade, rollback, and uninstall

Same-schema program upgrades attach and pin a complete replacement link set
before promoting it. Startup repairs an interrupted promotion. Package upgrade
restarts an already-active daemon, which performs this blue-green replacement.

The daemon checks the pinned BPF ABI before program replacement. If it reports an
incompatible ABI, the old links remain attached. Do not remove individual pins.
Rollback to the previous package, or schedule a maintenance window to restore
managed login shells, authenticate `daemon decommission`, install the new
package, and initialize a fresh attach. Preserve `/etc/osmanthus` and
`/var/log/osmanthus`; an incompatible policy schema requires a separately
documented policy conversion before startup.

Before uninstall, restore every managed login shell, then authenticate an
explicit decommission:

```bash
sudo osmanthus policy monitor remove UID
sudo osmanthus daemon decommission
sudo dnf remove osmanthus        # or: sudo apt-get remove osmanthus
```

The package uninstall script refuses while `/sys/fs/bpf/osmanthus` exists or an
account still uses `/usr/bin/osmanthus-shell`. Ordinary `systemctl stop` does not
remove pinned enforcement. Audit and policy files are retained for recovery.

## Incident boundary

Osmanthus is designed against bypass by a managed non-root shell or automation UID.
If root, the kernel, or boot trust is suspected compromised, preserve logs,
isolate the host through the surrounding infrastructure, and rebuild from a
trusted image. Local TOTP or file permissions cannot contain root.
