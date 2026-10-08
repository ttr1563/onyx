# Enforced architecture

## Decision boundary

Osmanthus does not decide by executable name alone. The Linux kernel backend denies
an operation only when both dimensions match:

1. the target is the configured root or one of its descendants; and
2. the operation class is enabled for that root.

The classes are delete, rename/move, truncate through `O_TRUNC`, opt-in ordinary
write, and ownership/mode change. This keeps the same operation blocked when it
comes from `rm`, Python, Node.js, or another process, while leaving unrelated
paths usable. The global write hook returns immediately unless at least one root
enables `write`.

## Runtime flow

```text
process
  ├─ execve/execveat ── monitored UID? ── event ring ── osmanthusd ── JSONL
  └─ filesystem operation
       └─ BPF LSM walks target ancestors
            ├─ no protected key ── allow
            ├─ active path/action lease ── allow
            └─ protected key ── audit event + synchronous errno
```

`osmanthusd` runs as root, loads `/etc/osmanthus/policy.json`, and owns the Unix socket at
`/run/osmanthus/osmanthusd.sock`. Its BPF maps and links are pinned below
`/sys/fs/bpf/osmanthus`, so killing the daemon does not detach enforcement. On daemon
restart, existing links are reopened, policy maps are reconciled, and all
maintenance entries are cleared.

The pinned map set includes an explicit BPF ABI version. Same-ABI upgrades reuse
the existing maps and promote a complete replacement link set only after every
new program is attached and pinned. If the ABI version or map layout is
incompatible, startup fails without replacing or detaching the existing links.
An incompatible release therefore requires an explicit decommission, package
rollback point, and fresh attach; it is never migrated silently in place.

The BPF ancestor walk uses the kernel `bpf_loop` helper and is bounded to 256
dentries. Reaching the bound returns `ELOOP` instead of allowing the operation, including outside configured
roots. This rare availability tradeoff prevents depth-based escape and is part
of the supported-path contract.

## Policy integrity

The effective policy is `/etc/osmanthus/policy.json` with a companion SHA-256 digest.
Both files must be regular, root-owned, mode 0444 files in a root-owned mode
0755 directory. Policy mutation is exposed as structured CLI operations; it
requires UID 0 and the separately enrolled policy-administrator TOTP. On daemon
reload or audit failure, the prior file and kernel policy are restored.

The policy is integrity-protected, not encrypted. Rules and paths are not
secrets. The TOTP seed is stored below `/etc/osmanthus/admin` with root-only access.
Linux root remains outside the threat boundary.

## Maintenance

A maintenance lease contains a UUID, canonical scope, operation classes,
administrator UID, issue time, and expiry. Default and maximum durations are
policy settings, initially five and thirty minutes, with an absolute 24-hour
limit. `maintenance pause` selects every configured action below one path but is
implemented as the same scoped lease rather than detaching enforcement. Kernel
expiry uses a monotonic deadline. Leases exist only in daemon memory and the BPF
map, are auditable, can be revoked, and are cleared on daemon restart.

## Shell evidence

`osmanthus-shell` is a PTY supervisor. For an enrolled UID it opens a daemon session,
starts the configured real shell, records base64-encoded input/output frames
before forwarding them, and closes the session with its exit status. If the
daemon or audit path rejects a frame, the supervised shell is terminated.
Kernel exec events independently cover descendant `execve` and `execveat`.

`policy monitor add UID --shell /real/shell` validates the current NSS account,
records its real shell, reloads the daemon policy, and then uses root-owned
`usermod` to select `/usr/bin/osmanthus-shell`. Removal performs the reverse change.
Policy, daemon, shell transition, and audit failures use compensating rollback;
concurrent shell changes are rejected rather than overwritten.

## Audit

The daemon appends JSON objects to `/var/log/osmanthus/audit.jsonl`. Records cover
kernel exec and deny events, session lifecycle and I/O, policy reload, and
maintenance lifecycle. The kernel denial identifies the target by device and
inode; session and exec records provide nearby command context. External
forwarding is intentionally separate.

Kernel resource enforcement remains active if audit handling fails. The PTY
supervisor stops forwarding interactive input when its audit request fails.
Exec tracepoints for enrolled service and scheduled-job UIDs are observational;
their ring-buffer or audit failure does not synchronously deny every new exec.

## Known gates

- `sb_mount` and `move_mount` are denied below protected roots so a new mount
  cannot replace the inode ancestry used by the resource boundary.
- `write` covers write syscalls, new writable shared mappings, and attempts to
  make a shared mapping writable. A mapping that was already writable before
  policy activation cannot be revoked; writers must be stopped or restarted
  before enabling that action.
- Database reads and outbound connection enforcement are designed separately in
  [data-protection.md](data-protection.md) and are not implemented yet.
- An incompatible BPF ABI is detected and rejected while the existing
  enforcement remains attached. Such an upgrade requires the documented
  maintenance/decommission/fresh-attach procedure.
- Native Windows Server interception/service integration is not implemented.

These are release blockers, not hidden fallback behavior. The authoritative
acceptance criteria are in [enforcement-requirements.md](enforcement-requirements.md).
