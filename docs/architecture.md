# Onyx v0.1 architecture

## Objective

Onyx v0.1 places a small, reviewable decision point in front of explicitly wrapped Linux commands. It denies known high-risk operations before process creation and requires a short-lived, one-time TOTP approval bound to the exact command digest.

## Execution flow

1. `onyx run -- <command>` loads protected local state and the effective policy.
2. If `/etc/onyx` exists, Onyx verifies its root ownership, read-only modes, schema, and digest. Any inconsistency stops evaluation. Otherwise, it uses the legacy user policy for compatibility.
3. The policy engine evaluates the executable basename and arguments.
4. A command with no finding is audited and started immediately.
5. A risky command without a matching permit is not started. Onyx stores a pending event and returns exit code 77.
6. `onyx approve <event-id>` shows the redacted event and reads a TOTP code from the terminal without echo.
7. Successful authentication creates a 30-second permit for the event's command digest.
8. A retry of the exact command atomically consumes that permit before process creation.
9. Completion and the child exit status are appended to the local audit log.

## State model

All mutable state lives under one state directory:

```text
onyx/
├── .lock
├── audit.jsonl
├── auth-state.json
├── config.json
├── policy.json
└── events/
    └── <uuid>.json
```

JSON state replacement uses a new owner-only temporary file, `fsync`, same-directory rename, and parent-directory `fsync`. Mutations are serialized with an advisory file lock. Approval is consumed before command execution, favoring fail-closed behavior over automatic retry.

Custom rules can instead be made authoritative in the system-policy store:

```text
/etc/onyx/
├── policy.json        root:root 0444
├── policy.sha256      root:root 0444
└── admin/             root:root 0700
    ├── config.json    policy-administrator TOTP seed
    ├── auth-state.json
    ├── audit.jsonl
    └── ...
```

`sudo onyx policy init` creates this tree as one rename. `sudo onyx policy add/remove` acquires the administrator-state lock, consumes a non-replayed administrator TOTP code, reloads and validates the current policy, then writes validated JSON and its digest through owner-controlled temporary files, `fsync`, and rename. Onyx intentionally exposes structured mutations instead of invoking an editor with shell escape paths.

The two policy files cannot be renamed as one filesystem object, so a crash between their renames can leave a temporary mismatch. Readers reject that state instead of falling back to user policy. An administrator can restore the complete `/etc/onyx` consistency unit from a trusted backup.

## Command binding

The digest is SHA-256 over each argument's byte length and value in order. It distinguishes argument boundaries and prevents a permit issued for one argument vector from authorizing a different vector.

The Linux implementation preserves raw argument bytes for digest calculation. Policy inspection and the human-readable audit summary use a lossy UTF-8 representation; unusual non-UTF-8 arguments must not be assumed to receive equivalent semantic policy analysis.

## TOTP

Onyx implements RFC 6238 with HMAC-SHA-1, six digits, and a 30-second period for compatibility with common authenticator applications. The verifier accepts one adjacent step on either side for clock drift, rate-limits failures, and records the last successful counter to reject replay.

Execution approval and policy administration use separate symmetric TOTP seeds. The policy-administrator seed is root-only; the execution-approval seed remains owned by the protected identity. File permissions do not protect either seed from root, and the latter does not resist full compromise of its owning identity. Hardware-backed asymmetric approval through a privileged verifier is the stronger future boundary.

## Audit behavior

Audit append failure prevents a command from starting when the failure occurs before execution. A failure while recording completion cannot undo an already completed command. Logs are local JSON Lines and deliberately omit command output and authentication secrets.

## Deferred enforcement layer

A later privileged broker may combine a root-owned daemon with Linux security controls such as BPF LSM. That layer must define kernel compatibility, policy update authorization, daemon failure behavior, process-tree semantics, package installation, rollback, and tamper resistance before implementation. It must not silently change the explicit-wrapper guarantees of v0.1.
