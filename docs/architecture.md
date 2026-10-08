# Onyx v0.1 architecture

## Objective

Onyx v0.1 places a small, reviewable decision point in front of explicitly wrapped Linux commands. It denies known high-risk operations before process creation and requires a short-lived, one-time TOTP approval bound to the exact command digest.

## Execution flow

1. `onyx run -- <command>` loads protected local state.
2. The policy engine evaluates the executable basename and arguments.
3. A command with no finding is audited and started immediately.
4. A risky command without a matching permit is not started. Onyx stores a pending event and returns exit code 77.
5. `onyx approve <event-id>` shows the redacted event and reads a TOTP code from the terminal without echo.
6. Successful authentication creates a 30-second permit for the event's command digest.
7. A retry of the exact command atomically consumes that permit before process creation.
8. Completion and the child exit status are appended to the local audit log.

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

## Command binding

The digest is SHA-256 over each argument's byte length and value in order. It distinguishes argument boundaries and prevents a permit issued for one argument vector from authorizing a different vector.

The Linux implementation preserves raw argument bytes for digest calculation. Policy inspection and the human-readable audit summary use a lossy UTF-8 representation; unusual non-UTF-8 arguments must not be assumed to receive equivalent semantic policy analysis.

## TOTP

Onyx implements RFC 6238 with HMAC-SHA-1, six digits, and a 30-second period for compatibility with common authenticator applications. The verifier accepts one adjacent step on either side for clock drift, rate-limits failures, and records the last successful counter to reject replay.

The server must retain the symmetric TOTP seed. File permissions reduce accidental disclosure but do not protect it from root. Hardware-backed asymmetric approval is the planned stronger boundary.

## Audit behavior

Audit append failure prevents a command from starting when the failure occurs before execution. A failure while recording completion cannot undo an already completed command. Logs are local JSON Lines and deliberately omit command output and authentication secrets.

## Deferred enforcement layer

A later privileged broker may combine a root-owned daemon with Linux security controls such as BPF LSM. That layer must define kernel compatibility, policy update authorization, daemon failure behavior, process-tree semantics, package installation, rollback, and tamper resistance before implementation. It must not silently change the explicit-wrapper guarantees of v0.1.
