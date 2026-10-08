# Onyx operations runbook

This runbook covers the explicit-wrapper architecture in Onyx v0.1. It does not turn Onyx into host-wide enforcement. Commands launched without `onyx run --` remain outside the protection boundary.

## Before installation

1. Choose a dedicated, least-privileged operating-system identity for protected automation.
2. Confirm that the host clock is synchronized. TOTP approval depends on accurate time.
3. Decide who controls the execution authenticator and the separate policy-administrator authenticator.
4. Decide how long local audit records must be retained and whether an existing log collector will forward them.
5. Keep a separate administrative access path for recovery. Onyx does not provide an unauthenticated reset command.

The identity running Onyx owns its execution state. The system policy is separately root-owned, but the wrapper still does not contain a fully compromised state owner or root.

## Initial deployment

Install the binary, then initialize Onyx once as the identity that will invoke it:

```console
onyx init --account production-web-01
sudo onyx policy init --account production-policy-admin
onyx status
onyx check -- rm -rf /example
onyx run -- /usr/bin/true
onyx logs --limit 10
```

Verify all of the following before putting Onyx in an automation path:

- the authenticator displays a six-digit code for the enrolled account;
- `status` reports the expected state directory and account;
- the destructive example is reported as blocked by `check` and is not executed;
- the harmless command exits successfully;
- the audit log contains `initialized`, `allowed`, and `completed` records;
- state directories have mode `0700` and state files have mode `0600`.
- `/etc/onyx` is root-owned mode `0755`, its policy and digest are root-owned mode `0444`, and `/etc/onyx/admin` is mode `0700`.

Use different authenticator entries for command execution and policy administration. Verify policy management from an administrative console:

```console
sudo onyx policy add --id deployment --executable deploy --argument-contains production --reason "production deployment"
onyx policy list
sudo onyx policy remove --id deployment
```

Both mutations must prompt for the policy-administrator code. Do not grant the protected workload unrestricted `sudo`; the TOTP prompt is an additional condition, not a replacement for operating-system privilege policy.

Use absolute executable paths in production automation when practical. Onyx binds approval to the exact argument bytes, but executable lookup still follows the invoking process environment when a basename is supplied.

## Audit retention

The default audit file is `/var/lib/onyx/audit.jsonl` for root or `$XDG_STATE_HOME/onyx/audit.jsonl` for a regular user. The repository's [`ops/logrotate/onyx`](../ops/logrotate/onyx) example is for a root-owned installation.

Before installing that example, review its path, owner, `10M` rotation threshold, and seven-generation retention. Validate a copied configuration from an administrative console:

```console
sudo logrotate --debug /etc/logrotate.d/onyx
```

Do not send TOTP seeds or production audit records to issue trackers. If audit forwarding is required, configure the existing host collector to tail the JSONL file; Onyx itself does not hold cloud credentials or upload logs.

## Routine checks

Run these checks after host maintenance and on the operator's normal security-review cadence:

```console
onyx status
onyx logs --limit 50
```

Also monitor:

- host clock synchronization;
- free disk space and log rotation;
- unexpected `approval_failed`, `execution_failed`, or repeated `blocked` records;
- owner and mode changes under the state directory;
- owner, mode, completeness, and digest failures under `/etc/onyx`;
- automation paths that invoke commands without `onyx run --`.

An audit write failure before execution is fail-closed. A completion-record failure cannot reverse a child command that already finished, so alert on write errors rather than assuming every completed operation has a final record.

## Backup and restore

The state directory contains the TOTP seed and must be treated as a secret. If recovery policy requires a backup, encrypt it with an independently controlled key and restrict access more tightly than the protected workload identity.

A restore must preserve each state directory as one consistency unit. Restore while no Onyx command, approval, or policy mutation is running. Preserve the user-state owner and `0700`/`0600` modes. Restore `/etc/onyx` only as root with `0755` on its top directory, `0444` on both policy files, and `0700`/`0600` within `admin`. Do not restore only one of `policy.json` and `policy.sha256`. Run `onyx status`, `onyx policy list`, and a harmless command afterward. Do not merge event or authentication-state files from different backup times.

If the backup may have been disclosed, do not restore its TOTP enrollment. Preserve required audit evidence, initialize a new state directory, and enroll a new authenticator instead.

## Upgrade and rollback

Before upgrading:

1. record the installed `onyx --version`;
2. retain the previous trusted binary or package artifact;
3. create an encrypted state backup if policy requires recovery;
4. review release notes for state-schema or policy changes;
5. test `status`, `check`, one harmless execution, and one non-executing blocked check after installation.

For a binary rollback, reinstall the previous trusted artifact only when its release notes declare the stored schema compatible. Onyx v0.1 rejects unsupported schema versions rather than attempting an implicit downgrade. Restoring older mutable state loses newer audit and approval history and should be an incident-controlled action, not a routine rollback.

## Lost authenticator or suspected compromise

If the authenticator is lost, use the separately controlled administrative access path. Preserve audit records required for investigation, replace the state directory with a fresh initialization, and enroll a new authenticator. Pending events and permits from the old state must not be copied forward.

If the state owner or root may be compromised:

1. stop relying on Onyx as an authorization boundary;
2. isolate the affected workload using the host or infrastructure control plane;
3. preserve logs according to incident-response policy;
4. rotate credentials exposed to that identity, including the execution TOTP seed; if root may be compromised, also replace the policy-administrator enrollment and validate the complete policy;
5. rebuild or recover the host from a trusted point before re-enrollment.

Local JSONL evidence can be changed or deleted by a sufficiently privileged attacker. Use an existing remote log pipeline when tamper-resistant retention is required.

## Decommissioning

Uninstalling the package does not delete security state or audit evidence. Confirm retention and incident requirements first, then archive or remove only the known Onyx state directory through the organization's administrative process. Record who approved the deletion and which backup, if any, remains recoverable.
