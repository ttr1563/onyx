# Security policy

## Supported versions

Onyx is still in the pre-1.0 development series. Security fixes are applied to the latest published patch release and the `develop` branch until a longer-term support policy is published.

## Reporting a vulnerability

Do not include TOTP seeds, authenticator codes, hostnames, IP addresses, production commands, or audit logs in a public issue.

Use GitHub's private vulnerability reporting feature for this repository. Include the affected revision, operating system, minimal reproduction steps using non-sensitive sample data, impact, and any suggested mitigation.

## Security boundary

Onyx v0.1 is an explicit command wrapper. It reduces mistakes and constrains cooperating automation, but it does not claim to resist:

- execution that bypasses `onyx run`;
- an attacker with root or equivalent host control;
- modification of that identity's command events, permits, execution-approval state, or local audit records;
- deletion of local-only audit records by a privileged attacker;
- all semantic equivalents of a dangerous command.

An initialized system policy is held at `/etc/onyx` as root-owned read-only files. Policy `add` and `remove` require effective UID 0 and a separate administrator TOTP. Missing files, unsafe ownership or modes, symbolic links, invalid schema, and digest mismatches fail closed. SHA-256 is an integrity consistency check, not a defense against root, which can replace the policy and digest together.

Command execution approval uses a different TOTP seed in the protected identity's mutable state. TOTP is a shared-secret mechanism: code running as that identity can read the execution-approval seed and modify its events or permits. Root-owned policy protects rule definitions, but does not turn the wrapper into containment for a fully compromised identity. A privileged broker with asymmetric, hardware-backed approval remains a possible stronger design.
