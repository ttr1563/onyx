# Security policy

## Supported versions

Onyx has not made its first stable release. Security fixes are applied to the latest development version until a release support policy is published.

## Reporting a vulnerability

Do not include TOTP seeds, authenticator codes, hostnames, IP addresses, production commands, or audit logs in a public issue.

Use GitHub's private vulnerability reporting feature for this repository. Include the affected revision, operating system, minimal reproduction steps using non-sensitive sample data, impact, and any suggested mitigation.

## Security boundary

Onyx v0.1 is an explicit command wrapper. It reduces mistakes and constrains cooperating automation, but it does not claim to resist:

- execution that bypasses `onyx run`;
- an attacker with root or equivalent host control;
- modification by the operating-system identity that owns the Onyx state directory;
- deletion of local-only audit records by a privileged attacker;
- all semantic equivalents of a dangerous command.

TOTP uses a shared secret stored by the verifier. It delays an attacker who lacks the enrolled authenticator, but the operating-system identity that owns Onyx state can read that seed and generate valid codes. A future administrator-owned broker with hardware-backed signing will keep only public verification material on the protected host.
