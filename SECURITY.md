# Security policy

## Supported versions

Osmanthus is in pre-release development. The public Onyx v0.1.3 artifacts are
the earlier compatibility wrapper and are not an Osmanthus enforcement release.
Security fixes for Osmanthus are applied to `develop` until its first signed
release establishes a supported-version policy.

## Reporting a vulnerability

Do not include TOTP seeds, authenticator codes, hostnames, IP addresses, production commands, or audit logs in a public issue.

Use GitHub's private vulnerability reporting feature for this repository. Include the affected revision, operating system, minimal reproduction steps using non-sensitive sample data, impact, and any suggested mitigation.

## Security boundary

Osmanthus uses Linux BPF LSM hooks to deny selected filesystem operations below
administrator-configured roots. The decision follows the target resource and
operation class rather than an executable name, so normal enforcement does not
require `osmanthus run`.

The effective policy and policy-administrator TOTP state are root-owned below
`/etc/osmanthus`. Policy changes and temporary maintenance leases require both
UID 0 and the administrator TOTP. The policy files are integrity-checked but not
encrypted; protected paths and rule values must not contain secrets.

The boundary does not contain Linux root, a compromised kernel, or a compromised
boot chain. Such an identity can replace local policy, code, BPF state, and audit
records. TOTP provides a separately held approval factor but is not proof of
physical presence.

Current operation classes cover deletion, rename or move, `O_TRUNC`, and
ownership or mode changes. Non-truncating writes are not yet classified as
destructive overwrite. Native Windows Server enforcement is a separate,
unimplemented platform track; WSL does not provide that coverage.

The public Onyx v0.1.3 wrapper has a different and weaker boundary. Its state is
not imported automatically into Osmanthus.
