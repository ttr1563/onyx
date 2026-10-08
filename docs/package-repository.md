# Legacy Onyx RPM repository runbook

> Historical reference only. This tree describes the retired Onyx v0.1.3
> wrapper repository and its Onyx signing identity. It must not be used to
> publish Osmanthus. The first Osmanthus repository bootstrap requires a
> separately approved version, signing identity, and release runbook.

This document covers the public Amazon Linux 2023 repository at
`https://ttr1563.github.io/onyx/rpm/`. It is a package distribution path, not
an enforcement component. Onyx retains the security boundaries documented in
`SECURITY.md` regardless of installation method.

## Supported repository layout

```text
docs/rpm/
├── RPM-GPG-KEY-ONYX
├── SHA256SUMS
├── SHA256SUMS.asc
├── onyx-release-1-1.noarch.rpm  # stable bootstrap filename
└── al2023/
    └── x86_64/
        ├── Packages/
        │   ├── onyx-<version>-1.amzn2023.x86_64.rpm
        │   └── onyx-release-1-1.amzn2023.noarch.rpm
        └── repodata/
            ├── repomd.xml
            └── repomd.xml.asc
```

The repository initially supports Amazon Linux 2023 on `x86_64`. The spec can
package an `aarch64` binary on an `aarch64` builder, but publication requires a
native build and install smoke test before that architecture is advertised.

## Build

Build on Amazon Linux 2023 with Rust 1.91 or later, RPM build tools, and
`createrepo_c`. Run resource checks first on shared or burstable hosts.

```console
scripts/build-rpm.sh 0.1.3 docs/rpm/al2023
```

The script performs a locked release build and creates the architecture RPM.
It does not sign or publish anything. The package owns all three executables,
the systemd unit, documentation, the SSM Session document template, license,
and logrotate configuration. It deliberately does not own or remove
`/var/lib/onyx` or `/etc/onyx`.

## Sign and generate metadata

Use the dedicated Onyx signing key from a restricted GnuPG home. Never put the
private key or passphrase in Git, shell arguments, artifacts, or logs.

```console
export ONYX_GPG_HOME=/secure/path/to/onyx-signing-home
export ONYX_GPG_KEY_ID=<full-fingerprint>
scripts/build-rpm-repository.sh docs/rpm
scripts/verify-rpm-repository.sh
```

The repository definition enables both package and metadata signature checks.
The public key fingerprint published in the release notes must match the key
embedded in `onyx-release` and `docs/rpm/RPM-GPG-KEY-ONYX`.

Initial key fingerprint:

```text
E9E3 C123 DEDF B3E9 AEA1 F3A9 CD2E 615D BC32 CF0C
```

## Release gate

Before merging the repository tree to `main`:

1. Run format, clippy, tests, and dependency advisory checks.
2. Verify every RPM signature and the detached `repomd.xml` signature.
3. Query package contents, dependencies, architecture, and scripts.
4. Install from a temporary local DNF repository on Amazon Linux 2023.
5. Run `onyx --version`, a harmless execution, and a blocked non-executing check.
6. Remove the package and confirm retained Onyx state is untouched.
7. Confirm the Pages tree contains no private key, passphrase, audit data, or enrollment seed.
8. Merge through the protected release PR, tag the immutable revision, and retain the previous package.

Publish metadata and packages in the same commit so Pages never intentionally
serves metadata for a missing RPM. After Pages finishes, fetch the public key,
release RPM, RPM payload, and `repomd.xml` over HTTPS and compare their hashes
with the committed files.

## Rollback

Keep the current and immediately previous installable RPM in `Packages/`.
Because repository metadata selects the highest version, ordinary rollback is
explicit:

```console
sudo dnf downgrade onyx-<previous-version>
```

If a new package or metadata signature is invalid, do not alter an existing
tag. Revert the repository publication through a PR or publish a fixed patch
release. For a security defect, stop promotion, follow the hotfix flow, and
leave evidence required for incident review intact.

## Signing-key lifecycle

The signing private key is an operational secret outside this repository.
Maintain an encrypted offline backup and record authorized maintainers. Before
expiry or suspected compromise, create a new dedicated key, publish both public
keys during a documented overlap release, update `onyx-release`, and only then
sign subsequent packages with the new key. A compromised key requires an
incident notice and a new trust bootstrap; silently replacing the public key is
not a recovery mechanism.
