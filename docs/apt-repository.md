# Onyx APT repository runbook

This document covers the public Debian/Ubuntu repository at
`https://ttr1563.github.io/onyx/apt/`. The repository is only a distribution
path; installation does not extend the enforcement boundary described in
`SECURITY.md`.

## Supported repository layout

```text
docs/apt/
├── onyx.asc
├── onyx.sources
├── SHA256SUMS
├── SHA256SUMS.asc
├── dists/stable/
│   ├── InRelease
│   ├── Release
│   ├── Release.gpg
│   └── main/binary-amd64/
│       ├── Packages
│       └── Packages.gz
└── pool/main/o/onyx/
    └── onyx_<version>-1_amd64.deb
```

The initial repository supports `amd64` on Debian 12 and Ubuntu 22.04 or
later. An architecture or distribution must pass its own installation smoke
test before it is advertised.

## Build

Build on an `x86_64` host with Rust 1.91 or later and GNU `ar`, `tar`, and
`gzip`:

```console
scripts/build-deb.sh 0.1.2 docs/apt/pool/main/o/onyx
```

The package contains the Onyx executable, MIT license, README, operations
runbook, and root logrotate example. `/var/lib/onyx` and `/etc/onyx` are
deliberately not owned or removed by the package, including during purge,
because they can contain enrollment state, policy, and audit evidence.

## Sign and generate metadata

APT metadata and checksum manifests use the same dedicated Onyx package key as
the RPM repository. Keep the private key and passphrase outside Git, shell
arguments, artifacts, and logs.

```console
export ONYX_GPG_HOME=/secure/path/to/onyx-signing-home
export ONYX_GPG_KEY_ID=<full-fingerprint>
scripts/build-apt-repository.sh docs/apt
scripts/verify-apt-repository.sh docs/apt
```

Initial key fingerprint:

```text
E9E3 C123 DEDF B3E9 AEA1 F3A9 CD2E 615D BC32 CF0C
```

The published deb822 source uses `Signed-By` so the key grants authority only
to the Onyx repository. Both `InRelease` and detached `Release.gpg` signatures
are published for compatible APT clients.

## Release gate

Before merging the repository tree to `main`:

1. Run format, clippy, tests, and dependency advisory checks.
2. Verify `InRelease`, `Release.gpg`, checksum signatures, and every listed hash.
3. Inspect package control fields, members, file owners, modes, and dependencies.
4. On Debian 12 and Ubuntu 22.04 or later, use the public-style `Signed-By`
   source to run `apt-get update` and install the package.
5. Run `onyx --version`, a harmless command, and a blocked non-executing check.
6. Upgrade from the previous package when available, then remove and purge the
   package and confirm retained Onyx state remains untouched.
7. Confirm that no private key, passphrase, TOTP seed, or real audit record is
   present in the Pages tree.
8. Publish package and metadata in one immutable release commit.

For the distribution smoke test, prepare the `debian:12` and `ubuntu:22.04`
images on a non-production builder, start Docker only for the test window, and
run:

```console
scripts/test-deb.sh docs/apt
```

The script does not pull images or start Docker implicitly. Each container is
network-isolated after image preparation and limited to one CPU, 512 MiB of
memory, and 256 PIDs. It checks signed repository refresh, installation,
allowed and blocked CLI paths, purge, and retention of `/var/lib/onyx` and
`/etc/onyx` evidence.

## Rollback and key lifecycle

Keep the current and immediately previous package in `pool`. Ordinary rollback
is explicit:

```console
sudo apt-get install onyx=<previous-version>-1
```

Do not rewrite an existing tag when a package is defective. Revert publication
through a PR or publish a fixed patch release. Key rotation must update the APT
and RPM trust bootstrap during an overlap release; a compromised key requires
an incident notice and a new explicit trust bootstrap.
