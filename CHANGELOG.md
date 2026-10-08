# Changelog

All notable changes to Onyx are documented in this file. Versions follow Semantic Versioning after the initial `0.1.0` release.

## [0.1.1] - 2026-10-08

### Added

- signed Amazon Linux 2023 `x86_64` RPM and DNF repository packaging;
- `onyx-release` bootstrap package with repository configuration and public signing key;
- English and Japanese GitHub Pages with language metadata and navigation;
- package signing, publication, key rotation, and rollback runbook.

### Distribution boundary

- the initial RPM repository supports Amazon Linux 2023 on `x86_64` only;
- uninstalling the RPM does not delete Onyx state or audit evidence.

## [0.1.0] - 2026-10-08

### Added

- explicit `onyx run -- <command>` protection for Linux commands;
- built-in high-risk command rules and additive site-specific policy rules;
- RFC 6238 TOTP enrollment and approval with replay and rate-limit protection;
- short-lived, command-bound permits that are consumed before process creation;
- local redacted JSONL audit records and a root-owned logrotate example;
- owner/mode, symlink, regular-file, size-bound, atomic-write, and state-lock checks;
- CLI status, audit inspection, and non-executing policy checks;
- security model, architecture, operations runbook, and GitHub Pages documentation;
- Homebrew Formula for source installation on Linux and macOS.

### Security boundary

- v0.1 protects only commands launched through `onyx run`;
- TOTP state is readable by its owning operating-system identity and is not a boundary against that identity or root;
- local-only audit records are not tamper-proof against privileged access.

[0.1.1]: https://github.com/ttr1563/onyx/releases/tag/v0.1.1
[0.1.0]: https://github.com/ttr1563/onyx/releases/tag/v0.1.0
