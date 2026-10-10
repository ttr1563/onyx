# Data access and exfiltration design

Osmanthus currently enforces filesystem integrity. Preventing information theft
requires separate controls for stored secrets, database authorization, database
connections, and outbound destinations. Treating all of these as command-name
patterns would be easy to bypass and would break unrelated deployments.

## Boundary model

```text
managed shell or automation UID
        │
        ├── filesystem mutation ── protected root/action (implemented)
        ├── secret file read ───── protected read root + UID/cgroup allowlist (planned)
        ├── database connection ── socket/destination + identity policy (planned)
        └── external connection ── destination/port allowlist + audit (planned)
                                      │
                                      └── database-native roles and audit
```

The location of application releases, credentials, Unix sockets, database data,
and deployment workspaces is deployment-specific. Osmanthus must therefore use
administrator-declared resources and identities rather than fixed paths or a
global list of forbidden commands.

## Filesystem integrity

`delete`, `rename`, `truncate`, `write`, and `change-permissions` can be selected
independently for each root. `write` denies ordinary write operations and new
writable shared mappings. It is opt-in because a live database or upload service
must normally write its own data.

An existing writable shared mapping cannot be revoked safely by attaching a new
BPF policy. Before enabling `write`, stop or restart processes that may already
hold such mappings, activate the policy, and verify the boundary with a
disposable file.

## Credentials and database access

Protecting a database data directory from deletion does not prevent a process
from reading credentials and querying the database. A future read-control layer
should bind secret roots to allowed service UIDs or cgroups. The application
service can read its credential, while an enrolled deployment or AI-agent UID
cannot. The policy must not log secret contents.

Database authorization remains authoritative inside the database: use distinct
roles, least privilege, short-lived credentials where available, query/audit
logging, and separate backup credentials. Osmanthus should complement these
controls, not parse SQL as its security boundary.

## Connection and exfiltration control

A future Linux network backend should enforce destination addresses, Unix socket
identities, ports, and initiating UID or cgroup at the operating-system boundary.
Useful modes are:

- allow only named database sockets or private database destinations for an
  application service;
- deny database destinations to interactive deployment or AI-agent identities;
- allow outbound HTTPS only through a controlled proxy for selected identities;
- record connection metadata without capturing payloads or credentials.

DNS names alone are not a stable enforcement identity because resolution can
change. Policy should compile approved names into observed address sets with
expiry and should keep an explicit failover procedure. Loopback, Unix sockets,
IPv4, IPv6, containers, and network namespaces require separate tests.

## Release boundary

Read and network enforcement are not implemented in the current Linux package.
Documentation and status output must not claim that database reads or data
exfiltration are blocked until kernel tests cover alternate clients, inherited
file descriptors, Unix sockets, TCP, IPv6, containers, policy reload, audit
failure, and rollback.
