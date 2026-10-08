# Osmanthus enforced monitoring requirements

This document is the authoritative product boundary for the enforced Osmanthus
architecture. Implementation convenience must not weaken these requirements.

## Objective

Osmanthus protects command execution originating in managed server shell sessions.
An operator or automation process uses its normal shell syntax; routine use must
not require an `osmanthus run -- ...` prefix.

## Required behavior

1. A privileged, operating-system-managed daemon starts at boot and owns policy,
   approval state, verifier secrets, and audit files.
2. SSH, SSM, local terminal, and automation shells explicitly enrolled in Osmanthus
   are supervised from session creation through all descendant processes.
   Protected filesystem roots are enforced host-wide, independently of shell
   enrollment, so alternate interpreters do not bypass the resource boundary.
3. The monitor observes shell input/output and every descendant `execve` or
   equivalent process creation event without requiring cooperation from the
   command being evaluated.
4. Protected filesystem operations are denied synchronously by the operating
   system before the operation changes its target. Command-pattern rules add
   detection context but do not broadly disable an executable.
5. Protected resource operations fail closed in the kernel. Loss of the daemon
   or audit destination does not detach pinned resource enforcement. Interactive
   supervised shells stop forwarding new input when they cannot record it;
   enrolled service and scheduled-job exec events remain observational and do
   not stop all host automation during an audit outage.
6. A temporary maintenance approval is bound to named protected roots,
   operation classes, and a bounded lifetime. TOTP approval uses a verifier
   secret readable only by the privileged daemon; hardware-backed asymmetric
   approval remains an additive backend. Exact-command one-time approval
   remains a compatibility feature of `osmanthus run`, not the kernel boundary.
7. Policy changes require operating-system administrator privilege and the
   policy-administrator authenticator. Unprivileged session owners cannot edit,
   replace, remove, or disable the effective policy.
8. Audit data is written locally to privileged files. It records session
   lifecycle, input/output metadata, process execution, policy decisions,
   approval, execution result, monitor failure, and daemon lifecycle. Remote
   forwarding is optional and outside the default installation.
9. `osmanthus run` and `osmanthus check` remain diagnostic and compatibility commands;
   they are not the normal enforcement path and are not evidence that automatic
   monitoring works.
10. Installation and upgrade must preserve existing audit/state for recovery,
    provide an explicit rollback path, and never replace a user's login shell
    without an administrator onboarding action.
11. Enforcement is scoped by protected resource roots and operation classes.
    Commands outside those roots remain usable; Osmanthus must not implement a broad
    executable denylist as the final security boundary.
12. An administrator can create a temporary maintenance lease for named roots
    and operation classes. A lease requires operating-system administrator
    privilege and administrator authentication, has a bounded lifetime, is
    fully audited, can be revoked early, and never survives a daemon restart.

## Protected resources and maintenance

A policy names canonical absolute roots and the destructive operation classes
guarded below them. Initial operation classes are deletion, rename or move,
    truncate, opt-in non-truncating write, ownership or mode change, and separately
named service-control operations. Read-only access and unrelated paths are not
blocked merely because Osmanthus is installed.

Shell command patterns provide early detection and a useful event description.
The final decision is based on the target resource and operation observed by
the operating-system enforcement backend, so changing `rm` to Python, Node.js,
or another executable does not bypass protection.

Maintenance mode is represented by an in-memory lease rather than disabling
the daemon or unloading enforcement. A lease is limited to selected protected
roots and operation classes. Its default and maximum durations are policy
settings; the absolute implementation limit is 24 hours. A pause is a lease for
all configured actions below one selected protected path, not a daemon stop or
host-wide permanent disablement. Every lease expires on daemon restart.
Creation, use, revocation, and expiry are audit events.

## Platform scope

### Linux server — first production target

- Managed entry points: OpenSSH, AWS SSM, and local login shells.
- Managed descendants: direct commands, scripts, nested shells, and child
  processes created with `execve`/`execveat`.
- Service management: a systemd unit for the privileged daemon.
- The protected-root kernel boundary also applies to scheduled jobs and systemd
  services. Their process-execution logs are collected only when their OS UID
  is explicitly enrolled.

### Windows Server — required native target

- Managed entry points: PowerShell, `cmd.exe`, WinRM, RDP-launched terminals,
  Scheduled Tasks, and enrolled Windows services.
- Service management: a Windows Service running under a privileged service
  identity.
- The common policy, event, approval, and audit schemas are shared with Linux;
  process interception and OS policy integration are implemented by a native
  Windows adapter.
- WSL-only support does not satisfy Windows Server support.

### macOS — deferred

macOS may reuse the common client and policy model later. No native enforcement
claim is made until a separately tested backend exists.

## Threat boundary

The enforced design protects a managed, non-administrator shell or automation
identity from bypassing command policy. It does not claim containment after
Linux root, Windows Administrator/SYSTEM, the kernel, or the boot trust chain is
compromised. Those identities control the local enforcement components.

Shell aliases, profile scripts, `PATH` shims, and voluntary wrappers alone do
not satisfy these requirements. Session transcript capture alone also does not
satisfy pre-execution blocking.

## Acceptance gates

- A normal shell command is logged and evaluated without the `osmanthus` prefix.
- A destructive operation typed normally is denied synchronously before its
  target changes, creates an audit event, and leaves its target unchanged. The
  process may start; protection is attached to the resource operation rather
  than a broad executable denylist.
- The same destructive operation implemented through a different executable is
  still denied when it targets a protected root.
- A harmless command and destructive work outside protected roots remain
  available unless another explicit policy applies.
- A valid maintenance lease allows only its named roots and operation classes;
  an expired lease or an operation outside its scope remains denied.
- A nested shell and a script cannot escape descendant process supervision.
- Killing or disconnecting the monitor cannot turn a protected session into an
  unmonitored session.
- The protected identity cannot read the approval verifier secret or modify the
  effective policy and audit store.
- A scoped maintenance lease allows only its named roots and operation classes,
  expires automatically, is revoked by daemon restart, and never disables
  monitoring or audit.
- Harmless interactive and deployment commands preserve exit status and usable
  terminal behavior.
- Package install, enable, disable, upgrade, rollback, and uninstall paths are
  tested without deleting audit or enrollment data.
- Filesystem ancestry checks fail closed if a target exceeds the kernel
  backend's bounded ancestor walk; the supported limit is documented and
  verified on every supported kernel.
- Linux is not declared complete until these gates pass on a packaged system.
- Windows Server is not declared complete until equivalent native integration
  tests pass on a supported Windows Server host.
