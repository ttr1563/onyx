# AWS Systems Manager Session Manager

Session Manager starts `sh` by default on Linux and does not have to enter
through the account's login shell. Protected-root enforcement remains active
at the kernel boundary, but a default SSM session does not produce the Osmanthus PTY
transcript.

Use `ops/ssm/osmanthus-session.json` as a custom Session document. Its Linux shell
profile replaces the default shell process with `/usr/bin/osmanthus-shell`. The
template intentionally keeps S3 and CloudWatch streaming disabled; Osmanthus writes
its local JSONL evidence independently.

## Prerequisites

1. Install and start the packaged `osmanthusd` service.
2. Determine the UID and real shell of the identity used by Session Manager.
3. Enroll that non-root UID with its current real shell:

   ```bash
   id ssm-user
   getent passwd ssm-user
   sudo osmanthus policy monitor add "$(id -u ssm-user)" --shell /bin/bash
   ```

   Replace `ssm-user` and `/bin/bash` with the actual account and current shell.
   The real shell must be a root-owned executable file and must not be
   group/world writable.
   The command records the original shell and changes the account login shell to
   `/usr/bin/osmanthus-shell`.

4. Confirm that a console or recovery path remains available before changing a
   remote entry point.

## Create and use the document

Creating the AWS document changes external account state and is not performed
by package installation. Review the template, then create a Session document
with a repository- and environment-specific name:

```bash
aws ssm create-document \
  --name OsmanthusSessionShell \
  --document-type Session \
  --document-format JSON \
  --content file://ops/ssm/osmanthus-session.json

aws ssm start-session \
  --target INSTANCE_ID \
  --document-name OsmanthusSessionShell
```

Restrict each operator's IAM `ssm:StartSession` permission to this document and
the intended managed instances. Deny operators `ssm:UpdateDocument` and
`ssm:DeleteDocument` for it. Otherwise an operator can select or alter a
Session document that does not start `osmanthus-shell`.

The AWS account administrator must also decide whether Session Manager's own
S3 or CloudWatch logging is required. Those settings are separate from Osmanthus's
local `/var/log/osmanthus/audit.jsonl` evidence.

## Verify

Start a new session through the custom document and run:

```bash
printf '%s\n' "$SHELL"
ps -o pid,ppid,user,args -p $$ -p "$PPID"
sudo tail -n 20 /var/log/osmanthus/audit.jsonl
```

Confirm a session start, input/output records, and a session end after logout.
Then test a disposable file both inside and outside a protected root. Do not use
production data for the first test.

AWS references:

- [Configurable shell profiles](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-shell-config.html)
- [Session document schema](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-schema.html)

## Remove the integration

First restore the managed account's original shell:

```bash
sudo osmanthus policy monitor remove "$(id -u ssm-user)"
```

Only then remove or stop authorizing the custom AWS document. AWS IAM and
document changes are external operations and are not rolled back by the Osmanthus
package manager.
