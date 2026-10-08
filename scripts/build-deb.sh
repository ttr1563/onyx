#!/usr/bin/env bash
set -euo pipefail
umask 022

version="${1:?usage: scripts/build-deb.sh VERSION [OUTPUT_ROOT]}"
output_root="${2:-dist/deb}"
repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
output_root="$(realpath -m "$output_root")"
case "$output_root" in
  "$repository_root/docs/apt/pool/main/o/osmanthus" | "$repository_root/dist"/*) ;;
  *)
    echo "output root must be docs/apt/pool/main/o/osmanthus or a path below dist" >&2
    exit 1
    ;;
esac

manifest_version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
if [[ "$version" != "$manifest_version" ]]; then
  echo "version $version does not match Cargo.toml $manifest_version" >&2
  exit 1
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must use MAJOR.MINOR.PATCH format" >&2
  exit 1
fi
for command in ar awk cargo du find gzip install md5sum realpath sort tar uname xargs; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "the Debian package must be built natively on Linux" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64) deb_architecture="amd64" ;;
  aarch64) deb_architecture="arm64" ;;
  *)
    echo "unsupported Debian package architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
package_root="$temporary/package"
mkdir -p \
  "$package_root/etc/logrotate.d" \
  "$package_root/usr/bin" \
  "$package_root/usr/share/doc/osmanthus" \
  "$package_root/usr/share/osmanthus/ssm" \
  "$package_root/lib/systemd/system"

cargo build --release --locked
install -m0755 target/release/osmanthus "$package_root/usr/bin/osmanthus"
install -m0755 target/release/osmanthusd "$package_root/usr/bin/osmanthusd"
install -m0755 target/release/osmanthus-shell "$package_root/usr/bin/osmanthus-shell"
install -m0644 ops/logrotate/osmanthus "$package_root/etc/logrotate.d/osmanthus"
install -m0644 ops/systemd/osmanthusd.service "$package_root/lib/systemd/system/osmanthusd.service"
install -m0644 LICENSE "$package_root/usr/share/doc/osmanthus/copyright"
gzip -9 -n -c README.md > "$package_root/usr/share/doc/osmanthus/README.md.gz"
gzip -9 -n -c docs/operations.md > "$package_root/usr/share/doc/osmanthus/operations.md.gz"
gzip -9 -n -c docs/ssm.md > "$package_root/usr/share/doc/osmanthus/ssm.md.gz"
chmod 0644 "$package_root/usr/share/doc/osmanthus/README.md.gz" \
  "$package_root/usr/share/doc/osmanthus/operations.md.gz" \
  "$package_root/usr/share/doc/osmanthus/ssm.md.gz"
install -m0644 ops/ssm/osmanthus-session.json \
  "$package_root/usr/share/osmanthus/ssm/osmanthus-session.json"

installed_size="$(du -sk --apparent-size "$package_root" | awk '{ print $1 }')"
cat > "$temporary/control" <<EOF
Package: osmanthus
Version: ${version}-1
Architecture: $deb_architecture
Maintainer: Osmanthus maintainers <ttr1563@users.noreply.github.com>
Installed-Size: ${installed_size}
Depends: libc6 (>= 2.34), libelf1, libgcc-s1, passwd, zlib1g
Conflicts: onyx
Section: admin
Priority: optional
Homepage: https://ttr1563.github.io/osmanthus-shell/
Description: lightweight command guard for Linux servers
 Osmanthus uses a privileged daemon and Linux BPF LSM hooks to deny configured
 destructive filesystem operations below protected roots. Scoped maintenance
 leases require TOTP approval, and audit records are written as local JSONL.
EOF
printf '/etc/logrotate.d/osmanthus\n' > "$temporary/conffiles"
cat > "$temporary/preinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = install ]; then
  if [ -e /sys/fs/bpf/onyx ]; then
    echo "osmanthus: legacy Onyx BPF pins remain; decommission Onyx before installation" >&2
    exit 1
  fi
  if getent passwd | awk -F: '$7 == "/usr/bin/onyx-shell" { found=1 } END { exit !found }'; then
    echo "osmanthus: restore accounts that still use /usr/bin/onyx-shell before installation" >&2
    exit 1
  fi
fi
exit 0
EOF
cat > "$temporary/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl is-active --quiet osmanthusd.service; then
    systemctl try-restart osmanthusd.service
  fi
fi
exit 0
EOF
cat > "$temporary/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
  if [ -e /sys/fs/bpf/osmanthus ]; then
    echo "osmanthus: run 'sudo osmanthus daemon decommission' before uninstall" >&2
    exit 1
  fi
  if getent passwd | awk -F: '$7 == "/usr/bin/osmanthus-shell" { found=1 } END { exit !found }'; then
    echo "osmanthus: restore monitored login shells before uninstall" >&2
    exit 1
  fi
fi
exit 0
EOF
cat > "$temporary/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$temporary/preinst" "$temporary/postinst" "$temporary/prerm" "$temporary/postrm"
(
  cd "$package_root"
  find . -type f -printf '%P\0' | sort -z | xargs -0 md5sum
) > "$temporary/md5sums"
printf '2.0\n' > "$temporary/debian-binary"

source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
tar \
  --sort=name \
  --owner=0 --group=0 --numeric-owner \
  --mtime="@${source_date_epoch}" \
  -C "$temporary" \
  -czf "$temporary/control.tar.gz" control conffiles md5sums preinst postinst prerm postrm
tar \
  --sort=name \
  --owner=0 --group=0 --numeric-owner \
  --mtime="@${source_date_epoch}" \
  -C "$package_root" \
  -czf "$temporary/data.tar.gz" .

mkdir -p "$output_root"
package="$output_root/osmanthus_${version}-1_${deb_architecture}.deb"
rm -f "$package"
(
  cd "$temporary"
  ar rcsD "$package" debian-binary control.tar.gz data.tar.gz
)

ar t "$package"
sha256sum "$package"
