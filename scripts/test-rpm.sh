#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

version="${1:?usage: scripts/test-rpm.sh VERSION [PACKAGE_ROOT]}"
repository_path="${2:-dist/rpm/$(rpm --eval '%{_target_cpu}')}"
repository_path="$(realpath -m "$repository_path")"
case "$repository_path" in
  "$repository_root/dist"/*) ;;
  *)
    echo "package root must be below dist" >&2
    exit 1
    ;;
esac
package="$(find "$repository_path/Packages" -maxdepth 1 -type f -name "osmanthus-${version}-*.rpm" -print -quit)"

if [[ -z "$package" ]]; then
  echo "Osmanthus RPM is missing" >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
install_root="$temporary/root"
mkdir -p "$install_root/var/lib/rpm"
rpm --root "$install_root" --dbpath /var/lib/rpm --initdb
rpm --checksig "$package"
rpm --root "$install_root" --dbpath /var/lib/rpm --nodeps --noscripts -i "$package"

test -x "$install_root/usr/bin/osmanthus"
test -x "$install_root/usr/bin/osmanthusd"
test -x "$install_root/usr/bin/osmanthus-shell"
test -s "$install_root/usr/lib/systemd/system/osmanthusd.service"
test -s "$install_root/etc/logrotate.d/osmanthus"
test -s "$install_root/usr/share/doc/osmanthus/ssm.md"
test -s "$install_root/usr/share/osmanthus/ssm/osmanthus-session.json"
"$install_root/usr/bin/osmanthus" --version | grep -Fx "osmanthus $version"
"$install_root/usr/bin/osmanthus" daemon --help | grep -F "decommission"
"$install_root/usr/bin/osmanthus" maintenance --help | grep -F "grant"
"$install_root/usr/bin/osmanthus" maintenance --help | grep -F "pause"
"$install_root/usr/bin/osmanthus" policy maintenance set --help | grep -F -- "--maximum"
"$install_root/usr/bin/osmanthus" policy protect add --help | grep -F "write"
"$install_root/usr/bin/osmanthus" policy auth --help | grep -F "rotate"
"$install_root/usr/bin/osmanthus" check -- rm -rf /example >/dev/null 2>&1 && exit 1 || status=$?
if [[ "$status" -ne 77 ]]; then
  echo "blocked command check returned unexpected status: $status" >&2
  exit 1
fi

mkdir -p "$install_root/var/lib/osmanthus"
touch "$install_root/var/lib/osmanthus/retention-marker"
mkdir -p "$install_root/etc/osmanthus"
touch "$install_root/etc/osmanthus/retention-marker"
rpm --root "$install_root" --dbpath /var/lib/rpm --nodeps --noscripts -e osmanthus
test -e "$install_root/var/lib/osmanthus/retention-marker"
test -e "$install_root/etc/osmanthus/retention-marker"
test ! -e "$install_root/usr/bin/osmanthus"
test ! -e "$install_root/usr/bin/osmanthusd"
test ! -e "$install_root/usr/bin/osmanthus-shell"
test ! -e "$install_root/usr/share/osmanthus/ssm/osmanthus-session.json"
