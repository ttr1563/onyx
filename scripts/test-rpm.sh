#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

version="${1:?usage: scripts/test-rpm.sh VERSION [REPOSITORY_PATH]}"
repository_path="${2:-docs/rpm/al2023/$(rpm --eval '%{_target_cpu}')}"
key_file="docs/rpm/RPM-GPG-KEY-ONYX"
package="$(find "$repository_path/Packages" -maxdepth 1 -type f -name "onyx-${version}-*.rpm" -print -quit)"
release_package="$(find "$repository_path/Packages" -maxdepth 1 -type f -name 'onyx-release-*.rpm' -print -quit)"

if [[ -z "$package" || -z "$release_package" || ! -s "$key_file" ]]; then
  echo "repository packages or signing key are missing" >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
install_root="$temporary/root"
mkdir -p "$install_root/var/lib/rpm"
rpm --root "$install_root" --dbpath /var/lib/rpm --initdb
rpm --root "$install_root" --dbpath /var/lib/rpm --import "$key_file"
rpm --root "$install_root" --dbpath /var/lib/rpm --checksig "$release_package" "$package"
rpm --root "$install_root" --dbpath /var/lib/rpm --nodeps -i "$release_package" "$package"

test -x "$install_root/usr/bin/onyx"
test -s "$install_root/etc/yum.repos.d/onyx.repo"
test -s "$install_root/etc/pki/rpm-gpg/RPM-GPG-KEY-ONYX"
test -s "$install_root/etc/logrotate.d/onyx"
"$install_root/usr/bin/onyx" --version | grep -Fx "onyx $version"
"$install_root/usr/bin/onyx" check -- rm -rf /example >/dev/null 2>&1 && exit 1 || status=$?
if [[ "$status" -ne 77 ]]; then
  echo "blocked command check returned unexpected status: $status" >&2
  exit 1
fi

mkdir -p "$install_root/var/lib/onyx"
touch "$install_root/var/lib/onyx/retention-marker"
mkdir -p "$install_root/etc/onyx"
touch "$install_root/etc/onyx/retention-marker"
rpm --root "$install_root" --dbpath /var/lib/rpm --nodeps -e onyx onyx-release
test -e "$install_root/var/lib/onyx/retention-marker"
test -e "$install_root/etc/onyx/retention-marker"
test ! -e "$install_root/usr/bin/onyx"
test ! -e "$install_root/etc/yum.repos.d/onyx.repo"
