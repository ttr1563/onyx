#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
output_root="${1:-docs/apt}"
output_root="$(realpath -m "$output_root")"
case "$output_root" in
  "$repository_root/docs/apt" | "$repository_root/dist"/*) ;;
  *)
    echo "output root must be docs/apt or a path below dist" >&2
    exit 1
    ;;
esac

key_file="${ONYX_GPG_PUBLIC_KEY:-packaging/rpm/RPM-GPG-KEY-ONYX}"
signing_key="${ONYX_GPG_KEY_ID:-}"
gpg_home="${ONYX_GPG_HOME:-}"
passphrase_file="${ONYX_GPG_PASSPHRASE_FILE:-}"
for command in ar awk cp date find gzip gpg install md5sum realpath sha256sum sort stat tail tar xargs; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done
if [[ ! -s "$key_file" ]]; then
  echo "public signing key not found: $key_file" >&2
  exit 1
fi
if [[ -z "$signing_key" || -z "$gpg_home" ]]; then
  echo "ONYX_GPG_KEY_ID and ONYX_GPG_HOME are required" >&2
  exit 1
fi

pool="$output_root/pool/main/o/onyx"
package="$(find "$pool" -maxdepth 1 -type f -name 'onyx_[0-9]*_amd64.deb' -print | sort -V | tail -n 1)"
if [[ -z "$package" ]]; then
  echo "Onyx Debian package not found under $pool" >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
metadata_root="$temporary/apt"
binary_dir="$metadata_root/dists/stable/main/binary-amd64"
mkdir -p "$binary_dir"
relative_package="${package#"$output_root"/}"

control_dir="$temporary/control"
mkdir -p "$control_dir"
(
  cd "$control_dir"
  ar x "$package" control.tar.gz
  tar -xzf control.tar.gz control
)
cat "$control_dir/control" > "$binary_dir/Packages"
cat >> "$binary_dir/Packages" <<EOF
Filename: ${relative_package}
Size: $(stat -c %s "$package")
MD5sum: $(md5sum "$package" | awk '{ print $1 }')
SHA256: $(sha256sum "$package" | awk '{ print $1 }')

EOF
gzip -9 -n -c "$binary_dir/Packages" > "$binary_dir/Packages.gz"

release="$metadata_root/dists/stable/Release"
release_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
{
  echo "Origin: Onyx"
  echo "Label: Onyx"
  echo "Suite: stable"
  echo "Codename: stable"
  echo "Version: 1"
  echo "Architectures: amd64"
  echo "Components: main"
  echo "Description: Onyx packages for Debian and Ubuntu"
  echo "Date: $(date --utc --date="@${release_epoch}" --rfc-email)"
  echo "SHA256:"
  for file in main/binary-amd64/Packages main/binary-amd64/Packages.gz; do
    printf ' %s %16s %s\n' \
      "$(sha256sum "$metadata_root/dists/stable/$file" | awk '{ print $1 }')" \
      "$(stat -c %s "$metadata_root/dists/stable/$file")" \
      "$file"
  done
} > "$release"

gpg_arguments=(--batch --yes --local-user "$signing_key" --digest-algo SHA256)
if [[ -n "$passphrase_file" ]]; then
  if [[ ! -r "$passphrase_file" ]]; then
    echo "GPG passphrase file is not readable" >&2
    exit 1
  fi
  gpg_arguments+=(--pinentry-mode loopback --passphrase-file "$passphrase_file")
fi
GNUPGHOME="$gpg_home" gpg "${gpg_arguments[@]}" \
  --clearsign --output "$metadata_root/dists/stable/InRelease" "$release"
GNUPGHOME="$gpg_home" gpg "${gpg_arguments[@]}" \
  --armor --detach-sign --output "$metadata_root/dists/stable/Release.gpg" "$release"

rm -rf "$output_root/dists"
cp -a "$metadata_root/dists" "$output_root/dists"
install -m0644 "$key_file" "$output_root/onyx.asc"
install -m0644 packaging/deb/onyx.sources "$output_root/onyx.sources"

(
  cd "$output_root"
  find dists pool -type f -print | sort | xargs sha256sum > SHA256SUMS
)
GNUPGHOME="$gpg_home" gpg "${gpg_arguments[@]}" \
  --armor --detach-sign --output "$output_root/SHA256SUMS.asc" "$output_root/SHA256SUMS"

sha256sum "$package" "$output_root/dists/stable/InRelease"
