#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
repository_path="${1:-docs/apt}"
repository_path="$(realpath -m "$repository_path")"
case "$repository_path" in
  "$repository_root/docs/apt" | "$repository_root/dist"/*) ;;
  *)
    echo "repository path must be docs/apt or a path below dist" >&2
    exit 1
    ;;
esac

command -v docker >/dev/null || {
  echo "required command not found: docker" >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  echo "Docker daemon is not available" >&2
  exit 1
}
test -s "$repository_path/onyx.asc"
test -s "$repository_path/dists/stable/InRelease"

images=(debian:12 ubuntu:22.04)
for image in "${images[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "required local image not found: $image" >&2
    exit 1
  }
  echo "Testing $image"
  docker run --rm \
    --pull=never \
    --network=none \
    --cpus=1 \
    --memory=512m \
    --pids-limit=256 \
    --mount "type=bind,src=$repository_path,dst=/repo,readonly" \
    "$image" \
    bash -euxc '
      install -D -m0644 /repo/onyx.asc /etc/apt/keyrings/onyx.asc
      printf "%s\n" \
        "Types: deb" \
        "URIs: file:/repo" \
        "Suites: stable" \
        "Components: main" \
        "Architectures: amd64" \
        "Signed-By: /etc/apt/keyrings/onyx.asc" \
        > /etc/apt/sources.list.d/onyx.sources
      apt_options=(
        -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/onyx.sources
        -o Dir::Etc::sourceparts=-
        -o APT::Get::List-Cleanup=0
      )
      apt-get "${apt_options[@]}" update
      apt-get "${apt_options[@]}" install -y onyx
      test "$(dpkg-query -W -f=\${Version} onyx)" = "0.1.2-1"
      onyx --version | grep -Fx "onyx 0.1.2"
      state_dir=/tmp/onyx-smoke
      onyx --state-dir "$state_dir" init --no-qr --account package-smoke >/dev/null
      onyx --state-dir "$state_dir" run -- /bin/true
      set +e
      onyx check -- rm -rf /example
      status=$?
      set -e
      test "$status" -eq 77
      install -d -m0700 /var/lib/onyx
      touch /var/lib/onyx/retain-after-package-removal
      install -d -m0755 /etc/onyx
      touch /etc/onyx/retain-after-package-removal
      apt-get "${apt_options[@]}" purge -y onyx
      test -e /var/lib/onyx/retain-after-package-removal
      test -e /etc/onyx/retain-after-package-removal
      test ! -e /usr/bin/onyx
    '
done
