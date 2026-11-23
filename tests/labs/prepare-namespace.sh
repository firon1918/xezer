#!/usr/bin/env bash
# CodeRabbit-generated: extract the same pinned image without starting a container.
set -euo pipefail
lab_root="${1:?Usage: prepare-namespace.sh ROOTFS_DIRECTORY}"
image='bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d'
if [ -e "$lab_root" ]; then
  echo 'Choose a new empty rootfs destination; existing data will not be replaced.' >&2
  exit 1
fi
docker pull "$image"
lab_container="$(docker create --network none "$image")"
trap 'docker rm "$lab_container" >/dev/null' EXIT
mkdir -p "$lab_root"
docker export "$lab_container" | tar --no-same-owner -xf - -C "$lab_root"
printf '%s\n' "$image" > "$lab_root/.xezer-image"
echo "Extracted pinned Juice Shop image to $lab_root"
