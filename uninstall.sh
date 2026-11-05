#!/usr/bin/env bash
# Full removal of amnezia-web-panel: container, image, .env and (on request) the directory.
# Amnezia containers and data are NOT touched.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if command -v docker >/dev/null 2>&1; then
  docker compose down --remove-orphans 2>/dev/null && echo "Container stopped and removed." \
    || echo "Container not found (ok)."
  docker rmi amnezia-web-panel:latest >/dev/null 2>&1 && echo "Image removed." \
    || echo "Image not found (ok)."
else
  echo "Docker not found — skipping container and image removal."
fi

read -rp "Remove .env (password hash, server address)? [y/N]: " ANS
case "$ANS" in
  [Yy]*) rm -f .env && echo ".env removed." ;;
  *) echo ".env kept." ;;
esac

read -rp "Remove the project directory $DIR completely? [y/N]: " ANS
case "$ANS" in
  [Yy]*)
    cd /
    rm -rf -- "$DIR"
    echo "Directory $DIR removed."
    ;;
  *)
    echo "Files kept in $DIR"
    ;;
esac

echo "Done. Amnezia services were not affected."
