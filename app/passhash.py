"""Print a PBKDF2 hash of a password read from stdin.

Used by install.sh inside the built image — no Python needed on the host:
    printf '%s' "$PASS" | docker run --rm -i amnezia-web-panel python -m app.passhash
"""
import sys

from .auth import hash_password

if __name__ == "__main__":
    pw = sys.stdin.read().strip()
    if not pw:
        raise SystemExit("usage: printf '%s' PASS | python -m app.passhash")
    print(hash_password(pw))
