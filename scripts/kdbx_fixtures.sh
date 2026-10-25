#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/tests/kdbx/fixtures"
mkdir -p "$FIX"
if ! command -v keepassxc-cli >/dev/null 2>&1; then
    echo "keepassxc-cli not found" >&2
    exit 1
fi
DB="$FIX/sample.kdbx"
KF="$FIX/sample.key"
PW="test-password-12345"
rm -f "$DB" "$KF"
dd if=/dev/urandom of="$KF" bs=32 count=1 status=none
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create --set-key-file "$KF" "$DB" >/dev/null 2>&1 || true
echo "ok"
