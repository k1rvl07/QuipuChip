#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# Build pm-core and run host tests
cargo test -p pm-core --features test-utils >/dev/null
echo "kdbx compat: host tests ok"
