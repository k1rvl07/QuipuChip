#!/usr/bin/env bash
# Runs every check this repository has, in the order that fails fastest.
#
#   scripts/test_all.sh            # host checks only
#   scripts/test_all.sh --with-kdbx   # also the KeePass compatibility harness
#   scripts/test_all.sh --with-device # also the read-only live-device smoke test
#
# Host checks never touch the device and never touch the vault partition.
# The live-device smoke test is read-only by design: it never provisions,
# unlocks, imports or resets anything.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WITH_KDBX=0
WITH_DEVICE=0
for arg in "$@"; do
    case "$arg" in
        --with-kdbx) WITH_KDBX=1 ;;
        --with-device) WITH_DEVICE=1 ;;
        -h | --help)
            sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

step "cargo fmt --check"
cargo fmt --all --check || fail "cargo fmt"

step "cargo clippy (pm-core, all targets)"
cargo clippy -p pm-core --all-targets --features test-utils -- -D warnings \
    || fail "cargo clippy"

step "cargo test (pm-core)"
cargo test -p pm-core --features test-utils || fail "cargo test"

step "wordlist generator --check"
python3 scripts/wordlist.py --check || fail "wordlist"

if [ "$WITH_KDBX" -eq 1 ]; then
    step "KDBX compatibility harness"
    scripts/kdbx_compat.sh || fail "kdbx compat"
else
    step "KDBX compatibility harness (skipped, pass --with-kdbx)"
fi

if [ "$WITH_DEVICE" -eq 1 ]; then
    step "live device smoke (read-only)"
    python3 tests/live/smoke.py || fail "device smoke"
else
    step "live device smoke (skipped, pass --with-device)"
fi

printf '\n\033[32mall checks passed\033[0m\n'
