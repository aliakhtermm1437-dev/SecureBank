#!/usr/bin/env bash
# SecureBank memory-safety drill — fires each payload against the
# binary `BIN` (default ./vuln).  Re-run with BIN=./hardened to see
# the mitigations refuse / abort safely.

set -u
BIN="${BIN:-./vuln}"
echo "=== target: $BIN ==="

step() { echo; echo "--- $* ---"; }
ok()   { echo "  result: $?"; }

step "1. Stack buffer overflow (300 'A's into 16-byte buffer)"
"$BIN" bof "$(printf 'A%.0s' {1..300})"; ok

step "2. Format-string read (%x %x %x %x %s)"
"$BIN" fmt '%x %x %x %x %s'; ok

step "3. Integer overflow (count=1073741825 → wraps on 32-bit)"
"$BIN" int 1073741825; ok

step "4. Use-after-free read"
"$BIN" uaf 0; ok

echo
echo "=== drill complete ==="
