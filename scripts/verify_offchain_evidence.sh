#!/usr/bin/env bash
# Compute SHA-256 over the exact bytes of an off-chain file and optionally
# compare it with the digest stored in an on-chain EvidenceReference.
set -euo pipefail

FILE_PATH="${1:?usage: verify_offchain_evidence.sh <file> [expected-sha256]}"
EXPECTED="${2:-}"

if [[ ! -f "$FILE_PATH" ]]; then
  echo "file not found: $FILE_PATH" >&2
  exit 2
fi

if command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$FILE_PATH" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$FILE_PATH" | awk '{print $1}')"
else
  echo "neither shasum nor sha256sum is available" >&2
  exit 2
fi

echo "sha256=$ACTUAL"
if [[ -z "$EXPECTED" ]]; then
  exit 0
fi
if [[ ! "$EXPECTED" =~ ^[0-9a-f]{64}$ ]]; then
  echo "expected digest must be 64 lowercase hexadecimal characters" >&2
  exit 2
fi
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "MISMATCH: the file bytes differ from the anchored evidence" >&2
  exit 1
fi
echo "MATCH: the file bytes match the anchored evidence"
