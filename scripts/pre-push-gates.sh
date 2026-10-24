#!/usr/bin/env bash
# Repository safety suite for csoai-skill-gspc-verify.
# Runs the skill's own controls against the live verifier before any push.
# Exit 0 only when the intact fixture verifies and the tampered fixture is rejected.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
python3 scripts/verify.py fixtures/card-valid.json >/tmp/gspc-verify-valid.out 2>&1
code=$?
if [ "$code" -ne 0 ]; then
  echo "pre-push: valid fixture did not verify (exit $code)"
  sed -n '1,12p' /tmp/gspc-verify-valid.out
  fail=1
else
  echo "pre-push: valid fixture VERIFIED"
fi

python3 scripts/verify.py fixtures/card-tampered.json >/tmp/gspc-verify-tampered.out 2>&1
code=$?
if [ "$code" -ne 2 ]; then
  echo "pre-push: tampered fixture was not rejected as INVALID (exit $code)"
  sed -n '1,12p' /tmp/gspc-verify-tampered.out
  fail=1
else
  echo "pre-push: tampered fixture REJECTED as INVALID"
fi

exit "$fail"
