#!/usr/bin/env bash
# Repository safety suite for csoai-skill-gspc-verify.
# Runs the skill's own controls against the live verifier and checks the emitted
# csoai.evidence-event/0.1 records before any push.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
TMP="${TMPDIR:-/tmp}"

python3 scripts/verify.py fixtures/card-valid.json \
  --event="$TMP/gspc-ev-valid.json" --control=fixtures/card-tampered.json \
  >"$TMP/gspc-verify-valid.out" 2>&1
code=$?
if [ "$code" -ne 0 ]; then
  echo "pre-push: valid fixture did not verify (exit $code)"
  sed -n '1,12p' "$TMP/gspc-verify-valid.out"
  fail=1
else
  echo "pre-push: valid fixture VERIFIED"
fi

python3 scripts/verify.py fixtures/card-tampered.json \
  --event="$TMP/gspc-ev-bad.json" --control=fixtures/card-tampered.json \
  >"$TMP/gspc-verify-tampered.out" 2>&1
code=$?
if [ "$code" -ne 2 ]; then
  echo "pre-push: tampered fixture was not rejected as INVALID (exit $code)"
  sed -n '1,12p' "$TMP/gspc-verify-tampered.out"
  fail=1
else
  echo "pre-push: tampered fixture REJECTED as INVALID"
fi

python3 - "$TMP/gspc-ev-valid.json" "$TMP/gspc-ev-bad.json" <<'PY'
import json, sys
ok = True
valid = json.load(open(sys.argv[1]))
bad = json.load(open(sys.argv[2]))
if valid.get("state") != "CONSISTENT":
    print("pre-push: valid fixture event state is", valid.get("state"), "not CONSISTENT"); ok = False
if valid.get("negative_control", {}).get("got") != "INVALID":
    print("pre-push: negative control did not record INVALID"); ok = False
if bad.get("state") != "DIVERGENT":
    print("pre-push: tampered fixture event state is", bad.get("state"), "not DIVERGENT"); ok = False
for name, ev in (("valid", valid), ("tampered", bad)):
    if not str(ev.get("event_id", "")).startswith("sha256:"):
        print("pre-push:", name, "event has no sha256 event_id"); ok = False
print("pre-push: evidence events", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && fail=1

exit "$fail"
