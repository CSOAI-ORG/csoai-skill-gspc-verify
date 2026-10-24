#!/usr/bin/env python3
"""Verify a CSOAI card or signed record by calling the public verifier.

Usage:
  verify.py <url-or-file>

Prints a compact JSON summary and a human line. Exit 0 VALID, 2 INVALID,
3 any other state, 4 transport/usage error. The script never interprets the
signature; it reports the service's vocabulary.
"""
import hashlib
import json
import os
import time
import sys
import urllib.error
import urllib.request

ENDPOINT = "https://councilof.ai/api/verify"
UA = "csoai-verify-skill/0.1"

# State mapping into the CC0 evidence-event schema (csoai.evidence-event/0.1).
EVIDENCE_STATE = {"VALID": "CONSISTENT", "INVALID": "DIVERGENT",
                  "UNCHECKABLE": "UNCHECKABLE", "WITHDRAWN": "PARTIAL"}
EVIDENCE_STATES = set(EVIDENCE_STATE.values())
LIMITS = [
    "One verification establishes signature integrity and status only.",
    "It does not establish truth, quality, completeness or compliance.",
    "A VALID signature over a measurement performed wrongly is a VALID signature over a wrong number.",
]


def jcs(obj):
    """RFC 8785-compatible canonical bytes for the values this script emits."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_event_id(ev):
    body = {k: v for k, v in ev.items() if k not in ("event_id", "signature", "anchors")}
    return "sha256:" + hashlib.sha256(jcs(body)).hexdigest()


def validate_event(ev):
    errs = []
    for k in ("schema", "event_id", "subject", "claim", "method", "declared", "observed",
              "state", "value", "negative_control", "limits"):
        if k not in ev:
            errs.append("missing " + k)
    if ev.get("schema") != "csoai.evidence-event/0.1":
        errs.append("schema must be csoai.evidence-event/0.1")
    if ev.get("state") not in EVIDENCE_STATES:
        errs.append("state outside the schema enum")
    if not isinstance(ev.get("limits"), list) or not ev.get("limits"):
        errs.append("limits must be a non-empty array")
    if ev.get("event_id") != compute_event_id(ev):
        errs.append("event_id does not recompute")
    if not isinstance(ev.get("negative_control", {}).get("got"), str):
        errs.append("negative_control.got must be a string")
    return errs


def load(arg):
    if arg.startswith(("http://", "https://")):
        req = urllib.request.Request(arg, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
        return raw, arg
    with open(os.path.expanduser(arg), "rb") as f:
        return f.read(), os.path.abspath(arg)


def post(raw):
    req = urllib.request.Request(
        ENDPOINT, data=raw, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def append_log(path, record):
    """Append one evidence event. One line per verification, never rewritten."""
    try:
        os.makedirs(os.path.dirname(os.path.expanduser(path)), exist_ok=True)
        with open(os.path.expanduser(path), "a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
    except Exception as e:
        print(json.dumps({"warning": "log_failed", "detail": str(e)}))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    log = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--log=")), None)
    event_path = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--event=")), None)
    control_path = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--control=")), None)
    if len(args) != 1:
        print(json.dumps({"error": "usage: verify.py <url-or-file>"}))
        return 4
    try:
        raw, ref = load(args[0])
    except Exception as e:
        print(json.dumps({"error": "read_failed", "detail": str(e), "ref": args[0]}))
        return 4
    digest = hashlib.sha256(raw).hexdigest()
    try:
        body = json.loads(raw)
    except Exception:
        # not JSON: send as a reference
        body = None
    try:
        if body is None:
            result = post(json.dumps({"card": args[0]}).encode())
        else:
            result = post(raw)
    except urllib.error.HTTPError as e:
        print(json.dumps({"error": "http_" + str(e.code), "detail": e.read()[:300].decode("utf-8", "ignore")}))
        return 4
    except Exception as e:
        print(json.dumps({"error": "transport", "detail": str(e)}))
        return 4

    state = result.get("state")
    out = {
        "ref": ref,
        "sha256_sent": digest,
        "state": state,
        "cryptographic_state": result.get("cryptographic_state"),
        "status": result.get("status"),
        "reasons": result.get("reasons") or ([result["reason"]] if result.get("reason") else []),
        "id": result.get("id"),
        "family": result.get("family"),
        "failed_checks": [c.get("code") for c in result.get("checks", []) if c.get("ok") is False],
        "informational_checks": [c.get("code") for c in result.get("checks", []) if c.get("ok") is None],
    }
    print(json.dumps(out, indent=1))
    print("STATE:", state)
    if log:
        append_log(log, {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "ref": ref, "sha256_sent": digest, "state": out["state"],
                         "cryptographic_state": out["cryptographic_state"],
                         "reasons": out["reasons"]})
    if event_path:
        mapped = EVIDENCE_STATE.get(state)
        if mapped is None:
            print(json.dumps({"error": "state_unmapped", "state": state}))
            return 3
        control_state = "not_run"
        if control_path:
            try:
                craw, _ = load(control_path)
                control_state = (post(craw) or {}).get("state") or "transport_error"
            except Exception:
                control_state = "transport_error"
        ev = {
            "schema": "csoai.evidence-event/0.1",
            "subject": {"kind": "signed_record", "locator": ref,
                        "declared_by": "csoai" if state else None},
            "claim": {"text": "the bytes verify against the pinned key",
                      "source_url": ref if ref.startswith("http") else None,
                      "source_sha256": digest,
                      "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            "method": {"id": "csoai.verify", "version": "0.1", "holder": "csoai",
                       "code_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest()},
            "declared": {"state": state, "cryptographic_state": out["cryptographic_state"],
                         "status": out["status"]},
            "observed": {"state": state, "reasons": out["reasons"],
                         "failed_checks": out["failed_checks"]},
            "state": mapped,
            "value": None,
            "negative_control": {"id": "tampered-fixture", "expected": "INVALID", "got": control_state},
            "limits": LIMITS,
        }
        ev["event_id"] = compute_event_id(ev)
        errs = validate_event(ev)
        if errs:
            print(json.dumps({"error": "invalid_event", "errors": errs}))
            return 5
        os.makedirs(os.path.dirname(os.path.expanduser(event_path)) or ".", exist_ok=True)
        with open(os.path.expanduser(event_path), "w") as f:
            json.dump(ev, f, indent=1, sort_keys=True)
        print("EVENT:", event_path, ev["event_id"], ev["state"])

    return 0 if state == "VALID" else (2 if state == "INVALID" else 3)


if __name__ == "__main__":
    sys.exit(main())
