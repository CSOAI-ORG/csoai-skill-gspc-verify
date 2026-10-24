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
    args = [a for a in sys.argv[1:] if not a.startswith("--log=")]
    log = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--log=")), None)
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
    return 0 if state == "VALID" else (2 if state == "INVALID" else 3)


if __name__ == "__main__":
    sys.exit(main())
