---
name: csoai-verify
description: Verify a CSOAI signed card or signed evidence record without deciding validity yourself. Use when a task needs to know whether a GSPC card, claim receipt or signed evidence record is intact, altered, withdrawn or uncheckable. Calls the public verifier at councilof.ai/api/verify and reports its state vocabulary verbatim.
metadata:
  allowed-tools: Bash
---

# CSOAI verify

Verification is a cryptographic check performed by a service, not a judgement made by a language model.
**Never** decide that a signature "looks valid". Run the script and report its output.

## Procedure

1. Identify the artifact: a card URL, a card file, or a signed evidence record (JSON).
2. Run:

```bash
python3 scripts/verify.py <card-url-or-file>
```

3. Report the returned `state`, `cryptographic_state`, `status`, and `reasons` **verbatim**.
   Do not translate `UNCHECKABLE` into "probably fine", and do not translate `INVALID` into a claim about
   the organisation behind the artifact.
4. Preserve the original artifact reference (URL, sha256 of the bytes you sent) alongside the result.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | `state` is `VALID` |
| 2 | `state` is `INVALID` |
| 3 | `UNCHECKABLE`, `WITHDRAWN`, or any other non-VALID state |
| 4 | transport/usage error (no verdict) |

## What this skill does not do

- It does not certify anything. Measurement is not certification.
- It does not judge quality, truth or compliance of the underlying claim.
- It does not repair or rewrite an artifact; corrections are a separate, appended record.

## Known vocabulary (observed 2026-10-24)

`state`: `VALID` · `INVALID` · `UNCHECKABLE` · `WITHDRAWN`
`cryptographic_state`: `VALID` · `INVALID`
`status`: `LIVE` · `WITHDRAWN`
reason codes observed: `preimage_mismatch`, `signature_invalid`

Treat this list as observed, not exhaustive: report what the verifier returns.
