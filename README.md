# csoai-verify — portable verification skill

An Agent Skill that verifies a CSOAI signed card or signed evidence record by calling the public verifier at
`https://councilof.ai/api/verify`. The script performs the check; the model only reports the result.

**Never** let a language model decide that a signature “looks valid”. That is the whole point of this skill.

## What it returns

The service's own vocabulary, verbatim: `state` (`VALID`, `INVALID`, `UNCHECKABLE`, `WITHDRAWN`),
`cryptographic_state`, `status`, and reason codes such as `preimage_mismatch`, `signature_invalid`.
A failed signature is reported as a failure, never softened; an uncheckable artifact is reported as uncheckable.

## Use

```bash
python3 scripts/verify.py <card-url-or-file>
```

Exit codes: `0` VALID · `2` INVALID · `3` other state · `4` transport/usage error.

## Install

- **Any skills-compatible agent** — copy this directory into the agent's skills folder.
  - Gemini CLI / Antigravity CLI: `~/.gemini/skills/csoai-verify/`
  - Antigravity App/IDE: use the surface's documented skills directory.
- **MCP clients** — no skill needed: register `https://councilof.ai/mcp` (streamable HTTP, no auth) and use the
  GSPC tools directly.
- **DeepSeek Harness** — MCP row `@deepseek-ai/dsh-mcp-client` with `serverName: csoai`,
  `transport: streamable-http`, `url: https://councilof.ai/mcp`.

## Method and limits

- Public GET + `POST /api/verify` only; no accounts, no private material.
- The script records the `sha256` of the bytes it sent, so a result can be reproduced from the same bytes.
- Verification is not certification. A `VALID` result means the signed bytes verify against the pinned key; it
  says nothing about the truth, quality or compliance of the underlying claim.
- One page/one card is a sample; absence is not evidence of absence.

## Evidence events (CC0)

Every run can emit one `csoai.evidence-event/0.1` record — the schema already published in
`packages/evidence-fabric/schema/evidence-event-0.1.schema.json` (CC0-1.0). No new schema, no new fields.

```bash
python3 scripts/verify.py <card> --event=event.json --control=fixtures/card-tampered.json
```

State mapping: `VALID → CONSISTENT`, `INVALID → DIVERGENT`, `UNCHECKABLE → UNCHECKABLE`, `WITHDRAWN → PARTIAL`.
`event_id = "sha256:" + sha256(RFC 8785 JCS(event − event_id, signature, anchors))`, computed exactly as
`event.py::compute_event_id`. The optional `--control` runs a negative control and records its result, so an event
never claims a control that was not run.
