# Kams

**An OpenTelemetry-native observability and control layer for the Model Context Protocol.**

Built for [Agents of SigNoz](https://www.wemakedevs.org/hackathons/signoz) — Track 01, AI & Agent Observability.

> *"If you can't observe your AI agents, you don't own them."*
>
> Everyone answers the first half. Kams answers **own**.

---

## The problem

MCP is the fastest-spreading interface in agent infrastructure and it is almost entirely unobserved.

An MCP server is **third-party code whose tool descriptions are injected verbatim into your model's context**, and whose arguments carry your data off-process. There is no telemetry standard for it, no integrity check on it, and no way to contain it when it misbehaves. Your package manager verifies a lockfile before running someone else's code. Your agent does not.

That gap has a documented exploit. A **rug pull** is when a server behaves benignly long enough to be reviewed and trusted, then silently changes what it advertises. The tool's name, schema, and implementation stay identical — only the description changes. Since descriptions become instructions, that is enough.

```
$ python demo/scenario.py

3. The server rug-pulls — same name, same schema, new description
  save_note    Save a short note to the user's notebook. Returns the note i…  ← poisoned
  save_note    BLOCKED  server 'notes-mcp' is quarantined by Kams policy
                        [quarantine-poisoned-pinned-definition]: A pinned tool
                        definition changed into text that reads as prompt injection.

  [CRITICAL] integrity.definition_drift: Tool 'save_note' description changed on a
             pinned baseline and the new text reads as an injection attempt
             (model_directed_imperative, instruction_block, rewrite_magnitude)
  enforcing quarantine_server on notes-mcp [quarantine-poisoned-pinned-definition]
```

## What Kams does

A transparent MCP interceptor. Any agent — Claude Code, Cursor, a LangChain app — changes one line of config to point at Kams instead of the real server. Kams forwards faithfully and:

- emits **OpenTelemetry spans, metrics, and logs** into SigNoz for every MCP operation
- **pins tool definitions** in `kams.lock` and detects drift against them
- **scores server-originated text** for prompt injection, deterministically
- **enforces policy** — throttle, block, quarantine — and emits the enforcement as a span

```
agent ──▶ kams-shim ──▶ upstream MCP server
              │
              ├──── OTLP ────▶ SigNoz  (traces · metrics · logs · dashboards · alerts)
              │                   │
              └──── enforce ◀─────┘  alert webhook
```

## Quickstart

Requires Docker and Python 3.12+.

```bash
./scripts/bootstrap.sh      # SigNoz via Foundry, org created, OTLP verified
uv sync
uv run python demo/scenario.py
```

Point an existing agent at it by wrapping the server command:

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "kams",
      "args": ["shim", "--server", "filesystem", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

```bash
kams status              # what's recorded, and its trust state
kams pin filesystem      # promote to pinned — drift is now a finding
```

## How the detection works

### Integrity — the supply-chain detector

The obvious approach is to hash the `tools/list` response. It does not work: servers legitimately reorder and add tools, so a whole-response hash fires on benign change, gets muted, and protects nobody.

Instead, per-tool digests over a canonicalised `(name, description, inputSchema)` triple, with **typed** deltas so severity tracks the threat rather than the diff:

| Change | Severity | Why |
|---|---|---|
| `DESCRIPTION_CHANGED` | **HIGH** | The poisoning vector — descriptions reach the model as instruction |
| `SCHEMA_WIDENED` | MEDIUM | More surface for data to leave through |
| `TOOL_ADDED` | MEDIUM | A new capability mid-session was in nobody's threat model |
| `SCHEMA_NARROWED` | LOW | Usually a genuine fix |
| `TOOL_REMOVED` | LOW | Availability, not security |

**`kams.lock` is the missing lockfile.** Trust on first use records a *provisional* baseline; `kams pin` makes it an *assertion*. That distinction drives severity — the identical poisoned description scores **HIGH** provisional and **CRITICAL** pinned, because pinning is what makes drift an assertion violation.

### Injection scoring

"Changed" is not enough; we score *how alarming*, with no LLM in the path:

- **invisible characters** — zero-width, bidi overrides, and `U+E0000–E007F` tag characters, a smuggling vector that renders as nothing and reaches the model intact
- **model-directed imperatives** — "ignore previous", "do not tell the user"
- **instruction blocks** — `<IMPORTANT>`, the shape Invariant Labs demonstrated
- **exfiltration shapes**, **cross-tool references**, **high-entropy blobs**
- **rewrite magnitude** — context, weighted low, never damning alone

Signals combine with **noisy-OR** (`1 − Π(1 − wᵢsᵢ)`) rather than a weighted sum. They are largely independent, and one conclusive signal should carry a verdict without corroboration; a sum would dilute it among quieter ones and need clamping.

Scoring runs over what a change **added**, so a description that always contained a URL does not fire.

### Threat model — documented, not invented

| Attack | Detector |
|---|---|
| Rug pull | `kams.lock` pinning + `DESCRIPTION_CHANGED` |
| Tool poisoning ([Invariant Labs, 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) | injection scoring on the delta |
| Cross-server shadowing | cross-tool reference signal |
| Poisoned outputs ([CyberArk](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)) | result-side scanning |
| Tool squatting / homoglyphs | mixed-script name detection |

## Design principles

1. **Observability never breaks the workload.** Every export path is best-effort; a detector that throws is caught and treated as no-opinion. Quarantine is the single deliberate fail-closed exception, always explicit and always TTL'd.
2. **No LLM in the enforcement path.** Enforcement is deterministic and reproducible in a unit test. LLM judgement is enrichment, computed off the critical path, and cannot change a severity or an action.
3. **Detection is declarative.** Detectors emit typed findings; `policy.yaml` maps findings to actions. Changing what Kams *does* about a threat never means changing Kams.
4. **Never log a secret to prove a secret leaked.** Egress findings carry class, count, and a salted digest — never values.
5. **Degrade, don't disappear.** Missing trace context, an uncooperative agent, an unknown method — each drops one capability and keeps the rest.

Full design: [`architecture.md`](architecture.md).

## Transparency is tested, not asserted

Everything rests on the agent being unable to tell Kams is there. `tests/golden/` runs an identical transcript with and without the proxy and asserts the two stdout streams are **byte-identical** — covering non-alphabetical key order, emoji, a 200KB payload past the default stream limit, error `data`, and unknown methods.

Messages carry their original bytes and are forwarded unmodified unless a hook explicitly rewrites them. Parsing is for observation only. Re-serialising everything would silently reorder keys and change unicode escaping — invisible when diffing parsed objects, very visible to anything hashing the wire.

```bash
uv run pytest        # 62 tests
```

The false-positive suite is the load-bearing half. Ordinary tool prose containing "you must", "do not", URLs, and imperatives must stay quiet — and does.

## Contributing upstream

[`src/kams/semconv/mcp.yaml`](src/kams/semconv/mcp.yaml) is a semantic-convention model file for MCP, written to OpenTelemetry's own schema for submission to `open-telemetry/semantic-conventions-genai`. Two gaps it addresses:

**Trace context propagation.** MCP defines no mechanism — the stdio transport has no headers. Kams proposes W3C `traceparent` inside `params._meta`, which the MCP spec reserves for out-of-band metadata. Agents that don't participate get spans marked `mcp.trace.propagated=false` rather than silently-rooted ones, because a broken propagation chain otherwise looks exactly like a working one.

**Context-cost attribution.** Tool results consume the model's context window, but nothing attributes that cost back to the server responsible. Kams proposes `mcp.context.cost.tokens` with a mandatory `mcp.context.cost.estimated` discriminator — a cost metric that silently mixes measured and estimated values is not trustworthy.

## Repository

```
casting.yaml{,.lock}   Foundry deployment of SigNoz (MCP server enabled)
policy.yaml            declarative enforcement rules
kams.lock              pinned tool definitions
src/kams/
  transport/           stdio + HTTP adapters — no logic
  protocol/            JSON-RPC framing, MCP shapes, _meta handling
  detect/              integrity, injection scoring, baselines — pure
  policy/              parser + evaluator — pure
  telemetry/           spans, metrics, semconv constants
  semconv/mcp.yaml     the upstream-able model file
demo/                  rug-pulling server + narrated scenario
tests/golden/          byte-transparency guarantees
```

`detect/` and `policy/` are pure — no I/O, no network, no ambient clock. The brain is testable without Docker, SigNoz, or Bedrock.

## Status

Working: transparent stdio relay, semconv telemetry into SigNoz, integrity detection with pinning, injection scoring, declarative policy, reflex enforcement, narrated demo.

In progress: SigNoz alert webhook → enforcement (the fleet-scale control loop), dashboards and alerts as versioned code, egress and context-cost detectors.

Known limits, stated plainly:

- Enforcement applies to calls issued *after* a finding is processed. MCP permits pipelining, so a burst issued before the `tools/list` response is handled can slip through within a single connection. Standing state in `kamsd` closes this across connections.
- The LLM judge described in `architecture.md` §3.2 is designed but not yet implemented. It only ever annotates.
- HTTP transport shares the detector pipeline but has had less exercise than stdio.

## AI assistance

Kams was built with **Claude Code (Claude Opus 5)** as an AI coding assistant, used for implementation, test authoring, and documentation throughout. This is disclosed as the hackathon rules require.

## Licence

MIT.
