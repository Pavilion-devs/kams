# Kams — Plan

**An OpenTelemetry-native observability and control layer for the Model Context Protocol.**

> *"If you can't observe your AI agents, you don't own them."* — Agents of SigNoz hackathon theme.
> Everyone will answer the first half. Kams answers **"own."**

---

## 1. The thesis

MCP is the fastest-spreading interface in agent infrastructure and it is almost entirely unobserved. An MCP server is **third-party code whose tool descriptions are injected directly into your model's context** and whose arguments carry your data off-process. Today there is no standard telemetry for it, no integrity check on it, and no way to contain it when it misbehaves.

Kams is a transparent MCP interceptor. Any agent — Claude Code, Cursor, a LangChain app, our own demo agent — changes one line of config to point at Kams instead of the real MCP server. Kams forwards faithfully and emits canonical OpenTelemetry GenAI/MCP telemetry into SigNoz, derives behavioural and integrity signals, and closes the loop: SigNoz alerts fire back into Kams, which throttles, blocks, or quarantines the offending server — and that enforcement action is itself a span in the same trace.

**Observe → own.**

### Why this and not the obvious build

The hackathon's own Track 01 examples list *"SRE Sidekick with SigNoz MCP."* SigNoz has already published six blog posts and a full demo repo doing exactly that (a LangChain agent that queries the SigNoz MCP server, traced with OTel, with p95/token/error dashboard panels). A large share of submissions will be that project with a different frontend. It is a commodity submission.

The asymmetry we're exploiting:

> **Every team will use MCP as a client. Almost nobody will observe MCP as infrastructure.**

Writing a protocol proxy is harder than wiring an SDK, and every piece of signposting in this hackathon points entrants the other way. That is the moat.

---

## 2. Hackathon context

| | |
|---|---|
| Event | Agents of SigNoz (WeMakeDevs × SigNoz) |
| Window | Jul 20 – Jul 26, 2026 |
| Track | **01 — AI & Agent Observability** (prize: MacBook Air per member) |
| Prize pool | $20,000 |
| Team | Solo |
| Submission | https://forms.gle/xv1TXSiC54MEWujRA |
| Blog track | Closed Jul 19 — not available to us |
| Side track | Social Buzz (top 10 posts win swag) — cheap, worth a build-in-public thread |

### Hard requirements (rules)

These are pass/fail. Several entrants will miss them.

- [ ] Project uses / integrates with SigNoz — depth across signals scores higher
- [ ] **Repo contains `casting.yaml` AND `casting.yaml.lock`** (Foundry, reproducible deploy)
- [ ] SigNoz installed via **Foundry** (`curl -fsSL https://signoz.io/foundry.sh | bash`, then `foundryctl cast -f casting.yaml`)
- [ ] **AI assistant use declared in the README** — undeclared use = disqualification. We used Claude Code (Claude Opus 5); this will be stated explicitly.
- [ ] No code written before Jul 20 (we are inside the window — clean)
- [ ] Team ≤ 4
- [ ] Submitted via the Google Form before the deadline

### Judging criteria → how Kams maps

| Criterion | Kams' answer |
|---|---|
| **Potential Impact** | Every org adopting MCP has an unmonitored third-party surface injecting text into their models. Real, current, unsolved. |
| **Creativity & Innovation** | Nobody is treating MCP as observable infrastructure. Integrity fingerprinting of tool definitions is novel. |
| **Technical Excellence** | JSON-RPC protocol proxy across stdio + HTTP, semconv-conformant emitter, alert-driven enforcement loop. Systems work, not a wrapper. |
| **Best Use of SigNoz** | All five signals — traces, metrics, logs, dashboards, alerts — with dashboards and alerts **provisioned as code via the SigNoz API**, never hand-clicked. Plus Foundry with `mcp.enabled: true`, plus the SigNoz MCP server observed through Kams itself. |
| **User Experience** | One-line config change to adopt. No SDK, no code change in the agent. |
| **Presentation Quality** | 2.5-minute incident-narrative demo, architecture diagram, dashboards-as-code in the repo. |

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Agent (demo agent on Bedrock / Claude Code / Cursor / any)  │
└───────────────────────────┬──────────────────────────────────┘
                            │  MCP (stdio or streamable HTTP)
                            ▼
              ┌──────────────────────────────────┐
              │            K A M S               │
              │  ── interceptor ──               │
              │   · JSON-RPC passthrough         │
              │   · gen_ai.* + mcp.* span emit   │
              │   · tool-definition fingerprint  │
              │   · argument egress classifier   │
              │   · policy engine (enforce)      │
              └───────┬──────────────────┬───────┘
                      │ forwards         │ OTLP
                      ▼                  ▼
        ┌─────────────────────┐   ┌──────────────────────────┐
        │ Upstream MCP servers│   │        SigNoz            │
        │  · SigNoz MCP       │   │  traces·metrics·logs     │
        │  · filesystem       │   │  dashboards·alerts       │
        │  · a deliberately   │   └───────────┬──────────────┘
        │    misbehaving one  │               │ alert webhook
        └─────────────────────┘               │
                      ▲                       ▼
                      └──────── quarantine ───┘
                        (enforcement emitted as a span
                         in the same trace)
```

### Components

| Component | Responsibility |
|---|---|
| `kams/proxy/stdio.py` | stdio transport interceptor — spawns upstream server, pipes JSON-RPC both ways |
| `kams/proxy/http.py` | streamable-HTTP transport interceptor |
| `kams/telemetry/spans.py` | semconv-conformant span emission for every JSON-RPC method |
| `kams/telemetry/metrics.py` | derived metrics: call rate, latency, error rate, **context cost** (tokens of tool results) |
| `kams/integrity.py` | fingerprints `tools/list` responses; detects mid-session drift |
| `kams/egress.py` | classifies argument payloads for PII/secret patterns; **records counts and classes, never raw values** |
| `kams/policy.py` | enforcement: allow / rate-limit / block-tool / quarantine-server |
| `kams/control/webhook.py` | receives SigNoz alert webhooks → policy state change |
| `provisioning/` | dashboards + alerts as versioned JSON, applied via SigNoz API |
| `casting.yaml` / `.lock` | Foundry deployment of SigNoz with `spec.mcp.spec.enabled: true` |
| `demo/` | agent + scenario driver that produces the incident narrative |

---

## 4. Telemetry specification

This is the core of the "Best Use of SigNoz" and "Technical Excellence" score. Conform where the spec is settled; propose (and document) where it is silent.

### Traces

Conforming to the current OpenTelemetry GenAI semantic conventions (relocated to `open-telemetry/semantic-conventions-genai`; verified Jul 25 2026).

**Agent-side spans** (emitted by the demo agent):

| Span | Name | Key attributes |
|---|---|---|
| Agent invocation | `invoke_agent {gen_ai.agent.name}` | `gen_ai.operation.name`, `gen_ai.provider.name=aws.bedrock`, `gen_ai.agent.name`, `gen_ai.agent.id`, `gen_ai.conversation.id` |
| Inference | `{gen_ai.operation.name} {gen_ai.request.model}` | `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.usage.cache_read.input_tokens`, `gen_ai.response.finish_reasons` |
| Tool execution | `execute_tool {gen_ai.tool.name}` | `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type`, `gen_ai.agent.name` |

**Kams-side spans** (the part nobody else has):

| JSON-RPC method | Span | Attributes |
|---|---|---|
| `initialize` | `mcp.initialize {server}` | server name, protocol version, client info |
| `tools/list` | `mcp.tools/list {server}` | tool count, **fingerprint digest**, drift boolean |
| `tools/call` | `mcp.tools/call {tool}` | tool name, arg byte size, arg class counts, result byte size, **estimated context cost in tokens**, error type |
| `resources/read` | `mcp.resources/read` | uri scheme, size |
| `prompts/get` | `mcp.prompts/get` | prompt name |

Correlation: Kams propagates trace context so MCP spans nest **inside** the agent's `execute_tool` span. `gen_ai.conversation.id` is carried through so you can answer "which conversation caused this MCP traffic."

> **Spec status note (verified Jul 25 2026):** the MCP semantic-convention *docs* page is not yet published (404); the model YAML in `semantic-conventions-genai` is still in flux. Kams ships its own `semconv/mcp.yaml` model file conforming where the spec is settled and documenting proposals where it is not. **This is the upstream-able artifact** and the literal "contribution to the ecosystem."

### Metrics

| Metric | Type | Unit | Why it matters |
|---|---|---|---|
| `mcp.client.operation.duration` | histogram | s | Which MCP server is slow |
| `mcp.tool.call.count` | counter | {call} | Traffic shape per server/tool |
| `mcp.tool.error.count` | counter | {error} | Reliability per third party |
| `mcp.context.cost.tokens` | histogram | {token} | **Novel.** Tool results eat context. Attributes the token burn back to the server that caused it. |
| `mcp.integrity.drift.count` | counter | {event} | Tool definitions changed mid-session |
| `mcp.egress.classified.count` | counter | {field} | Sensitive-class fields crossing into third-party servers |
| `kams.enforcement.count` | counter | {action} | What the control plane did, and why |

### Logs

Structured, correlated by `trace_id`:
- Integrity events (before/after digest of a changed tool definition — description text diffed, never secrets)
- Policy decisions with the rule that fired
- Upstream protocol errors

### Dashboards & alerts (as code)

Versioned JSON in `provisioning/`, applied via the SigNoz API (`signoz_create_dashboard` / `signoz_create_alert` or the REST equivalent). Never hand-clicked — this is a deliberate scoring signal.

Dashboard panels:
1. MCP call volume + p95 latency by server
2. Error rate by server/tool
3. Context cost (tokens) attributed by server — *the panel nobody else will have*
4. Integrity timeline: tool-definition drift events
5. Egress classes by destination server
6. Enforcement actions over time

Alerts:
- Tool-definition drift detected → **fires the control loop**
- MCP error rate > threshold for a server
- Context cost per conversation exceeds budget
- Sensitive-class egress to a non-allowlisted server

---

## 5. Stack decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | **Python 3.12** | Already installed; mature MCP SDK |
| LLM | **Claude on Amazon Bedrock**, `us-east-1` | User has a Bedrock bearer token (`AMAZON_BEDROCK_API_KEY`) |
| Auth | Bearer token via `AWS_BEARER_TOKEN_BEDROCK` | **Verified working** against control plane and data plane |
| Client | **boto3 `bedrock-runtime.converse`** | **Verified:** `AnthropicBedrockMantle` does not work with this credential — 403 on gated models, 404 (`model does not exist`) on the ones we can reach |
| Model ID | **`us.anthropic.claude-sonnet-4-6`** | **Verified working.** Haiku 4.5 also works as a cheap fallback |
| Agent loop | Hand-rolled Converse tool loop | No `tool_runner`/`anthropic.lib.tools.mcp` on this path — see note below |
| SigNoz | **Self-hosted via Foundry**, Docker Compose flavor, `spec.mcp.spec.enabled: true` | Rules require the Foundry install path and the lock file in the repo |
| Package mgmt | `uv` | Already installed |

### Bedrock feature gaps that constrain the design

Verified against the platform availability matrix — these are **not** available on Bedrock and must not appear in our code:

- ❌ MCP connector (`mcp_servers` param) — **so the agent must run a local MCP client. This forces exactly the architecture we want: our interceptor sits in the path.**
- ❌ Web search / web fetch / code execution server tools
- ❌ Files API, Message Batches, Models API
- ❌ Fast mode, task budgets, automatic prompt caching

Available and used: adaptive thinking, effort, tool use, explicit prompt caching, token counting.

### Model access, verified Jul 25 2026 (us-east-1)

Being listed by `list_foundation_models` does **not** imply access. Probed the data plane directly:

| Model | Status |
|---|---|
| `us.anthropic.claude-sonnet-4-6` | ✅ **working — this is our model** |
| `us.anthropic.claude-haiku-4-5-20251001-v1:0` | ✅ working (cheap fallback for scenario traffic) |
| `us.anthropic.claude-opus-5` | ❌ `AccessDeniedException` — gated, requires an AWS access request |
| `us.anthropic.claude-sonnet-5` | ❌ `AccessDeniedException` |
| `us.anthropic.claude-opus-4-8` | ❌ `AccessDeniedException` |

**Consequence — and it is not a downgrade.** Losing the Anthropic SDK tool runner means we hand-write the Converse agent loop (~80 lines: `stopReason == "tool_use"` → execute → `toolResult` → repeat). That means **we emit every `gen_ai.*` span ourselves, deliberately conformant to the current semconv**, rather than inheriting whatever an auto-instrumentation library happens to produce. For a project whose entire claim is semconv-correct agent telemetry, hand-instrumenting is the more defensible position — and it is a better story in the README.

Requesting Opus 5 access from AWS is worth doing in the background, but it is not on the critical path: Sonnet 4.6 drives the demo perfectly well, and the model is not what is being judged.

### Environment status (checked Jul 25 2026)

| | |
|---|---|
| Python 3.12.3 | ✅ |
| `uv` 0.11.12 | ✅ |
| Node 18.20.8 | ✅ (not needed) |
| Docker | ❌ **installing — required for `foundryctl cast`** |
| Go | ❌ (not needed; staying in Python) |
| AWS Bedrock credentials | ✅ (user-supplied) |

---

## 6. Build phases

> **See `architecture.md` for the detailed design and the dependency-ordered build sequence that supersedes the phase list below.** The phases here remain the coarse project shape; §10 of the architecture doc is the one to build against.

**Phase 0 — Foundation**
Docker up. `foundryctl` installed. `casting.yaml` written with `spec.mcp.spec.enabled: true`. `foundryctl cast` → SigNoz at `localhost:8080`, MCP at `localhost:8000/mcp`. **Commit `casting.yaml` + `casting.yaml.lock` immediately** — the rules requirement, banked early.

**Phase 1 — Interceptor spine**
stdio JSON-RPC proxy that faithfully forwards to an upstream MCP server. Correctness first: an agent must not be able to tell Kams is there. Verify against the SigNoz MCP server and a filesystem server.

**Phase 2 — Telemetry**
Span emission per JSON-RPC method, semconv-conformant. Trace-context propagation so MCP spans nest inside the agent's tool span. Derived metrics. OTLP export into SigNoz. First real traces visible.

**Phase 3 — Intelligence**
Integrity fingerprinting (`tools/list` digest + mid-session drift detection). Egress classification. Context-cost attribution.

**Phase 4 — Control loop**
Policy engine + alert webhook receiver. SigNoz alert → quarantine → enforcement emitted as a span in the same trace.

**Phase 5 — Provisioning & demo**
Dashboards and alerts as code via the SigNoz API. Demo agent on Bedrock. Scenario driver for the incident narrative.

**Phase 6 — Submission**
README (with the **AI-use declaration**), architecture diagram, demo video, semconv YAML + upstream PR draft, submit the form. Build-in-public post for the Social Buzz side track.

Scope-down order if time runs short: Phase 4 degrades to alert-triggered blocking without the rich policy engine; Phase 3 degrades to integrity-only (drop egress classification). **Phases 0–2 are non-negotiable** — they carry the rules compliance and the core claim.

---

## 7. Demo narrative (~2.5 min)

1. An agent works productively across three MCP servers, all traffic flowing through Kams. SigNoz shows clean traces, cost attribution per server, live dashboards.
2. Mid-session, one server **silently changes a tool's description** to smuggle in an instruction.
3. Kams' fingerprint check catches the drift. Integrity log + metric. **SigNoz alert fires.**
4. Alert webhook → Kams quarantines that server. The enforcement decision appears **as a span in the same trace** as the poisoned call.
5. The agent continues, degraded but contained. One trace, start to finish, in the SigNoz waterfall.

Closing beat: point Kams at **SigNoz's own MCP server** and observe SigNoz's MCP inside SigNoz.

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Proxy transparency bugs break the agent | Correctness before telemetry. Golden-transcript test: same JSON-RPC exchange with and without Kams. |
| MCP semconv shifts under us | Ship our own model YAML, document conformance vs. proposal explicitly. Being early is the contribution, not a liability. |
| Bedrock model/region access not enabled | Verify with a one-shot call before building the agent. Falls back to any Claude model available in the account. |
| Reads as a security project, not observability | Frame integrity as **one of four signals** (cost, reliability, integrity, latency). Observability first; security is the payoff. |
| Foundry install friction | Do it first (Phase 0), not last. Lock file committed before anything else. |
| Solo + short window | Phase list is ordered so every cut point still leaves a coherent, rules-compliant submission. |

---

## 9. Open questions

- ~~Exact mechanism that produces `casting.yaml.lock`~~ — **resolved: `foundryctl forge` writes it**, before `cast` runs.
- ~~Which Claude model IDs are enabled~~ — **resolved: `us.anthropic.claude-sonnet-4-6`** (see table above).
- Whether the SigNoz REST API or the SigNoz MCP server is the cleaner path for dashboard provisioning — try MCP first (better story), fall back to REST.
- Whether Sonnet 4.6 adaptive thinking is reachable through Converse's `additionalModelRequestFields` — verify when building the agent; not load-bearing if it isn't.

---

## 10. Declarations

Kams was built with **Claude Code (Claude Opus 5)** as an AI coding assistant. This is disclosed here and will be stated explicitly in the submission README, as required by the hackathon rules. Failure to disclose is a disqualifying offence; we are disclosing.

---

*Plan written Jul 25, 2026. Hackathon closes Jul 26, 2026.*
