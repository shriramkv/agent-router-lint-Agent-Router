# agent-router-lint

[![ci](https://github.com/shriramkv/agent-router-lint-Agent-Router/actions/workflows/ci.yml/badge.svg)](https://github.com/shriramkv/agent-router-lint-Agent-Router/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![deps](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

A cross-resource security and reliability linter for **[Agent Router](https://aaif.io/projects/agent-router)** manifests (the AAIF project formerly known as Envoy AI Gateway).

Agent Router is configured through Kubernetes resources: `AIGatewayRoute`, `AIServiceBackend`, `BackendSecurityPolicy` and `MCPRoute`, which in turn point at Envoy Gateway `Backend`, `BackendTLSPolicy` and `BackendTrafficPolicy` objects and at `Secret`s. The CRD schema validates each object on its own. Most real mistakes, though, live **between** objects:

- a route that points at a backend name with a typo
- a provider backend that reaches `api.openai.com` with no `BackendSecurityPolicy`, so the key ends up in agent code
- a gateway that captures token usage but never rate-limits it, so a runaway agent loop can spend without limit
- an `MCPRoute` that exposes every upstream tool to unauthenticated clients
- a real API key committed inside a `Secret` manifest

`agent-router-lint` loads a whole manifest set, indexes every object, and checks the wiring. It runs anywhere Python runs, has **zero dependencies**, and gives you an A-F grade you can gate CI on.

## Quick start

```bash
pip install git+https://github.com/shriramkv/agent-router-lint
agent-router-lint --demo bad          # see it catch 17 planted faults
agent-router-lint --demo good         # a hardened setup, grade A

agent-router-lint deploy/ai-gateway/                 # a directory
kustomize build overlays/prod | agent-router-lint -  # rendered output from stdin
helm template my-release ./chart | agent-router-lint - --min-grade B
```

No install needed for a quick try: `python -m agent_router_lint --demo bad`.

## Sample output

```
agent-router-lint  demo:bad

  [CRITICAL] secret-hardcoded                   Secret/agents/bedrock-key
             Key 'apiKey' contains what looks like a real aws-access-key committed to the manifest.
             fix: Rotate the credential now, remove it from git history, and inject it at deploy time ...
  [HIGH    ] backend-unauthenticated-external   AIServiceBackend/agents/openai
             AIServiceBackend talks to external api.openai.com but no BackendSecurityPolicy targets it ...
  [HIGH    ] route-dangling-backend             AIGatewayRoute/agents/chat
             rules[1] references AIServiceBackend agents/openai-typo which is not defined.
  [MEDIUM  ] route-no-rate-limit                AIGatewayRoute/agents/chat
             Gateway ai-gateway has no BackendTrafficPolicy rateLimit; a runaway agent loop can spend without limit.
  ...
  Grade F  score 0/100  critical=1  high=9  medium=4  low=5
```

Against the upstream project's own examples, the token-rate-limit example (the hardened one) grades **A**, while the minimal OpenAI quick-start grades **D** because it has no token accounting, rate limit, fallback or timeouts. That is the intended reading: quick-starts are for getting going, the linter tells you what to add before production.

## Rules

Run `agent-router-lint --list-rules` for the live catalogue.

| Severity | Rule | What it catches |
|---|---|---|
| critical | `secret-hardcoded` | `Secret` (stringData or base64 data) holds a real-looking OpenAI, Anthropic, AWS, GitHub, Google or Slack credential, or a private key |
| critical | `bsp-inline-credential` | a credential written inline in a `BackendSecurityPolicy` |
| high | `backend-unauthenticated-external` | `AIServiceBackend` reaches an external host with no `BackendSecurityPolicy` targeting it |
| high | `backend-plaintext-external` | external provider on port 80 or a non-TLS port |
| high | `backend-missing-schema` / `backend-unknown-schema` | `spec.schema.name` missing or not one of the supported schemas |
| high | `backend-missing-backendref` | `AIServiceBackend` with nowhere to send traffic |
| high | `bsp-unknown-type` / `bsp-type-mismatch` | policy `type` does not match the credential field that is set (mirrors the CRD's CEL rules, caught before `kubectl apply`) |
| high | `route-dangling-backend` | `AIGatewayRoute` backendRef to an `AIServiceBackend` that does not exist |
| high | `route-no-rules` / `route-rule-no-backend` | empty routes or rules |
| high | `route-cost-type-invalid` / `route-cost-cel-missing` | bad `llmRequestCosts` entries |
| high | `mcp-route-unauthenticated` | `MCPRoute` without a client `securityPolicy` |
| high | `mcp-backend-dangling` | `MCPRoute` backendRef to a missing `Backend` |
| medium | `backend-no-tls-validation` | external backend with no `BackendTLSPolicy` (or `Backend.spec.tls`) |
| medium | `backend-dangling-backendref`, `bsp-dangling-target`, `bsp-dangling-secret`, `bsp-no-target` | broken references around backends and policies |
| medium | `route-no-parent` | route not attached to any `Gateway` |
| medium | `route-duplicate-model` | two rules match the same `x-ai-eg-model` on one Gateway, so one silently shadows the other |
| medium | `route-no-token-accounting` | no `llmRequestCosts`, so per-tenant quotas and cost attribution are impossible |
| medium | `route-no-rate-limit` | parent Gateway has no `BackendTrafficPolicy` rate limit (denial of wallet) |
| medium | `route-cost-no-key` | cost entry without a `metadataKey` that rate limits could read |
| medium | `mcp-oauth-plaintext-issuer` / `mcp-oauth-no-jwks` | weak MCP OAuth configuration |
| medium | `mcp-backend-external-no-credentials` | external MCP upstream with no per-backend `securityPolicy` |
| low | `route-rate-limit-not-token-based` | rate limit counts requests, not tokens |
| low | `route-no-fallback` | every rule has a single backend (no provider failover) |
| low | `route-no-request-timeout` | rule without `timeouts.request` |
| low | `mcp-backend-no-tool-selector` | MCP upstream exposes its full tool surface |
| low | `secret-placeholder` | `Secret` still holds a placeholder such as `OPENAI_API_KEY` |
| low | `deprecated-api-version` | `aigateway.envoyproxy.io/v1alpha1` instead of `v1beta1` |

In-cluster hosts (`*.svc.cluster.local`, single-label names, private and loopback IPs) are treated as internal, so self-hosted vLLM or test upstreams do not trigger the external-provider rules. Policies only count when they are in the same namespace as their target, matching how Kubernetes resolves `targetRefs`.

## Grading

Each distinct rule costs its severity penalty once (critical 40, high 20, medium 10, low 3). Repeats of the same rule add 25% each, capped at 2x, so one systemic gap in a 300-object manifest set does not drown everything else. Any critical finding caps the grade at **D**.

| Grade | Score |
|---|---|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | below 60 |

## CI usage

```yaml
- name: Lint Agent Router config
  run: |
    pip install git+https://github.com/shriramkv/agent-router-lint
    kustomize build deploy/overlays/prod | agent-router-lint - --min-grade B --fail-on critical
```

Exit codes: `0` passed, `1` a gate failed, `2` input could not be read or parsed.

Output formats (`-f`): `console` (default), `json`, `markdown` (paste into a PR comment), `badge` (shields.io URL), `badge-endpoint` (shields.io endpoint JSON).

Other options: `--disable RULE` (repeatable), `--builtin-yaml` (force the zero-dependency loader even if PyYAML is installed), `--list-rules`.

## Design notes

- **Zero dependencies.** A small built-in loader handles the block-YAML subset Kubernetes manifests use (multi-document streams, compact sequences, flow collections, block scalars). It produces output identical to PyYAML on all 39 example manifests in the upstream repository, and the test suite cross-checks it against PyYAML on the bundled samples. If PyYAML is installed it is used automatically.
- **Static only.** Nothing talks to a cluster. Run it on rendered output (`kustomize build`, `helm template`) to lint what will actually be applied.
- **Schema-aware.** API schemas, `BackendSecurityPolicy` types and `llmRequestCosts` types follow the `v1beta1` API in the upstream repository.

## Where it fits in the AAIF toolchain

Agent Router and [agentgateway](https://aaif.io) are both AAIF traffic-layer projects. This repo is the Agent Router counterpart to [agentgateway-lint](https://github.com/shriramkv/agentgateway-lint) and [agentgateway-diff](https://github.com/shriramkv/agentgateway-diff), and the MCP-route checks complement the MCP server tooling in [aaif-agentic-toolkit](https://github.com/shriramkv/aaif-agentic-toolkit).

## Development

```bash
python -m unittest discover -s tests -v
```

See [AGENTS.md](AGENTS.md) for conventions when contributing with a coding agent.

## License

MIT
