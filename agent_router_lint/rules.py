"""Cross-resource lint rules for Agent Router (formerly Envoy AI Gateway) manifests.

Agent Router is configured with Kubernetes resources in the
``aigateway.envoyproxy.io`` API group (AIGatewayRoute, AIServiceBackend,
BackendSecurityPolicy, MCPRoute) that point at Envoy Gateway resources
(Gateway, Backend, BackendTLSPolicy, BackendTrafficPolicy) and Secrets.
Most mistakes live in the *references between* those objects, which a
per-object schema check cannot see. This module builds an index of every
object in the scanned set and checks the wiring.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from .report import Finding

AI_GROUP = "aigateway.envoyproxy.io"
CURRENT_AI_VERSION = "v1beta1"
AI_KINDS = {"AIGatewayRoute", "AIServiceBackend", "BackendSecurityPolicy", "MCPRoute", "QuotaPolicy", "GatewayConfig"}

API_SCHEMAS = {
    "OpenAI", "Cohere", "AWSBedrock", "AzureOpenAI", "GCPVertexAI", "GCPAnthropic",
    "Anthropic", "AWSAnthropic", "AWSOpenAI", "TypeSafe",
}
COST_TYPES = {
    "InputToken", "CachedInputToken", "CacheCreationInputToken", "OutputToken",
    "TotalToken", "ReasoningToken", "CEL",
}
BSP_TYPES = {
    "APIKey": "apiKey",
    "AWSCredentials": "awsCredentials",
    "AzureAPIKey": "azureAPIKey",
    "AzureCredentials": "azureCredentials",
    "GCPCredentials": "gcpCredentials",
    "AnthropicAPIKey": "anthropicAPIKey",
    "OpenAICredentials": "openAICredentials",
}
MODEL_HEADER = "x-ai-eg-model"

SECRET_PATTERNS = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"sk-(proj-)?[A-Za-z0-9_\-]{20,}")),
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
PLACEHOLDER = re.compile(r"^(<.*>|\$\{.*\}|[A-Z0-9_]+|changeme|replace.*|your[-_ ].*|xxx+|dummy|test|fake.*)$", re.I)

Key = Tuple[str, str, str]  # kind, namespace, name


def _ns(obj: dict) -> str:
    return (obj.get("metadata") or {}).get("namespace") or "default"


def _name(obj: dict) -> str:
    return (obj.get("metadata") or {}).get("name") or "<unnamed>"


def _ident(obj: dict) -> str:
    return f"{obj.get('kind', '?')}/{_ns(obj)}/{_name(obj)}"


def _is_local_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return True
    if h in ("localhost",) or h.endswith((".svc", ".svc.cluster.local", ".cluster.local", ".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        pass
    return "." not in h  # single-label names resolve in-cluster


class Index:
    def __init__(self, docs: Iterable[Tuple[str, dict]]):
        self.objs: List[Tuple[str, dict]] = []
        self.by_key: Dict[Key, dict] = {}
        self.by_kind: Dict[str, List[dict]] = defaultdict(list)
        for src, d in docs:
            if not isinstance(d, dict) or "kind" not in d:
                continue
            if d.get("kind") == "List" and isinstance(d.get("items"), list):
                for it in d["items"]:
                    if isinstance(it, dict) and "kind" in it:
                        self._add(src, it)
                continue
            self._add(src, d)

    def _add(self, src: str, d: dict) -> None:
        self.objs.append((src, d))
        self.by_key[(d["kind"], _ns(d), _name(d))] = d
        self.by_kind[d["kind"]].append(d)

    def get(self, kind: str, ns: str, name: str) -> Optional[dict]:
        return self.by_key.get((kind, ns, name))


def _spec(obj: dict) -> dict:
    s = obj.get("spec")
    return s if isinstance(s, dict) else {}


def _list(v) -> list:
    return v if isinstance(v, list) else []


def _targets(obj: dict) -> List[dict]:
    spec = _spec(obj)
    refs = _list(spec.get("targetRefs"))
    if isinstance(spec.get("targetRef"), dict):
        refs.append(spec["targetRef"])
    return [r for r in refs if isinstance(r, dict)]


def _backend_endpoints(backend: dict) -> List[Tuple[str, Optional[int]]]:
    eps = []
    for ep in _list(_spec(backend).get("endpoints")):
        if not isinstance(ep, dict):
            continue
        if isinstance(ep.get("fqdn"), dict):
            eps.append((str(ep["fqdn"].get("hostname", "")), ep["fqdn"].get("port")))
        elif isinstance(ep.get("ip"), dict):
            eps.append((str(ep["ip"].get("address", "")), ep["ip"].get("port")))
        elif isinstance(ep.get("unix"), dict):
            eps.append(("localhost", None))
    return eps


def _secret_values(secret: dict) -> List[Tuple[str, str]]:
    vals = []
    for k, v in (secret.get("stringData") or {}).items():
        vals.append((k, str(v)))
    for k, v in (secret.get("data") or {}).items():
        try:
            vals.append((k, base64.b64decode(str(v), validate=True).decode("utf-8", "replace")))
        except Exception:
            vals.append((k, str(v)))
    return vals


def lint(index: Index) -> Tuple[List[Finding], Dict[str, int]]:
    F: List[Finding] = []

    def add(rule, sev, obj, msg, fix=""):
        F.append(Finding(rule, sev, msg, _ident(obj) if isinstance(obj, dict) else str(obj), fix))

    # --- policy indexes -------------------------------------------------
    bsp_targets: Dict[Tuple[str, str, str], List[dict]] = defaultdict(list)
    for bsp in index.by_kind.get("BackendSecurityPolicy", []):
        for t in _targets(bsp):
            bsp_targets[(t.get("kind", "AIServiceBackend"), _ns(bsp), t.get("name", ""))].append(bsp)
    tls_targets = set()
    for tp in index.by_kind.get("BackendTLSPolicy", []):
        for t in _targets(tp):
            tls_targets.add((t.get("kind", "Backend"), _ns(tp), t.get("name", "")))
    ratelimited_gateways = set()
    token_ratelimited_gateways = set()
    for btp in index.by_kind.get("BackendTrafficPolicy", []):
        rl = _spec(btp).get("rateLimit")
        if not isinstance(rl, dict):
            continue
        for t in _targets(btp):
            key = (t.get("kind", "Gateway"), _ns(btp), t.get("name", ""))
            ratelimited_gateways.add(key)
            rules = _list(((rl.get("global") or {}) if isinstance(rl.get("global"), dict) else {}).get("rules"))
            rules += _list(((rl.get("local") or {}) if isinstance(rl.get("local"), dict) else {}).get("rules"))
            for r in rules:
                resp = ((r or {}).get("cost") or {}).get("response") or {}
                if resp.get("from") == "Metadata":
                    token_ratelimited_gateways.add(key)

    # --- apiVersion -----------------------------------------------------
    for _, obj in index.objs:
        av = str(obj.get("apiVersion", ""))
        if obj.get("kind") in AI_KINDS and av.startswith(AI_GROUP + "/"):
            ver = av.split("/", 1)[1]
            if ver != CURRENT_AI_VERSION and ver == "v1alpha1":
                add("deprecated-api-version", "low", obj,
                    f"{av} is the pre-1.0 API version; current examples use {AI_GROUP}/{CURRENT_AI_VERSION}.",
                    f"Change apiVersion to {AI_GROUP}/{CURRENT_AI_VERSION}.")

    # --- AIServiceBackend ----------------------------------------------
    external_aisb = {}
    for b in index.by_kind.get("AIServiceBackend", []):
        spec = _spec(b)
        schema = (spec.get("schema") or {}).get("name") if isinstance(spec.get("schema"), dict) else None
        if not schema:
            add("backend-missing-schema", "high", b, "spec.schema.name is required so the router knows how to translate requests.",
                "Set spec.schema.name, e.g. OpenAI, AWSBedrock, Anthropic.")
        elif schema not in API_SCHEMAS:
            add("backend-unknown-schema", "high", b, f"Unknown API schema {schema!r}.",
                "Use one of: " + ", ".join(sorted(API_SCHEMAS)) + ".")
        ref = spec.get("backendRef")
        if not isinstance(ref, dict) or not ref.get("name"):
            add("backend-missing-backendref", "high", b, "spec.backendRef is missing; the AI backend has nowhere to send traffic.",
                "Add spec.backendRef pointing at a gateway.envoyproxy.io Backend.")
            continue
        kind = ref.get("kind", "Backend")
        ns = ref.get("namespace") or _ns(b)
        target = index.get(kind, ns, ref["name"])
        if target is None:
            if index.by_kind.get(kind):
                add("backend-dangling-backendref", "medium", b,
                    f"backendRef {kind}/{ns}/{ref['name']} is not defined in the scanned manifests.",
                    "Fix the name or include the Backend manifest.")
            continue
        eps = _backend_endpoints(target)
        ext = [(h, p) for h, p in eps if not _is_local_host(h)]
        if not ext:
            continue
        external_aisb[(_ns(b), _name(b))] = (target, ext)
        has_tls = (kind, ns, ref["name"]) in tls_targets or isinstance(_spec(target).get("tls"), dict)
        for host, port in ext:
            if port == 80 or (port not in (None, 443) and not has_tls):
                add("backend-plaintext-external", "high", b,
                    f"Traffic to external host {host}:{port} is not TLS-protected; prompts and credentials travel in clear text.",
                    "Use port 443 and attach a BackendTLSPolicy (or Backend spec.tls) for the Backend.")
            elif not has_tls:
                add("backend-no-tls-validation", "medium", b,
                    f"External host {host}:{port} has no BackendTLSPolicy, so the upstream certificate is not validated.",
                    "Add a BackendTLSPolicy targeting the Backend with wellKnownCACertificates: System and the hostname.")
        has_auth = bool(bsp_targets.get(("AIServiceBackend", _ns(b), _name(b))) or bsp_targets.get((kind, ns, ref["name"]))
                        or spec.get("backendSecurityPolicyRef"))
        if not has_auth:
            add("backend-unauthenticated-external", "high", b,
                f"AIServiceBackend talks to external {ext[0][0]} but no BackendSecurityPolicy targets it; "
                "credentials end up in agent code instead of the gateway.",
                "Add a BackendSecurityPolicy (e.g. type: APIKey with a secretRef) whose targetRefs names this AIServiceBackend.")

    # --- BackendSecurityPolicy -----------------------------------------
    for bsp in index.by_kind.get("BackendSecurityPolicy", []):
        spec = _spec(bsp)
        t = spec.get("type")
        if t not in BSP_TYPES:
            add("bsp-unknown-type", "high", bsp, f"type {t!r} is not a supported BackendSecurityPolicy type.",
                "Use one of: " + ", ".join(BSP_TYPES) + ".")
        else:
            want = BSP_TYPES[t]
            present = [f for f in BSP_TYPES.values() if f in spec]
            if want not in present:
                add("bsp-type-mismatch", "high", bsp, f"type is {t} but spec.{want} is not set.", f"Add spec.{want}.")
            extra = [f for f in present if f != want]
            if extra:
                add("bsp-type-mismatch", "high", bsp, f"type is {t} but spec also sets {', '.join(extra)}; the API server rejects this.",
                    f"Remove {', '.join(extra)}.")
            cfg = spec.get(want) if isinstance(spec.get(want), dict) else {}
            sref = (cfg.get("secretRef") or {}).get("name") if isinstance(cfg.get("secretRef"), dict) else None
            if sref and index.by_kind.get("Secret") and index.get("Secret", _ns(bsp), sref) is None:
                add("bsp-dangling-secret", "medium", bsp, f"secretRef {sref!r} is not defined in the scanned manifests.",
                    "Create the Secret or fix the name.")
            if isinstance(cfg.get("inline"), str) or isinstance(cfg.get("apiKey"), str):
                add("bsp-inline-credential", "critical", bsp, "Credential is written inline in the policy instead of a Secret.",
                    "Move it into a Kubernetes Secret and reference it with secretRef.")
        if not _targets(bsp):
            add("bsp-no-target", "medium", bsp, "Policy has no targetRefs, so it protects nothing.",
                "Add targetRefs naming the AIServiceBackend(s) it should apply to.")
        for tr in _targets(bsp):
            k = tr.get("kind", "AIServiceBackend")
            if index.by_kind.get(k) and index.get(k, _ns(bsp), tr.get("name", "")) is None:
                add("bsp-dangling-target", "medium", bsp, f"targetRef {k}/{tr.get('name')} does not exist in the scanned manifests.",
                    "Fix the targetRef name or include the target manifest.")

    # --- Secrets --------------------------------------------------------
    for s in index.by_kind.get("Secret", []):
        for key, val in _secret_values(s):
            hit = next((label for label, rx in SECRET_PATTERNS if rx.search(val)), None)
            if hit:
                add("secret-hardcoded", "critical", s, f"Key {key!r} contains what looks like a real {hit} committed to the manifest.",
                    "Rotate the credential now, remove it from git history, and inject it at deploy time (External Secrets, SOPS, sealed-secrets).")
            elif val and PLACEHOLDER.match(val.strip()):
                add("secret-placeholder", "low", s, f"Key {key!r} still holds placeholder {val.strip()!r}; requests will fail with 401.",
                    "Create the Secret out-of-band (kubectl create secret) instead of shipping a placeholder.")

    # --- AIGatewayRoute -------------------------------------------------
    model_owner: Dict[Tuple[str, str], str] = {}
    routes = index.by_kind.get("AIGatewayRoute", [])
    for r in routes:
        spec = _spec(r)
        parents = [p for p in _list(spec.get("parentRefs")) if isinstance(p, dict)]
        if not parents:
            add("route-no-parent", "medium", r, "No parentRefs; the route is not attached to any Gateway and receives no traffic.",
                "Add parentRefs naming the Gateway.")
        rules = [x for x in _list(spec.get("rules")) if isinstance(x, dict)]
        if not rules:
            add("route-no-rules", "high", r, "Route has no rules.", "Add at least one rule with backendRefs.")
        single_backend_rules = 0
        for i, rule in enumerate(rules):
            refs = [x for x in _list(rule.get("backendRefs")) if isinstance(x, dict)]
            if not refs:
                add("route-rule-no-backend", "high", r, f"rules[{i}] has no backendRefs.", "Add a backendRef to an AIServiceBackend.")
            for ref in refs:
                kind = ref.get("kind", "AIServiceBackend")
                if kind != "AIServiceBackend":
                    continue  # e.g. InferencePool
                ns = ref.get("namespace") or _ns(r)
                if index.get("AIServiceBackend", ns, ref.get("name", "")) is None:
                    add("route-dangling-backend", "high", r,
                        f"rules[{i}] references AIServiceBackend {ns}/{ref.get('name')} which is not defined.",
                        "Create the AIServiceBackend or fix the name.")
            if len(refs) == 1:
                single_backend_rules += 1
            timeouts = rule.get("timeouts") if isinstance(rule.get("timeouts"), dict) else {}
            if not timeouts.get("request"):
                add("route-no-request-timeout", "low", r,
                    f"rules[{i}] has no timeouts.request; long generations can hang clients or be cut by defaults.",
                    "Set rules[].timeouts.request (e.g. 120s) sized to your slowest model.")
            for m in _list(rule.get("matches")):
                for h in _list((m or {}).get("headers")):
                    if isinstance(h, dict) and str(h.get("name", "")).lower() == MODEL_HEADER and h.get("type", "Exact") == "Exact":
                        for p in parents or [{"name": "<none>"}]:
                            k = (p.get("name", ""), str(h.get("value")))
                            owner = f"{_ident(r)} rules[{i}]"
                            if k in model_owner and model_owner[k] != owner:
                                add("route-duplicate-model", "medium", r,
                                    f"Model {h.get('value')!r} on Gateway {p.get('name')} is also matched by {model_owner[k]}; "
                                    "one rule silently shadows the other.",
                                    "Keep one rule per model per Gateway; use multiple backendRefs inside it for fallback.")
                            else:
                                model_owner[k] = owner
        if rules and single_backend_rules == len(rules):
            add("route-no-fallback", "low", r, "Every rule has a single backend, so one provider outage takes the model down.",
                "Add a second backendRef with priority: 1 for failover (see the provider_fallback example).")
        costs = [c for c in _list(spec.get("llmRequestCosts")) if isinstance(c, dict)]
        if not costs:
            add("route-no-token-accounting", "medium", r,
                "No llmRequestCosts: token usage is not captured, so per-tenant quotas and cost attribution are impossible.",
                "Add llmRequestCosts (InputToken, OutputToken, TotalToken) with metadataKeys used by your rate-limit policy.")
        for c in costs:
            t = c.get("type")
            if t not in COST_TYPES:
                add("route-cost-type-invalid", "high", r, f"llmRequestCosts type {t!r} is not supported.",
                    "Use one of: " + ", ".join(sorted(COST_TYPES)) + ".")
            if t == "CEL" and not c.get("cel"):
                add("route-cost-cel-missing", "high", r, f"llmRequestCosts {c.get('metadataKey')!r} is type CEL but has no cel expression.",
                    "Add a cel expression, e.g. input_tokens + output_tokens * 4.")
            if not c.get("metadataKey"):
                add("route-cost-no-key", "medium", r, "llmRequestCosts entry has no metadataKey, so rate limits cannot reference it.",
                    "Set metadataKey (e.g. llm_total_token).")
        for p in parents:
            gk = (p.get("kind", "Gateway"), p.get("namespace") or _ns(r), p.get("name", ""))
            if gk not in ratelimited_gateways:
                add("route-no-rate-limit", "medium", r,
                    f"Gateway {gk[2]} has no BackendTrafficPolicy rateLimit; a runaway agent loop can spend without limit.",
                    "Add a BackendTrafficPolicy with a Global rateLimit whose cost.response reads llm token metadata.")
            elif costs and gk not in token_ratelimited_gateways:
                add("route-rate-limit-not-token-based", "low", r,
                    f"Gateway {gk[2]} rate-limits requests, not tokens; one huge prompt costs the same as a tiny one.",
                    "Set cost.response.from: Metadata with namespace io.envoy.ai_gateway and a token metadataKey.")

    # --- MCPRoute -------------------------------------------------------
    for m in index.by_kind.get("MCPRoute", []):
        spec = _spec(m)
        sp = spec.get("securityPolicy") if isinstance(spec.get("securityPolicy"), dict) else {}
        if not sp:
            add("mcp-route-unauthenticated", "high", m,
                "MCPRoute has no securityPolicy, so any client that reaches the Gateway can call every exposed tool.",
                "Add spec.securityPolicy.oauth (issuer + jwks) or another client auth mechanism.")
        oauth = sp.get("oauth") if isinstance(sp.get("oauth"), dict) else None
        if oauth:
            iss = str(oauth.get("issuer", ""))
            host = re.sub(r"^https?://", "", iss).split("/")[0].split(":")[0]
            if iss.startswith("http://") and not _is_local_host(host):
                add("mcp-oauth-plaintext-issuer", "medium", m, f"OAuth issuer {iss} uses plain HTTP.", "Use an https:// issuer.")
            if not oauth.get("jwks"):
                add("mcp-oauth-no-jwks", "medium", m, "OAuth is configured without jwks, so tokens cannot be verified.",
                    "Add oauth.jwks.remoteJWKS.uri.")
        for i, br in enumerate(_list(spec.get("backendRefs"))):
            if not isinstance(br, dict):
                continue
            if not isinstance(br.get("toolSelector"), dict):
                add("mcp-backend-no-tool-selector", "low", m,
                    f"backendRefs[{i}] ({br.get('name')}) exposes its full tool surface.",
                    "Add toolSelector.include / includeRegex to expose only the tools agents need.")
            kind = br.get("kind", "Backend")
            target = index.get(kind, br.get("namespace") or _ns(m), br.get("name", ""))
            if target is not None:
                ext = [h for h, _ in _backend_endpoints(target) if not _is_local_host(h)]
                if ext and not br.get("securityPolicy"):
                    add("mcp-backend-external-no-credentials", "medium", m,
                        f"backendRefs[{i}] reaches external MCP server {ext[0]} without a securityPolicy.",
                        "Add backendRefs[].securityPolicy.apiKey.secretRef if the upstream needs credentials, or confirm it is public.")
            elif index.by_kind.get(kind):
                add("mcp-backend-dangling", "high", m, f"backendRefs[{i}] {kind}/{br.get('name')} is not defined.",
                    "Fix the name or include the Backend manifest.")

    stats = {
        "objects": len(index.objs),
        "routes": len(routes),
        "ai_backends": len(index.by_kind.get("AIServiceBackend", [])),
        "security_policies": len(index.by_kind.get("BackendSecurityPolicy", [])),
        "mcp_routes": len(index.by_kind.get("MCPRoute", [])),
    }
    return F, stats
