import base64
import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent_router_lint import cli  # noqa: E402
from agent_router_lint.report import Finding, Report, render  # noqa: E402
from agent_router_lint.rules import Index, _is_local_host, lint  # noqa: E402
from agent_router_lint.yamlite import load_all  # noqa: E402

SAMPLES = os.path.join(ROOT, "agent_router_lint", "samples")


def run(text, builtin=True):
    docs = [("t", d) for d in load_all(textwrap.dedent(text), force_builtin=builtin)]
    findings, stats = lint(Index(docs))
    return {f.rule for f in findings}, findings, stats


def cli_run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.main(list(argv))
    return rc, buf.getvalue()


EXTERNAL_BACKEND = """
apiVersion: aigateway.envoyproxy.io/v1beta1
kind: AIServiceBackend
metadata: {name: p, namespace: ns}
spec:
  schema: {name: OpenAI}
  backendRef: {name: p, kind: Backend, group: gateway.envoyproxy.io}
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: Backend
metadata: {name: p, namespace: ns}
spec:
  endpoints:
    - fqdn:
        hostname: api.openai.com
        port: 443
"""


class YamlLiteTests(unittest.TestCase):
    def test_matches_pyyaml_on_samples(self):
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest("PyYAML not installed")
        for name in ("good.yaml", "bad.yaml"):
            with open(os.path.join(SAMPLES, name)) as fh:
                text = fh.read()
            self.assertEqual(load_all(text, force_builtin=True), [d for d in yaml.safe_load_all(text) if d])

    def test_compact_sequence_and_scalars(self):
        doc = load_all("a:\n- 1\n- x: 'q'\n  y: true\nb: ~\nc: [1, \"two\"]\n", force_builtin=True)[0]
        self.assertEqual(doc, {"a": [1, {"x": "q", "y": True}], "b": None, "c": [1, "two"]})

    def test_block_scalar_and_comments(self):
        doc = load_all("k: |\n  line1\n  line2\nz: 3 # note\n", force_builtin=True)[0]
        self.assertEqual(doc, {"k": "line1\nline2\n", "z": 3})

    def test_multiline_flow(self):
        doc = load_all("s:\n  [\n    \"a\",\n    \"b\",\n  ]\n", force_builtin=True)[0]
        self.assertEqual(doc, {"s": ["a", "b"]})

    def test_multi_document(self):
        self.assertEqual(len(load_all("a: 1\n---\nb: 2\n---\n", force_builtin=True)), 2)


class SampleTests(unittest.TestCase):
    def test_good_sample_is_clean(self):
        rc, out = cli_run("--demo", "good", "-f", "json")
        data = json.loads(out)
        self.assertEqual(data["grade"], "A")
        self.assertEqual(data["findings"], [])
        self.assertEqual(rc, 0)

    def test_bad_sample_catches_every_planted_fault(self):
        rc, out = cli_run("--demo", "bad", "-f", "json", "--builtin-yaml")
        rules = {f["rule"] for f in json.loads(out)["findings"]}
        expected = {
            "deprecated-api-version", "route-duplicate-model", "route-dangling-backend",
            "route-cost-cel-missing", "route-cost-type-invalid", "backend-unauthenticated-external",
            "backend-unknown-schema", "bsp-type-mismatch", "backend-plaintext-external",
            "backend-no-tls-validation", "secret-hardcoded", "mcp-route-unauthenticated",
            "mcp-backend-no-tool-selector", "mcp-backend-external-no-credentials",
            "route-no-rate-limit", "route-no-fallback", "route-no-request-timeout",
        }
        self.assertTrue(expected <= rules, expected - rules)
        self.assertEqual(json.loads(out)["grade"], "F")

    def test_pyyaml_and_builtin_agree(self):
        _, a = cli_run("--demo", "bad", "-f", "json", "--builtin-yaml")
        _, b = cli_run("--demo", "bad", "-f", "json")
        self.assertEqual(json.loads(a)["findings"], json.loads(b)["findings"])


class RuleTests(unittest.TestCase):
    def test_unauthenticated_external_backend(self):
        rules, _, _ = run(EXTERNAL_BACKEND)
        self.assertIn("backend-unauthenticated-external", rules)
        self.assertIn("backend-no-tls-validation", rules)

    def test_policy_and_tls_clear_findings(self):
        rules, _, _ = run(EXTERNAL_BACKEND + """
---
apiVersion: aigateway.envoyproxy.io/v1beta1
kind: BackendSecurityPolicy
metadata: {name: k, namespace: ns}
spec:
  targetRefs:
    - {group: aigateway.envoyproxy.io, kind: AIServiceBackend, name: p}
  type: APIKey
  apiKey:
    secretRef: {name: s}
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {name: t, namespace: ns}
spec:
  targetRefs:
    - {group: gateway.envoyproxy.io, kind: Backend, name: p}
""")
        self.assertNotIn("backend-unauthenticated-external", rules)
        self.assertNotIn("backend-no-tls-validation", rules)

    def test_in_cluster_backend_needs_no_auth(self):
        rules, _, _ = run(EXTERNAL_BACKEND.replace("api.openai.com", "vllm.models.svc.cluster.local").replace("443", "8000"))
        self.assertNotIn("backend-unauthenticated-external", rules)
        self.assertNotIn("backend-plaintext-external", rules)

    def test_policy_in_other_namespace_does_not_count(self):
        rules, _, _ = run(EXTERNAL_BACKEND + """
---
apiVersion: aigateway.envoyproxy.io/v1beta1
kind: BackendSecurityPolicy
metadata: {name: k, namespace: other}
spec:
  targetRefs:
    - {kind: AIServiceBackend, name: p}
  type: APIKey
  apiKey: {secretRef: {name: s}}
""")
        self.assertIn("backend-unauthenticated-external", rules)

    def test_openai_credentials_type_is_valid(self):
        rules, _, _ = run("""
kind: BackendSecurityPolicy
apiVersion: aigateway.envoyproxy.io/v1beta1
metadata: {name: x}
spec:
  targetRefs: [{kind: AIServiceBackend, name: a}]
  type: OpenAICredentials
  openAICredentials: {}
""")
        self.assertNotIn("bsp-unknown-type", rules)
        self.assertNotIn("bsp-type-mismatch", rules)

    def test_bsp_missing_field_and_no_target(self):
        rules, _, _ = run("""
kind: BackendSecurityPolicy
metadata: {name: x}
spec:
  type: APIKey
""")
        self.assertIn("bsp-type-mismatch", rules)
        self.assertIn("bsp-no-target", rules)

    def test_base64_secret_is_decoded(self):
        enc = base64.b64encode(b"sk-proj-abcdefghijklmnopqrstuvwxyz0123").decode()
        rules, _, _ = run(f"kind: Secret\nmetadata: {{name: s}}\ndata:\n  apiKey: {enc}\n")
        self.assertIn("secret-hardcoded", rules)

    def test_placeholder_secret_is_low(self):
        rules, f, _ = run("kind: Secret\nmetadata: {name: s}\nstringData:\n  apiKey: OPENAI_API_KEY\n")
        self.assertEqual(rules, {"secret-placeholder"})
        self.assertEqual(f[0].severity, "low")

    def test_token_rate_limit_satisfies_rate_rules(self):
        base = """
kind: AIGatewayRoute
apiVersion: aigateway.envoyproxy.io/v1beta1
metadata: {name: r}
spec:
  parentRefs: [{name: gw}]
  rules:
    - backendRefs: [{name: a}, {name: b, priority: 1}]
      timeouts: {request: 60s}
  llmRequestCosts:
    - {metadataKey: t, type: TotalToken}
"""
        rules, _, _ = run(base)
        self.assertIn("route-no-rate-limit", rules)
        req_only = base + """
---
kind: BackendTrafficPolicy
metadata: {name: p}
spec:
  targetRefs: [{kind: Gateway, name: gw}]
  rateLimit:
    type: Global
    global:
      rules:
        - limit: {requests: 10, unit: Hour}
"""
        rules, _, _ = run(req_only)
        self.assertNotIn("route-no-rate-limit", rules)
        self.assertIn("route-rate-limit-not-token-based", rules)
        token = req_only.replace("        - limit: {requests: 10, unit: Hour}",
                                 "        - limit: {requests: 10, unit: Hour}\n"
                                 "          cost:\n            response:\n              from: Metadata")
        rules, _, _ = run(token)
        self.assertNotIn("route-rate-limit-not-token-based", rules)
        self.assertNotIn("route-no-fallback", rules)
        self.assertNotIn("route-no-request-timeout", rules)

    def test_inference_pool_refs_are_not_dangling(self):
        rules, _, _ = run("""
kind: AIGatewayRoute
metadata: {name: r}
spec:
  parentRefs: [{name: gw}]
  rules:
    - backendRefs:
        - {name: pool, kind: InferencePool, group: inference.networking.k8s.io}
""")
        self.assertNotIn("route-dangling-backend", rules)

    def test_mcp_oauth_checks(self):
        rules, _, _ = run("""
kind: MCPRoute
metadata: {name: m}
spec:
  parentRefs: [{name: gw}]
  securityPolicy:
    oauth:
      issuer: http://auth.example.com/realm
  backendRefs: []
""")
        self.assertIn("mcp-oauth-plaintext-issuer", rules)
        self.assertIn("mcp-oauth-no-jwks", rules)
        self.assertNotIn("mcp-route-unauthenticated", rules)

    def test_local_host_detection(self):
        for h in ("localhost", "svc.ns.svc.cluster.local", "10.0.0.4", "127.0.0.1", "0.0.0.0", "vllm"):
            self.assertTrue(_is_local_host(h), h)
        for h in ("api.openai.com", "8.8.8.8"):
            self.assertFalse(_is_local_host(h), h)


class CliTests(unittest.TestCase):
    def test_gates(self):
        self.assertEqual(cli_run("--demo", "bad", "--min-grade", "C")[0], 1)
        self.assertEqual(cli_run("--demo", "bad", "--fail-on", "critical")[0], 1)
        self.assertEqual(cli_run("--demo", "good", "--min-grade", "A", "--fail-on", "low")[0], 0)

    def test_disable_rule(self):
        _, out = cli_run("--demo", "bad", "-f", "json", "--disable", "secret-hardcoded")
        self.assertNotIn("secret-hardcoded", {f["rule"] for f in json.loads(out)["findings"]})

    def test_directory_scan_and_formats(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.yaml"), "w") as fh:
                fh.write(EXTERNAL_BACKEND)
            rc, out = cli_run(d, "-f", "markdown")
            self.assertIn("backend-unauthenticated-external", out)
            _, badge = cli_run(d, "-f", "badge")
            self.assertTrue(badge.startswith("https://img.shields.io/badge/"))
            _, ep = cli_run(d, "-f", "badge-endpoint")
            self.assertEqual(json.loads(ep)["schemaVersion"], 1)

    def test_missing_path_returns_2(self):
        self.assertEqual(cli_run("/no/such/file.yaml")[0], 2)

    def test_list_rules(self):
        rc, out = cli_run("--list-rules")
        self.assertEqual(rc, 0)
        self.assertIn("secret-hardcoded", out)


class ScoreTests(unittest.TestCase):
    def test_critical_caps_at_d_and_repeats_are_damped(self):
        r = Report("t", "x", [Finding("a", "critical", "m")])
        self.assertEqual(r.grade, "D")
        many = Report("t", "x", [Finding("b", "low", "m")] * 10)
        self.assertEqual(many.score, 94.0)
        self.assertIn("Grade", render(many, "console"))


if __name__ == "__main__":
    unittest.main()
