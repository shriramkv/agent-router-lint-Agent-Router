"""Command-line entry point for agent-router-lint."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Tuple

from . import __version__
from .report import Report, grade_at_least, render, severity_at_least
from .rules import Index, lint
from .yamlite import YamlError, load_all

HERE = os.path.dirname(os.path.abspath(__file__))
DEMOS = {
    "good": os.path.join(HERE, "samples", "good.yaml"),
    "bad": os.path.join(HERE, "samples", "bad.yaml"),
}


def collect(paths: List[str], builtin: bool) -> Tuple[List[Tuple[str, dict]], List[str]]:
    docs, errors = [], []

    def load(label: str, text: str) -> None:
        try:
            if label.endswith(".json") or text.lstrip().startswith("{") and not label.endswith((".yaml", ".yml")):
                obj = json.loads(text)
                items = obj if isinstance(obj, list) else [obj]
            else:
                items = load_all(text, force_builtin=builtin)
            docs.extend((label, d) for d in items)
        except (YamlError, ValueError) as exc:
            errors.append(f"{label}: {exc}")

    for p in paths:
        if p == "-":
            load("<stdin>", sys.stdin.read())
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for f in sorted(files):
                    if f.endswith((".yaml", ".yml", ".json")):
                        fp = os.path.join(root, f)
                        with open(fp, encoding="utf-8") as fh:
                            load(fp, fh.read())
        elif os.path.isfile(p):
            with open(p, encoding="utf-8") as fh:
                load(p, fh.read())
        else:
            errors.append(f"{p}: no such file or directory")
    return docs, errors


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="agent-router-lint",
        description="Cross-resource linter for Agent Router (formerly Envoy AI Gateway) manifests.",
    )
    ap.add_argument("paths", nargs="*", help="YAML/JSON files or directories ('-' reads stdin, e.g. from kustomize build)")
    ap.add_argument("--demo", choices=sorted(DEMOS), help="lint a bundled sample (good or bad)")
    ap.add_argument("-f", "--format", default="console", choices=["console", "json", "markdown", "badge", "badge-endpoint"])
    ap.add_argument("--min-grade", metavar="GRADE", help="exit 1 if the grade is worse than this (A-F)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit 1 if any finding is at or above this severity")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule (repeatable)")
    ap.add_argument("--builtin-yaml", action="store_true", help="force the zero-dependency YAML loader even if PyYAML is installed")
    ap.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


RULES = [
    ("secret-hardcoded", "critical", "Secret contains a real-looking provider key"),
    ("bsp-inline-credential", "critical", "credential written inline in a BackendSecurityPolicy"),
    ("backend-unauthenticated-external", "high", "external AIServiceBackend with no BackendSecurityPolicy"),
    ("backend-plaintext-external", "high", "external Backend on port 80 / without TLS"),
    ("backend-missing-schema", "high", "AIServiceBackend without spec.schema.name"),
    ("backend-unknown-schema", "high", "unsupported API schema"),
    ("backend-missing-backendref", "high", "AIServiceBackend without spec.backendRef"),
    ("bsp-unknown-type", "high", "unsupported BackendSecurityPolicy type"),
    ("bsp-type-mismatch", "high", "type does not match the populated credential field"),
    ("route-dangling-backend", "high", "AIGatewayRoute references a missing AIServiceBackend"),
    ("route-no-rules", "high", "AIGatewayRoute without rules"),
    ("route-rule-no-backend", "high", "rule without backendRefs"),
    ("route-cost-type-invalid", "high", "unsupported llmRequestCosts type"),
    ("route-cost-cel-missing", "high", "CEL cost without expression"),
    ("mcp-route-unauthenticated", "high", "MCPRoute without client securityPolicy"),
    ("mcp-backend-dangling", "high", "MCPRoute backendRef to missing Backend"),
    ("backend-no-tls-validation", "medium", "external Backend without BackendTLSPolicy"),
    ("backend-dangling-backendref", "medium", "AIServiceBackend points at a missing Backend"),
    ("bsp-no-target", "medium", "BackendSecurityPolicy with no targetRefs"),
    ("bsp-dangling-target", "medium", "BackendSecurityPolicy target missing"),
    ("bsp-dangling-secret", "medium", "secretRef to a missing Secret"),
    ("route-no-parent", "medium", "AIGatewayRoute not attached to a Gateway"),
    ("route-duplicate-model", "medium", "two rules match the same model on one Gateway"),
    ("route-no-token-accounting", "medium", "no llmRequestCosts (no usage attribution / token quotas)"),
    ("route-cost-no-key", "medium", "llmRequestCosts entry without metadataKey"),
    ("route-no-rate-limit", "medium", "parent Gateway has no rateLimit (denial-of-wallet)"),
    ("mcp-oauth-plaintext-issuer", "medium", "OAuth issuer over http"),
    ("mcp-oauth-no-jwks", "medium", "OAuth without jwks"),
    ("mcp-backend-external-no-credentials", "medium", "external MCP backend without securityPolicy"),
    ("route-rate-limit-not-token-based", "low", "rate limit counts requests, not tokens"),
    ("route-no-fallback", "low", "every rule has one backend (no failover)"),
    ("route-no-request-timeout", "low", "rule without timeouts.request"),
    ("mcp-backend-no-tool-selector", "low", "MCP backend exposes its full tool surface"),
    ("secret-placeholder", "low", "Secret still holds a placeholder"),
    ("deprecated-api-version", "low", "aigateway.envoyproxy.io/v1alpha1 in use"),
]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        for rid, sev, desc in RULES:
            print(f"{sev:9} {rid:38} {desc}")
        return 0
    paths = list(args.paths)
    if args.demo:
        paths.append(DEMOS[args.demo])
    if not paths:
        build_parser().print_usage(sys.stderr)
        print("error: give at least one path, '-' for stdin, or --demo good|bad", file=sys.stderr)
        return 2
    docs, errors = collect(paths, args.builtin_yaml)
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if errors and not docs:
        return 2
    findings, stats = lint(Index(docs))
    findings = [f for f in findings if f.rule not in set(args.disable)]
    target = f"demo:{args.demo}" if args.demo and not args.paths else ", ".join(args.paths or paths)
    report = Report("agent-router-lint", target, findings, stats)
    print(render(report, args.format))
    rc = 0
    if args.min_grade and not grade_at_least(report.grade, args.min_grade):
        rc = 1
    if args.fail_on and any(severity_at_least(f.severity, args.fail_on) for f in findings):
        rc = 1
    return rc


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
