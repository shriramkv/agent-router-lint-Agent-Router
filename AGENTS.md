# AGENTS.md

Guidance for coding agents working in this repository.

## Project

`agent-router-lint` is a static, cross-resource linter for Agent Router (formerly Envoy AI Gateway) Kubernetes manifests. Package: `agent_router_lint/`.

- `yamlite.py`: zero-dependency block-YAML loader. Must stay output-compatible with `yaml.safe_load_all` for Kubernetes-style manifests.
- `rules.py`: the `Index` of all objects and the `lint()` function. Every rule lives here.
- `report.py`: findings, grading and output renderers.
- `cli.py`: argument parsing, input collection, exit codes, and the `RULES` catalogue shown by `--list-rules`.
- `samples/good.yaml` must grade A with zero findings. `samples/bad.yaml` must trigger every rule listed in `tests/test_lint.py::test_bad_sample_catches_every_planted_fault`.

## Commands

- Run tests: `python -m unittest discover -s tests -v`
- Try it: `python -m agent_router_lint --demo bad`

## Rules for changes

- You MUST keep the runtime dependency list empty. PyYAML stays optional.
- You MUST support Python 3.9. Do not use `match` statements or `X | Y` types outside annotations.
- When you add a rule, you MUST add it to `RULES` in `cli.py`, the README rule table, and a test that proves it fires and a test that proves the fix clears it.
- Enumerations (API schemas, policy types, cost types) MUST match the upstream `api/v1beta1` Go types. Cite the upstream file in the commit message when you change them.
- Every finding SHOULD carry a concrete `fix` string.
- Never commit real credentials, including in tests. Build test keys from obviously fake material.
- Do not make network calls. The linter is static by design.
