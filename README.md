# klee-mcp — LLM vulnerability triage with KLEE, delivered over MCP

**klee-mcp** is an MCP (Model Context Protocol) server plus a Claude Code
skill that closes the loop between *finding* C/C++ vulnerability
candidates with a language model and *validating* them with symbolic
execution. Give it a path to a C/C++ codebase; it emits a report with
confirmed bugs, concrete KLEE-synthesised inputs, a disclosure-ready
reproducer (`reproduce.c` + `poc.bin`), exploitability classification
(arbitrary-vs-bounded read/write, stack/heap target, CVSS-v3 vector),
and a list of rescued false positives.

The default trigger is natural language:

> "Analyze `examples/toy/bof_01.c` with klee-mcp."

The skill then auto-generates the KLEE harness, runs the verifier
with LLM-supplied bounds (and an auto-relax retry if the bounds were
wrong), optionally proves reachability from an LLM-picked entry
point, emits the disclosure artefacts, and writes the report.

## What it does (in one picture)

```
  C/C++ source
       │
       ▼
 ┌──────────────────────────────────────────────────────────┐
 │  LLM auditor (Claude Code + klee-mcp-triage skill)       │
 │    · enumerate TUs, find candidate functions             │
 │    · declare tainted inputs + LLM bounds                 │
 │    · (for complex libs) author a wrapper TU              │
 └──────────────────────────────────────────────────────────┘
       │  candidate JSON (CWE, tainted inputs, bounds, ...)
       ▼
 ┌──────────────────────────────────────────────────────────┐
 │  symex-validator MCP server (this repo)                  │
 │    auto_harness → harness.c                              │
 │    verify_vulnerability → KLEE (podman klee/klee:3.1)    │
 │    check_reachability_tool → entry→target probe          │
 │    emit_reproducer → reproduce.c + poc.bin               │
 └──────────────────────────────────────────────────────────┘
       │
       ▼
  Verdict: {confirmed | infeasible | timeout | build_failed | klee_error}
  + concrete ktest inputs
  + exploitability: {primitive, severity, CVSS vector, stack/heap, PC-overwrite hint}
  + auto-generated reproducer (gcc -fsanitize=address ... && ./reproduce)
  + disclosure-ready advisory text
```

## Key features

- **One-instruction triage.** `"analyze X with klee-mcp"` — the skill
  orchestrates Phases 0–3 without further input.
- **LLM-supplied bounds (`klee_assume`).** The LLM's semantic grasp of
  a function's preconditions reduces path explosion; the server also
  handles the case where those bounds are *wrong* via an auto-relax
  retry. The response flags when LLM bounds ruled out a real bug.
- **Reachability probes.** Given an LLM-picked entry function, the
  server patches a scratch copy of the source to insert
  `klee_report_error()` at the target, then runs KLEE to produce a
  concrete input that drives entry → target.
- **Whole-library linking.** Ship a pre-built library bitcode (e.g.
  `libpng+zlib.bc`) via `extra_bitcodes`; the runner `llvm-link`s it
  onto the harness before KLEE.
- **Disclosure-ready artefacts.** Every confirmed bug ships with a
  standalone `reproduce.c`, a raw `poc.bin`, the vulnerable source
  copy, a gcc+ASan run recipe, and a heuristic CVSS-v3 vector.
- **Exploitability classification.** Per confirmed bug: primitive
  (arbitrary/bounded read/write, uaf, null-deref, int-overflow, …),
  severity, attacker-controlled-address flag, stack/heap region,
  PC-overwrite possibility, and number of distinct triggers KLEE
  produced.

## MCP tools

| Tool | Purpose |
|------|---------|
| `auto_harness` | Given `source_file + function_name + cwe`, infer taints and return a default KLEE harness. |
| `verify_vulnerability` | Run KLEE on the candidate. Supports assumptions, loop_bounds, use_bounds, auto_relax, extra_bitcodes. |
| `check_reachability_tool` | Probe `entry_function` → `target_function` reachability. |
| `emit_reproducer` | Write `reproduce.c`, `poc.bin`, source copy, run recipe. |
| `generate_harness_tool` | Manual harness build with explicit taints. |
| `list_supported_cwes` | Enumerate the CWE tokens accepted by the tools. |

Complete JSON schema for candidates:
[`vuln_finder/candidate_schema.json`](vuln_finder/candidate_schema.json).

## Claude Code skill

The orchestrator skill is
[`vuln_finder/SKILL.md`](vuln_finder/SKILL.md). It defines:

- Phase 0: `auto_harness` or author-a-wrapper-TU (for libpng/libxml2-
  style APIs that need state setup).
- Phase 1: `verify_vulnerability` with bounds + auto-relax.
- Phase 2: `check_reachability_tool`.
- Phase 3: `emit_reproducer` + disclosure template.
- A per-bug disclosure template (advisory header, root cause,
  reproduction, concrete inputs, suggested fix, coordinated-
  disclosure email boilerplate).

## Example run (self-contained)

```bash
# One-time setup
python -m venv .venv && ./.venv/bin/pip install -r requirements.txt
podman pull docker.io/klee/klee:3.1

# Validate the toy stack-BOF example end-to-end
./.venv/bin/python scripts/verify_one.py \
    --candidate benchmark/candidates/bof_01.json --dump-harness

# Produces: verdict=confirmed, concrete input, reproducer hex,
# exploitability={primitive: bounded_write, severity: HIGH,
# pc_overwrite_possible: true, target_region: stack, cvss: CVSS:3.1/...}
```

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for Arch-Linux + podman
installation and [`INSTALL.md`](INSTALL.md) for the quick setup.

## Repo layout

- `symex_mcp/` — Python MCP server.
  - `server.py` — FastMCP entry point + 6 registered tools.
  - `klee_runner.py` — podman + KLEE driver with
    CWE→error-class mapping and side-effect filtering.
  - `harness_gen.py` — candidate → KLEE harness.c.
  - `reachability.py` — source patching + `klee_report_error` probe.
  - `reproducer.py` — `.ktest` decoder + `reproduce.c`/`poc.bin` emitter.
  - `exploitability.py` — primitive / severity / CVSS classification.
- `vuln_finder/` — Claude Code skill + candidate JSON schema.
- `examples/` — toy C programs and extracted real-library targets.
- `benchmark/` — candidate JSONs + `run_bench.py` (CSV output).
- `scripts/` — `verify_one.py`, `check_reach.py`, `build_lib_bc.sh`,
  `run_mcp.sh`.

## Evaluation (what you get out of the box)

`python benchmark/run_bench.py` runs **14 candidates** across 5 phases
(toy CWE coverage, LLM bounds + auto-relax, reachability, extracted
real libpng, whole-library libpng + zlib bitcode). On the reference
environment all 14 verdicts match ground truth. One real libpng
finding (`png_format_number` at `pngerror.c:140`) is classified as
`arbitrary_write`, severity **CRITICAL**, with a disclosure-ready
reproducer.

## Status

This is the public release of the system described in the paper
*"Closing the Triage Loop: MCP-mediated KLEE Validation of
LLM-Reported Vulnerabilities"* (C2S3-26 submission). See
[`DEPLOYMENT.md`](DEPLOYMENT.md) for reproducing the evaluation and
integrating the skill with Claude Code.

## License

MIT. See [`LICENSE`](LICENSE).
