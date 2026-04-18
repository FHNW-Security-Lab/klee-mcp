#!/usr/bin/env python
"""Standalone CLI to validate one candidate without going through MCP.

Usage:
    python scripts/verify_one.py --candidate candidate.json

Or with CLI flags:
    python scripts/verify_one.py \\
        --source examples/bof_01.c \\
        --function vulnerable_copy \\
        --cwe CWE-121 \\
        --timeout 60

Useful for smoke-testing the pipeline and for the benchmark runner.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the repo importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from symex_mcp.harness_gen import generate_harness
from symex_mcp.klee_runner import verify_with_retry
from symex_mcp.models import CWE, TaintedInput, VerifyRequest


def _parse() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", type=Path, help="Path to JSON candidate")
    ap.add_argument("--source", type=Path)
    ap.add_argument("--function")
    ap.add_argument("--cwe")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--dump-harness", action="store_true")
    return ap.parse_args()


def _req_from_json(path: Path) -> VerifyRequest:
    data = json.loads(path.read_text())
    taints = [TaintedInput.model_validate(t) for t in data.get("tainted_inputs", [])]
    return VerifyRequest(
        source_file=str(Path(data["source_file"]).resolve()),
        cwe=CWE(data["cwe"]),
        function_name=data["function_name"],
        sink_line=data.get("sink_line"),
        tainted_inputs=taints,
        assumptions=data.get("assumptions", []),
        loop_bounds=data.get("loop_bounds", {}),
        use_bounds=bool(data.get("use_bounds", False)),
        auto_relax_on_infeasible=bool(data.get("auto_relax_on_infeasible", False)),
        extra_sources=data.get("extra_sources", []),
        extra_bitcodes=data.get("extra_bitcodes", []),
        include_dirs=data.get("include_dirs", []),
        defines=data.get("defines", []),
        timeout_s=int(data.get("timeout_s", 60)),
        max_memory_mb=int(data.get("max_memory_mb", 2000)),
    )


def main() -> int:
    args = _parse()
    if args.candidate:
        req = _req_from_json(args.candidate)
    else:
        if not (args.source and args.function and args.cwe):
            print("Either --candidate or --source/--function/--cwe is required", file=sys.stderr)
            return 2
        req = VerifyRequest(
            source_file=str(args.source.resolve()),
            cwe=CWE(args.cwe),
            function_name=args.function,
            timeout_s=args.timeout,
        )

    if args.dump_harness:
        harness = generate_harness(req)
        print("--- harness.c ---")
        print(harness)
        print("--- end harness ---")

    resp = verify_with_retry(req)
    print(json.dumps(resp.model_dump(mode="json"), indent=2))
    return 0 if resp.verdict.value == "confirmed" else 1


if __name__ == "__main__":
    sys.exit(main())
