#!/usr/bin/env python
"""Run all candidate JSONs under benchmark/candidates and summarise.

Intended as the scaffold for the paper's evaluation harness. For Juliet,
point --candidates at a directory produced by your Juliet-to-candidate
converter; each file is one test case.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from symex_mcp.harness_gen import generate_harness
from symex_mcp.klee_runner import verify_with_retry
from symex_mcp.models import CWE, TaintedInput, VerifyRequest


@dataclass
class Row:
    name: str
    expected: str
    verdict: str
    cwe: str
    wall_seconds: float
    bounds_applied: bool
    initial_verdict: str
    relaxed: bool
    notes: str


def _req_from_json(path: Path) -> tuple[VerifyRequest, str]:
    data = json.loads(path.read_text())
    taints = [TaintedInput.model_validate(t) for t in data.get("tainted_inputs", [])]
    req = VerifyRequest(
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
    return req, data.get("expected_verdict", "confirmed")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--candidates",
        type=Path,
        default=Path("benchmark/candidates"),
    )
    ap.add_argument("--out", type=Path, default=Path("benchmark/results.csv"))
    args = ap.parse_args()

    rows: list[Row] = []
    for cand in sorted(args.candidates.glob("*.json")):
        name = cand.stem
        # Expected verdict: prefer explicit `expected_verdict` field;
        # fall back to heuristic (safe_ prefix -> infeasible, else confirmed).
        try:
            raw = json.loads(cand.read_text())
        except Exception:
            raw = {}
        expected = raw.get("expected_verdict")
        if expected is None:
            expected = "infeasible" if name.startswith("safe_") else "confirmed"
        print(f"\n=== {name} (expected={expected}) ===", flush=True)
        req, _ = _req_from_json(cand)
        try:
            resp = verify_with_retry(req)
        except Exception as exc:
            rows.append(
                Row(
                    name=name,
                    expected=expected,
                    verdict="harness_error",
                    cwe=req.cwe.value,
                    wall_seconds=0.0,
                    bounds_applied=False,
                    initial_verdict="",
                    relaxed=False,
                    notes=str(exc)[:120],
                )
            )
            continue
        rows.append(
            Row(
                name=name,
                expected=expected,
                verdict=resp.verdict.value,
                cwe=req.cwe.value,
                wall_seconds=round(resp.wall_seconds, 2),
                bounds_applied=resp.bounds_applied,
                initial_verdict=(resp.initial_verdict.value if resp.initial_verdict else ""),
                relaxed=resp.relaxed_retry_performed,
                notes=resp.notes[:200],
            )
        )
        print(
            f"  verdict={resp.verdict.value}  wall={resp.wall_seconds:.1f}s"
            f"  bounds={resp.bounds_applied}"
            f"  relaxed={resp.relaxed_retry_performed}"
            f"  notes={resp.notes[:100]}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()) if rows else [])
        writer.writeheader()
        for r in rows:
            writer.writerow(asdict(r))

    # quick summary
    ok = sum(1 for r in rows if r.verdict == r.expected)
    print(f"\nSUMMARY: {ok}/{len(rows)} match expected verdict")
    print(f"CSV: {args.out}")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
