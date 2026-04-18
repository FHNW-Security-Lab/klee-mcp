#!/usr/bin/env python
"""Standalone CLI for check_reachability."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from symex_mcp.models import ReachabilityRequest, TaintedInput
from symex_mcp.reachability import check_reachability


def _parse() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", type=Path, required=True,
                    help="JSON with {source_file, entry_function, target_function, "
                         "tainted_inputs, assumptions?, loop_bounds?, use_bounds?, timeout_s?}")
    return ap.parse_args()


def main() -> int:
    args = _parse()
    data = json.loads(args.candidate.read_text())
    req = ReachabilityRequest(
        source_file=str(Path(data["source_file"]).resolve()),
        entry_function=data["entry_function"],
        target_function=data["target_function"],
        tainted_inputs=[TaintedInput.model_validate(t) for t in data.get("tainted_inputs", [])],
        assumptions=data.get("assumptions", []),
        loop_bounds=data.get("loop_bounds", {}),
        use_bounds=bool(data.get("use_bounds", False)),
        extra_sources=data.get("extra_sources", []),
        include_dirs=data.get("include_dirs", []),
        defines=data.get("defines", []),
        timeout_s=int(data.get("timeout_s", 60)),
    )
    resp = check_reachability(req)
    print(json.dumps(resp.model_dump(mode="json"), indent=2))
    return 0 if resp.verdict.value == "reached" else 1


if __name__ == "__main__":
    sys.exit(main())
