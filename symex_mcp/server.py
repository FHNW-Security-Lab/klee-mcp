"""FastMCP server exposing symbolic-execution validation tools to Claude Code.

Tools:
  - verify_vulnerability: main entry. Given a candidate vuln (file,
    function, CWE, tainted inputs, optional LLM bounds), runs KLEE
    inside a podman container. Returns a structured verdict. Supports
    opt-in LLM bounds (`assumptions`, `loop_bounds`, `use_bounds`) and
    optional server-side auto-relax retry on infeasible.
  - check_reachability: Phase 2 — given entry_function and
    target_function in the same TU, asks KLEE whether control reaches
    target_function from entry_function with symbolic inputs.
  - generate_harness_tool: exposes the harness generator for inspection.
  - list_supported_cwes: enumerates accepted CWE tokens.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from pathlib import Path

from .harness_gen import generate_harness
from .klee_runner import verify_with_retry
from .models import (
    CWE,
    ReachabilityRequest,
    TaintedInput,
    VerifyRequest,
)
from .reachability import check_reachability
from .reproducer import emit_reproducer as _emit_reproducer

logging.basicConfig(
    level=os.environ.get("SYMEX_LOG", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("symex-mcp")

mcp = FastMCP("symex-validator")


def _coerce_taints(raw: Optional[list[dict[str, Any]]]) -> list[TaintedInput]:
    if not raw:
        return []
    return [TaintedInput.model_validate(t) for t in raw]


@mcp.tool()
def list_supported_cwes() -> dict:
    """Return the CWE identifiers this server accepts in verify_vulnerability."""
    return {
        "cwes": [c.value for c in CWE],
        "notes": (
            "KLEE validates memory-safety, integer-overflow, and arithmetic "
            "bugs directly. UAF/double-free detection depends on the code "
            "exercising the freed pointer under a symbolic path; if that "
            "requires nontrivial state sequencing, KLEE may not reach it "
            "within the time budget."
        ),
    }


@mcp.tool()
def auto_harness(
    source_file: str,
    function_name: str,
    cwe: str = "OTHER",
) -> dict:
    """Phase-0 tool: fully automatic harness generation from just the
    source file and function name.

    The server parses the target function's prototype, infers one
    symbolic taint per parameter with sensible defaults:
      - scalar → klee_make_symbolic of matching width (char=1, int=4, long/size_t=8)
      - `char *`, `const char *` → 256-byte symbolic buffer, null-terminated
      - other pointer-to-X → 256-byte symbolic buffer (if the attacker
        controls a struct, this is usually what you want)
    Then returns the harness C source and the inferred taint list.

    This is the starting point of the recommended workflow:
      1. auto_harness(src, fn, cwe) -> inspect harness + taints
      2. (optional) adjust taints / add assumptions / add loop_bounds
      3. verify_vulnerability(..., use_bounds=True,
         auto_relax_on_infeasible=True) -> get a verdict
      4. (optional) check_reachability_tool(src, entry, target)
         -> prove the function is reachable from a realistic entry

    If the inferred taints are wrong for your case (e.g. a pointer
    parameter should be NULL, or a scalar should be a bounded value),
    call verify_vulnerability directly with your own tainted_inputs.
    """
    req = VerifyRequest(
        source_file=source_file,
        cwe=CWE(cwe),
        function_name=function_name,
        tainted_inputs=[],  # force inference
    )
    from .harness_gen import _infer_taints, extract_prototype, parse_args
    from pathlib import Path

    source_text = Path(source_file).read_text(errors="replace")
    proto = extract_prototype(source_text, function_name)
    if proto is None:
        return {
            "error": f"could not find prototype of {function_name} in {source_file}",
            "source_file": source_file,
            "function": function_name,
        }
    _, args_str = proto
    parsed = parse_args(args_str)
    inferred = _infer_taints(parsed, [])
    harness_c = generate_harness(req)
    return {
        "harness_c": harness_c,
        "function": function_name,
        "source_file": source_file,
        "inferred_tainted_inputs": [t.model_dump() for t in inferred],
        "prototype_args": [{"c_type": c, "name": n} for c, n in parsed],
    }


@mcp.tool()
def generate_harness_tool(
    source_file: str,
    function_name: str,
    cwe: str,
    tainted_inputs: Optional[list[dict[str, Any]]] = None,
    assumptions: Optional[list[str]] = None,
    loop_bounds: Optional[dict[str, int]] = None,
    use_bounds: bool = False,
) -> dict:
    """Build a KLEE harness from an explicit taint spec. Prefer auto_harness
    for a quick start; use this tool when you want to supply the taints
    yourself (e.g. to declare a pointer parameter NULL via size_bytes=0).

    If `use_bounds` is True, each item in `assumptions` is pasted inside a
    `klee_assume(...)` call, and each {var: N} in `loop_bounds` is emitted
    as `klee_assume(var <= N)`. With `use_bounds=False` both are ignored.
    """
    req = VerifyRequest(
        source_file=source_file,
        cwe=CWE(cwe),
        function_name=function_name,
        tainted_inputs=_coerce_taints(tainted_inputs),
        assumptions=assumptions or [],
        loop_bounds=loop_bounds or {},
        use_bounds=use_bounds,
    )
    harness_c = generate_harness(req)
    return {
        "harness_c": harness_c,
        "function": function_name,
        "source_file": source_file,
        "bounds_applied": bool(use_bounds and (assumptions or loop_bounds)),
    }


@mcp.tool()
def verify_vulnerability(
    source_file: str,
    function_name: str,
    cwe: str,
    sink_line: Optional[int] = None,
    tainted_inputs: Optional[list[dict[str, Any]]] = None,
    assumptions: Optional[list[str]] = None,
    loop_bounds: Optional[dict[str, int]] = None,
    use_bounds: bool = False,
    auto_relax_on_infeasible: bool = False,
    extra_sources: Optional[list[str]] = None,
    include_dirs: Optional[list[str]] = None,
    defines: Optional[list[str]] = None,
    timeout_s: int = 60,
    max_memory_mb: int = 2000,
) -> dict:
    """Validate a candidate vulnerability with KLEE.

    Core arguments:
      source_file       Absolute path to the .c / .cpp file.
      function_name     Function to drive symbolically.
      cwe               Token from list_supported_cwes.
      tainted_inputs    [{name, c_type, size_bytes?, is_pointer?,
                         null_terminate?}]. If omitted, every parameter of
                        function_name is made symbolic with default sizes.

    LLM bounds (optimisation, all opt-in):
      assumptions       List of C expressions to wrap in klee_assume(...).
                        e.g. ["len <= 64", "mode < 4"]. Only applied when
                        use_bounds is True.
      loop_bounds       Dict {var: N} sugar for klee_assume(var <= N).
                        Useful when the LLM can tell you a loop driven by
                        `count` never realistically exceeds N. Only applied
                        when use_bounds is True.
      use_bounds        Master switch. Default False (LLM bounds ignored).
                        Turn on for the fast/tight run.
      auto_relax_on_infeasible
                        When True AND the bounded run returns 'infeasible',
                        the server automatically retries once with
                        use_bounds=False. The final verdict reflects the
                        retry; the bounded verdict is preserved in
                        `initial_verdict`. When False (default), the server
                        returns the bounded verdict as-is and sets
                        `retry_suggestion` hinting that the LLM may want to
                        call again with bounds relaxed.

    Build:
      extra_sources, include_dirs, defines, timeout_s, max_memory_mb.

    Returns VerifyResponse (see models.py). Key fields:
      verdict            confirmed | infeasible | timeout | build_failed | klee_error
      bounds_applied     whether LLM bounds were used for this run
      initial_verdict    if auto-relaxed, the bounded verdict
      retry_suggestion   human-readable hint for the LLM caller
      concrete_input_hex hex dump of the .ktest input if confirmed
    """
    req = VerifyRequest(
        source_file=source_file,
        cwe=CWE(cwe),
        function_name=function_name,
        sink_line=sink_line,
        tainted_inputs=_coerce_taints(tainted_inputs),
        assumptions=assumptions or [],
        loop_bounds=loop_bounds or {},
        use_bounds=use_bounds,
        auto_relax_on_infeasible=auto_relax_on_infeasible,
        extra_sources=extra_sources or [],
        include_dirs=include_dirs or [],
        defines=defines or [],
        timeout_s=timeout_s,
        max_memory_mb=max_memory_mb,
    )
    log.info(
        "verify_vulnerability: cwe=%s fn=%s src=%s use_bounds=%s auto_relax=%s",
        req.cwe.value,
        req.function_name,
        req.source_file,
        req.use_bounds,
        req.auto_relax_on_infeasible,
    )
    resp = verify_with_retry(req)
    return resp.model_dump(mode="json")


@mcp.tool()
def check_reachability_tool(
    source_file: str,
    entry_function: str,
    target_function: str,
    tainted_inputs: Optional[list[dict[str, Any]]] = None,
    assumptions: Optional[list[str]] = None,
    loop_bounds: Optional[dict[str, int]] = None,
    use_bounds: bool = False,
    extra_sources: Optional[list[str]] = None,
    include_dirs: Optional[list[str]] = None,
    defines: Optional[list[str]] = None,
    timeout_s: int = 60,
    max_memory_mb: int = 2000,
) -> dict:
    """Phase 2 reachability check: is `target_function` reachable from
    `entry_function`?

    The server patches a *copy* of the source file to prepend
    `klee_report_error(...)` to target_function, drives entry_function
    symbolically, and asks KLEE whether control reaches the probe. This
    is LLM-guided reachability — the caller picks an `entry_function`
    that is plausibly reachable from real external input (an exported
    API, a request handler, a parser root), not main. That keeps path
    explosion bounded while still giving a meaningful reachability
    story for the paper.

    Returns ReachabilityResponse. verdict ∈ {reached, not_reached,
    timeout, build_failed, klee_error}. On 'reached', concrete_input_hex
    is the entry_function input that drives execution to target_function.
    """
    req = ReachabilityRequest(
        source_file=source_file,
        entry_function=entry_function,
        target_function=target_function,
        tainted_inputs=_coerce_taints(tainted_inputs),
        assumptions=assumptions or [],
        loop_bounds=loop_bounds or {},
        use_bounds=use_bounds,
        extra_sources=extra_sources or [],
        include_dirs=include_dirs or [],
        defines=defines or [],
        timeout_s=timeout_s,
        max_memory_mb=max_memory_mb,
    )
    log.info(
        "check_reachability: src=%s %s -> %s use_bounds=%s",
        req.source_file,
        req.entry_function,
        req.target_function,
        req.use_bounds,
    )
    resp = check_reachability(req)
    return resp.model_dump(mode="json")


@mcp.tool()
def emit_reproducer(
    source_file: str,
    function_name: str,
    cwe: str,
    tainted_inputs: list[dict[str, Any]],
    parsed_inputs: dict[str, dict[str, Any]],
    out_dir: str,
    sink_line: Optional[int] = None,
) -> dict:
    """Write a standalone reproducer for a confirmed vulnerability.

    Produces:
      - `<out_dir>/reproduce.c`: self-contained C program that inlines
        the KLEE-synthesised concrete values and calls the vulnerable
        function. Compile with gcc -fsanitize=address to see the error.
      - `<out_dir>/poc.bin`: raw bytes of the primary pointer taint
        (if any), for byte-oriented consumers (`./reproduce < poc.bin`
        integrations, fuzz corpora).
      - `<out_dir>/<source_basename>`: a copy of the target source so
        the reproducer is fully self-contained.

    Intended workflow: after a verify_vulnerability call returns
    verdict=="confirmed", pass its parsed_inputs (plus the candidate's
    tainted_inputs and source_file) to this tool to emit
    disclosure-ready artefacts. The returned dict includes a
    run_recipe you can paste into a vendor advisory.
    """
    req = VerifyRequest(
        source_file=source_file,
        cwe=CWE(cwe),
        function_name=function_name,
        sink_line=sink_line,
        tainted_inputs=_coerce_taints(tainted_inputs),
    )
    produced = _emit_reproducer(req, parsed_inputs, Path(out_dir))
    return produced


def main() -> None:
    """Entry point for `python -m symex_mcp.server`."""
    mcp.run()


if __name__ == "__main__":
    main()
