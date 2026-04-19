"""Phase 2: LLM-guided reachability check.

Given an entry function and a target function in the same translation
unit, check whether any path from the entry function reaches the target.
We instrument the target by prepending `klee_report_error(...)` to its
body, then run KLEE with --exit-on-error-type=ReportError so the first
reaching path aborts cleanly. Presence of a test case whose error is
'reachability_probe' means REACHED; clean completion within the time
budget means NOT_REACHED.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .harness_gen import (
    _infer_taints,
    _split_args,
    extract_prototype,
    parse_args,
)
from .klee_runner import (
    CONTAINER_CMD,
    KLEE_IMAGE,
    _container_invoke,
    _find_klee_out,
    _ktest_to_hex,
    _parse_klee_errors,
    _tail,
)
from .models import (
    ReachabilityRequest,
    ReachabilityResponse,
    ReachabilityVerdict,
    TaintedInput,
    VerifyRequest,
)


_REACH_TAG = "reachability_probe"


def _patch_source(source_text: str, target_function: str) -> tuple[str, bool]:
    """Insert `klee_report_error(...)` at the top of target_function's body.

    We match `ret-type name(args) {` and splice right after the `{`.
    Returns (patched_text, did_patch).
    """
    # Use the same permissive prototype regex as harness_gen, but we need
    # the opening brace position. Find a function-like definition whose
    # name is target_function.
    pattern = re.compile(
        r"(?P<head>"
        r"[\w\s\*]+?\b" + re.escape(target_function) + r"\s*\([^)]*\)\s*"
        r")"
        r"(?P<brace>\{)",
        re.MULTILINE,
    )
    m = pattern.search(source_text)
    if not m:
        return source_text, False

    # klee_report_error(file, line, message, suffix). The `suffix` becomes
    # the error-file extension; we want the standard `.err` so our existing
    # glob picks it up. The `message` goes into the file body, tagged with
    # _REACH_TAG and the target name so we can distinguish reachability
    # probes from genuine bugs if both fire.
    probe = (
        f'\n    klee_report_error(__FILE__, __LINE__, '
        f'"{_REACH_TAG} target={target_function}", "err");\n'
    )
    # Also ensure klee/klee.h is included. Prepend if missing.
    if "klee/klee.h" not in source_text:
        source_text = '#include <klee/klee.h>\n' + source_text
        # recompute match positions on the new string
        m = pattern.search(source_text)
        assert m is not None  # we only prepended; the match must still exist

    brace_end = m.end("brace")
    patched = source_text[:brace_end] + probe + source_text[brace_end:]
    return patched, True


def _build_entry_harness(
    req: ReachabilityRequest, patched_source_name: str
) -> str:
    """Harness that drives req.entry_function with symbolic params.

    Mirrors harness_gen.generate_harness but targets entry_function and
    includes the *patched* source file (the one with the probe).
    """
    source_path = Path(req.source_file)
    source_text = source_path.read_text(errors="replace")

    proto = extract_prototype(source_text, req.entry_function)
    if proto is None:
        raise ValueError(
            f"entry_function '{req.entry_function}' not found in {req.source_file}"
        )
    _, args_str = proto
    parsed_args = parse_args(args_str)
    taints = _infer_taints(parsed_args, req.tainted_inputs)
    taint_by_name = {t.name: t for t in taints}

    decls: list[str] = []
    call_args: list[str] = []
    for ctype, name in parsed_args:
        t = taint_by_name.get(name)
        if t is None:
            decls.append(f"    {ctype.strip()} {name} = 0;")
            call_args.append(name)
            continue
        if t.is_pointer:
            if t.size_bytes == 0:
                decls.append(f"    {ctype.strip()} {name} = 0;")
            else:
                base = re.sub(r"\*\s*$", "", ctype).strip() or "char"
                n = max(1, int(t.size_bytes))
                decls.append(f"    {base} {name}[{n}];")
                decls.append(
                    f'    klee_make_symbolic({name}, sizeof({name}), "{name}");'
                )
                if t.null_terminate:
                    decls.append(f"    {name}[{n - 1}] = 0;")
            call_args.append(name)
        else:
            decls.append(f"    {ctype.strip()} {name};")
            decls.append(
                f'    klee_make_symbolic(&{name}, sizeof({name}), "{name}");'
            )
            call_args.append(name)

    assume_stmts: list[str] = []
    if req.use_bounds:
        for expr in req.assumptions:
            expr = expr.strip().rstrip(";")
            if expr:
                assume_stmts.append(f"    klee_assume({expr});")
        for var, bound in req.loop_bounds.items():
            assume_stmts.append(f"    klee_assume({var} <= {int(bound)});")
    if assume_stmts:
        decls.append("    /* LLM-supplied bounds (opt-in via use_bounds) */")
        decls.extend(assume_stmts)

    body = "\n".join(decls)
    call = f"{req.entry_function}({', '.join(call_args)});"
    return f"""/* AUTO-GENERATED reachability harness: {req.entry_function} -> {req.target_function} */
#include <klee/klee.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "{patched_source_name}"

int main(void) {{
{body}
    {call}
    return 0;
}}
"""


def check_reachability(req: ReachabilityRequest) -> ReachabilityResponse:
    source = Path(req.source_file)
    if not source.exists():
        return ReachabilityResponse(
            verdict=ReachabilityVerdict.BUILD_FAILED,
            source_file=str(source),
            entry_function=req.entry_function,
            target_function=req.target_function,
            notes=f"source file not found: {source}",
        )

    scratch = Path(tempfile.mkdtemp(prefix="symex-reach-"))

    # Patch the target in a copy of the source.
    original = source.read_text(errors="replace")
    patched, did_patch = _patch_source(original, req.target_function)
    if not did_patch:
        return ReachabilityResponse(
            verdict=ReachabilityVerdict.BUILD_FAILED,
            source_file=str(source),
            entry_function=req.entry_function,
            target_function=req.target_function,
            notes=f"could not locate definition of {req.target_function}()",
        )
    patched_path = scratch / source.name
    patched_path.write_text(patched)

    for extra in req.extra_sources:
        p = Path(extra)
        if p.exists():
            shutil.copy2(p, scratch / p.name)

    try:
        harness_c = _build_entry_harness(req, source.name)
    except Exception as exc:
        return ReachabilityResponse(
            verdict=ReachabilityVerdict.BUILD_FAILED,
            source_file=str(source),
            entry_function=req.entry_function,
            target_function=req.target_function,
            harness_path=None,
            patched_source_path=str(patched_path),
            notes=f"harness generation failed: {exc}",
        )

    harness_path = scratch / "harness.c"
    harness_path.write_text(harness_c)

    defines = " ".join(f"-D{d}" for d in req.defines)
    includes = " ".join(f"-I{p}" for p in req.include_dirs)
    inner = f"""
set -e
cd /work
clang -I. {includes} {defines} \\
    -emit-llvm -c -g -O0 \\
    -Xclang -disable-O0-optnone \\
    -Wno-everything \\
    harness.c -o harness.bc
klee \\
    --only-output-states-covering-new \\
    --max-time={req.timeout_s}s \\
    --max-memory={req.max_memory_mb} \\
    --exit-on-error-type=ReportError \\
    --libc=uclibc --posix-runtime \\
    harness.bc || true
"""
    t0 = time.time()
    try:
        proc = _container_invoke(scratch, inner, req.timeout_s)
    except subprocess.TimeoutExpired as te:
        return ReachabilityResponse(
            verdict=ReachabilityVerdict.TIMEOUT,
            source_file=str(source),
            entry_function=req.entry_function,
            target_function=req.target_function,
            harness_path=str(harness_path),
            patched_source_path=str(patched_path),
            stdout_tail=_tail(
                (te.stdout or b"").decode("utf-8", errors="replace")
                if isinstance(te.stdout, (bytes, bytearray))
                else (te.stdout or "")
            ),
            stderr_tail=_tail(
                (te.stderr or b"").decode("utf-8", errors="replace")
                if isinstance(te.stderr, (bytes, bytearray))
                else (te.stderr or "")
            ),
            wall_seconds=time.time() - t0,
            bounds_applied=bool(req.use_bounds and (req.assumptions or req.loop_bounds)),
            notes="container wall-clock timeout",
        )
    wall = time.time() - t0
    stdout, stderr = proc.stdout or "", proc.stderr or ""

    klee_out = _find_klee_out(scratch)
    if klee_out is None:
        build_failed = "error:" in stderr.lower() or "fatal error" in stderr.lower()
        return ReachabilityResponse(
            verdict=(
                ReachabilityVerdict.BUILD_FAILED if build_failed else ReachabilityVerdict.KLEE_ERROR
            ),
            source_file=str(source),
            entry_function=req.entry_function,
            target_function=req.target_function,
            harness_path=str(harness_path),
            patched_source_path=str(patched_path),
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
            wall_seconds=wall,
            bounds_applied=bool(req.use_bounds and (req.assumptions or req.loop_bounds)),
            notes="no klee-out-* directory produced",
        )

    errors = _parse_klee_errors(klee_out)
    # Reached iff any error test mentions our probe tag.
    reached = False
    first_ktest = None
    for e in errors:
        if _REACH_TAG in e.get("full", "") or _REACH_TAG in e.get("message", ""):
            reached = True
            if e.get("ktest"):
                first_ktest = klee_out / e["ktest"]
            break
    hex_input = _ktest_to_hex(first_ktest) if first_ktest else None

    if reached:
        verdict = ReachabilityVerdict.REACHED
        notes = f"KLEE reached {req.target_function} from {req.entry_function}"
    else:
        timed_out = (
            "HaltTimer invoked" in stdout
            or "KLEE: HaltTimer invoked" in stderr
            or (f"max-time" in stderr and wall >= req.timeout_s * 0.9)
        )
        verdict = (
            ReachabilityVerdict.TIMEOUT if timed_out else ReachabilityVerdict.NOT_REACHED
        )
        notes = (
            "KLEE exhausted paths without reaching the target"
            if not timed_out
            else "KLEE hit max-time before finishing"
        )

    return ReachabilityResponse(
        verdict=verdict,
        source_file=str(source),
        entry_function=req.entry_function,
        target_function=req.target_function,
        concrete_input_hex=hex_input,
        ktest_path=str(first_ktest) if first_ktest else None,
        harness_path=str(harness_path),
        patched_source_path=str(patched_path),
        stdout_tail=_tail(stdout),
        stderr_tail=_tail(stderr),
        wall_seconds=wall,
        bounds_applied=bool(req.use_bounds and (req.assumptions or req.loop_bounds)),
        notes=notes,
    )
