"""Drive KLEE inside a podman container and parse its verdict.

The container runs the official klee/klee image. We bind-mount a scratch
work dir (containing the original source, the generated harness, and a
build script) into /work, then exec the pipeline:
    clang -I/work -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone \
        -Wno-everything harness.c -o harness.bc
    klee --libc=uclibc --posix-runtime --only-output-states-covering-new \
        --exit-on-error-type=... harness.bc

KLEE writes results under /work/klee-out-N. We copy them back onto the
host scratch dir (they live there already via the bind mount), parse any
*.err files to extract the verdict, and return.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .models import CWE, VerifyRequest, VerifyResponse, VerifyVerdict


KLEE_IMAGE = os.environ.get("SYMEX_KLEE_IMAGE", "docker.io/klee/klee:3.1")
CONTAINER_CMD = os.environ.get("SYMEX_CONTAINER_CMD", "podman")


# Map CWE -> KLEE exit-on-error-type tokens. KLEE groups errors as:
#   ptr, assert, div, overflow, readonly, user, unhandled, model, execerr, ...
CWE_TO_KLEE_ERRS: dict[CWE, list[str]] = {
    CWE.STACK_BOF: ["Ptr"],
    CWE.HEAP_BOF: ["Ptr"],
    CWE.OOB_WRITE: ["Ptr"],
    CWE.OOB_READ: ["Ptr"],
    CWE.NULL_DEREF: ["Ptr"],
    # UAF reads/writes surface as Ptr errors under KLEE's memory model.
    CWE.UAF: ["Ptr", "Free"],
    CWE.DOUBLE_FREE: ["Free"],
    # Integer overflow: the overflow itself requires overflow intrinsics,
    # but the downstream consequence (e.g. OOB write via wrapped size) is a
    # Ptr error. We accept either.
    CWE.INT_OVERFLOW: ["Overflow", "Ptr"],
    CWE.DIV_BY_ZERO: ["Ptr"],
    CWE.OTHER: ["Ptr", "Assert", "Overflow", "Free"],
}


def _tail(text: str, n: int = 4000) -> str:
    return text[-n:] if len(text) > n else text


def _container_invoke(workdir: Path, inner_cmd: str, timeout_s: int) -> subprocess.CompletedProcess:
    """Run `inner_cmd` (a /bin/sh string) inside the klee container."""
    # :Z for SELinux relabel; harmless on non-SELinux systems.
    volume_flag = f"{workdir}:/work:Z"
    cmd = [
        CONTAINER_CMD,
        "run",
        "--rm",
        "--userns=keep-id",
        "-v",
        volume_flag,
        "-w",
        "/work",
        KLEE_IMAGE,
        "/bin/bash",
        "-lc",
        inner_cmd,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=False,
        timeout=timeout_s + 30,
    )
    # Some KLEE runs emit bytes that aren't valid UTF-8 (e.g. binary data
    # from crashed symbolic states). Decode with replace so we don't lose
    # the whole run to a single bad byte.
    proc.stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
    proc.stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    return proc


def _find_klee_out(workdir: Path) -> Path | None:
    """Return the path of the most recent klee-out-* directory, if any."""
    candidates = sorted(
        workdir.glob("klee-out-*"),
        key=lambda p: p.stat().st_mtime,
    )
    return candidates[-1] if candidates else None


def _parse_klee_errors(klee_out: Path) -> list[dict]:
    """Each *.err file in klee-out-N describes one discovered error."""
    errors = []
    for err in klee_out.glob("*.err"):
        content = err.read_text(errors="replace")
        ktest = err.with_suffix("").with_suffix(".ktest")
        errors.append(
            {
                "err_file": err.name,
                "err_kind": _infer_err_kind(err.name),
                "message": content.splitlines()[0] if content else "",
                "full": content,
                "ktest": ktest.name if ktest.exists() else None,
            }
        )
    return errors


def _infer_err_kind(filename: str) -> str:
    """KLEE names error files like 'test000001.ptr.err', 'test000002.overflow.err'."""
    parts = filename.split(".")
    if len(parts) >= 3:
        return parts[-2]
    return "unknown"


def _ktest_to_hex(ktest_path: Path) -> str:
    """Decode a KLEE .ktest binary into a hex dump of each object's payload.

    The .ktest format is documented in KLEE sources; rather than reimplement
    the parser, we just hex-dump the raw bytes — good enough for a report
    and for reproducing the crash by feeding the bytes back.
    """
    try:
        raw = ktest_path.read_bytes()
    except OSError:
        return ""
    return raw.hex()


def run_klee(
    req: VerifyRequest,
    harness_c: str,
) -> VerifyResponse:
    """Compile harness + run KLEE in a container. Returns a structured verdict."""
    source = Path(req.source_file)
    if not source.exists():
        return VerifyResponse(
            verdict=VerifyVerdict.BUILD_FAILED,
            cwe=req.cwe,
            source_file=str(source),
            function_name=req.function_name,
            sink_line=req.sink_line,
            notes=f"source file not found: {source}",
        )

    scratch = Path(tempfile.mkdtemp(prefix="symex-"))
    try:
        # stage source + any extra TUs
        shutil.copy2(source, scratch / source.name)
        for extra in req.extra_sources:
            p = Path(extra)
            if p.exists():
                shutil.copy2(p, scratch / p.name)

        # stage pre-built bitcodes (whole-library .bc files)
        staged_bcs: list[str] = []
        for bc in req.extra_bitcodes:
            p = Path(bc)
            if not p.exists():
                return VerifyResponse(
                    verdict=VerifyVerdict.BUILD_FAILED,
                    cwe=req.cwe,
                    source_file=str(source),
                    function_name=req.function_name,
                    sink_line=req.sink_line,
                    notes=f"extra_bitcode not found: {p}",
                )
            dest = scratch / p.name
            shutil.copy2(p, dest)
            staged_bcs.append(p.name)

        harness_path = scratch / "harness.c"
        harness_path.write_text(harness_c)

        err_types_list = CWE_TO_KLEE_ERRS.get(req.cwe, ["Ptr"])
        exit_flags = " ".join(f"--exit-on-error-type={e}" for e in err_types_list)
        defines = " ".join(f"-D{d}" for d in req.defines)
        includes = " ".join(f"-I{p}" for p in req.include_dirs)

        # If we were given extra bitcodes, llvm-link harness + extras into a
        # single linked.bc and hand that to KLEE. Otherwise run KLEE on
        # harness.bc directly (Phase-1 small-TU mode).
        if staged_bcs:
            link_cmd = f"llvm-link harness.bc {' '.join(staged_bcs)} -o linked.bc"
            klee_input = "linked.bc"
        else:
            link_cmd = "true"
            klee_input = "harness.bc"

        inner = f"""
set -e
cd /work
clang -I. {includes} {defines} \\
    -emit-llvm -c -g -O0 \\
    -Xclang -disable-O0-optnone \\
    -Wno-everything \\
    harness.c -o harness.bc
{link_cmd}
klee \\
    --only-output-states-covering-new \\
    --max-time={req.timeout_s}s \\
    --max-memory={req.max_memory_mb} \\
    {exit_flags} \\
    --libc=uclibc --posix-runtime \\
    {klee_input} || true
ls -1d klee-out-* 2>/dev/null | tail -n1 > /work/.last_out
"""
        t0 = time.time()
        try:
            proc = _container_invoke(scratch, inner, req.timeout_s)
        except subprocess.TimeoutExpired as te:
            te_stdout = te.stdout or b""
            te_stderr = te.stderr or b""
            if isinstance(te_stdout, bytes):
                te_stdout = te_stdout.decode("utf-8", errors="replace")
            if isinstance(te_stderr, bytes):
                te_stderr = te_stderr.decode("utf-8", errors="replace")
            return VerifyResponse(
                verdict=VerifyVerdict.TIMEOUT,
                cwe=req.cwe,
                source_file=str(source),
                function_name=req.function_name,
                sink_line=req.sink_line,
                stdout_tail=_tail(te_stdout),
                stderr_tail=_tail(te_stderr),
                harness_path=str(harness_path),
                wall_seconds=time.time() - t0,
                notes="container wall-clock timeout",
            )
        wall = time.time() - t0

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # build failure is easy to detect: no klee-out-* and clang errored.
        klee_out = _find_klee_out(scratch)
        if klee_out is None:
            # If clang failed, stderr will mention 'error:'.
            build_failed = "error:" in stderr.lower() or "fatal error" in stderr.lower()
            return VerifyResponse(
                verdict=(
                    VerifyVerdict.BUILD_FAILED if build_failed else VerifyVerdict.KLEE_ERROR
                ),
                cwe=req.cwe,
                source_file=str(source),
                function_name=req.function_name,
                sink_line=req.sink_line,
                stdout_tail=_tail(stdout),
                stderr_tail=_tail(stderr),
                harness_path=str(harness_path),
                wall_seconds=wall,
                notes="no klee-out-* directory produced",
            )

        # Lazy import to avoid a circular dependency: reproducer imports
        # CONTAINER_CMD from this module.
        from .reproducer import decode_ktest

        all_errors = _parse_klee_errors(klee_out)
        # Only errors whose kind matches this CWE's expected error class
        # count as bug confirmations. `abort`, `model`, `user` etc. are
        # side-effects (libpng's own error path calling abort, KLEE memory
        # cap exhaustion, etc.) and must NOT be reported as confirmed.
        expected_kinds = {k.lower() for k in CWE_TO_KLEE_ERRS.get(req.cwe, ["Ptr"])}
        errors = [e for e in all_errors if e.get("err_kind", "").lower() in expected_kinds]
        ignored = [e for e in all_errors if e not in errors]
        if errors:
            first_ktest = None
            for e in errors:
                if e.get("ktest"):
                    first_ktest = klee_out / e["ktest"]
                    break
            hex_input = _ktest_to_hex(first_ktest) if first_ktest else None
            parsed = decode_ktest(first_ktest) if first_ktest else {}
            from .exploitability import classify as classify_exploit
            exploit = classify_exploit(
                errors[0], req.cwe, source, all_matching_errors=errors
            ).model_dump()
            note = f"KLEE produced {len(errors)} error test(s) matching {sorted(expected_kinds)}"
            if ignored:
                ignored_kinds = sorted({e.get("err_kind", "?") for e in ignored})
                note += f"; ignored {len(ignored)} side-effect error(s) of kind(s) {ignored_kinds}"
            return VerifyResponse(
                verdict=VerifyVerdict.CONFIRMED,
                cwe=req.cwe,
                source_file=str(source),
                function_name=req.function_name,
                sink_line=req.sink_line,
                klee_errors=errors,
                concrete_input_hex=hex_input,
                ktest_path=str(first_ktest) if first_ktest else None,
                stdout_tail=_tail(stdout),
                stderr_tail=_tail(stderr),
                harness_path=str(harness_path),
                wall_seconds=wall,
                notes=note,
                parsed_inputs=parsed,
                exploitability=exploit,
            )

        # No errors found within budget: treat as infeasible unless we hit
        # the time cap, in which case the verdict is timeout.
        timed_out = (
            "HaltTimer invoked" in stdout
            or "KLEE: HaltTimer invoked" in stderr
            or f"max-time" in stderr and wall >= req.timeout_s * 0.9
        )
        return VerifyResponse(
            verdict=(VerifyVerdict.TIMEOUT if timed_out else VerifyVerdict.INFEASIBLE),
            cwe=req.cwe,
            source_file=str(source),
            function_name=req.function_name,
            sink_line=req.sink_line,
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
            harness_path=str(harness_path),
            wall_seconds=wall,
            bounds_applied=bool(req.use_bounds and (req.assumptions or req.loop_bounds)),
            notes=(
                "KLEE completed without reaching the target error class"
                if not timed_out
                else "KLEE hit max-time before finishing"
            ),
        )
    finally:
        # Leave scratch on disk for post-mortem; put a breadcrumb so callers
        # can find it from the response.
        pass


def verify_with_retry(req: VerifyRequest) -> VerifyResponse:
    """Top-level entry: runs verification, optionally retrying with bounds off.

    Policy:
      1. If the caller asked for bounds (use_bounds=True) and provided some,
         run once with them.
      2. If that run is INFEASIBLE and auto_relax_on_infeasible=True, rerun
         once with use_bounds=False. The final verdict reflects the relaxed
         run; initial_verdict and relaxed_retry_performed are set so the
         caller can see both.
      3. If bounded run is INFEASIBLE and auto_relax is False, add a
         retry_suggestion so the LLM-side caller knows what to try.
    """
    # Import here to avoid circular deps at import time.
    from .harness_gen import generate_harness

    harness_first = generate_harness(req)
    first = run_klee(req, harness_first)
    first.bounds_applied = bool(
        req.use_bounds and (req.assumptions or req.loop_bounds)
    )

    bounded_and_infeasible = (
        first.bounds_applied and first.verdict == VerifyVerdict.INFEASIBLE
    )

    if bounded_and_infeasible and req.auto_relax_on_infeasible:
        relaxed_req = req.model_copy(update={"use_bounds": False})
        harness_relaxed = generate_harness(relaxed_req)
        second = run_klee(relaxed_req, harness_relaxed)
        second.bounds_applied = False
        second.initial_verdict = first.verdict
        second.relaxed_retry_performed = True
        second.notes = (
            f"Auto-relaxed retry. Bounded run was infeasible ({first.notes}). "
            f"Relaxed verdict: {second.verdict.value}. {second.notes}"
        )
        if second.verdict == VerifyVerdict.CONFIRMED:
            second.notes += (
                " [WARNING: LLM bounds ruled out the crashing input — bounds "
                "were too tight.]"
            )
        return second

    if bounded_and_infeasible and not req.auto_relax_on_infeasible:
        first.retry_suggestion = (
            "Bounded run was infeasible. The LLM-supplied assumptions may be "
            "too tight. Recommended next step: call verify_vulnerability again "
            "with use_bounds=False, or with relaxed assumptions. Alternatively "
            "set auto_relax_on_infeasible=True to let the server do this."
        )

    return first
