"""Decode KLEE .ktest files and emit standalone reproducers.

A confirmed verdict carries a .ktest file (binary) with one symbolic
object per klee_make_symbolic call in the harness. We shell out to
the container's `ktest-tool` to decode it into per-variable values,
then emit:

  - reproduce.c: a self-contained C program with concrete values
    inlined, no KLEE dependency; compiles with gcc -fsanitize=address.
  - poc.bin: raw bytes of the primary symbolic buffer (if any), so
    byte-oriented harnesses can `./reproduce < poc.bin`.

These artefacts are what a vulnerability coordinator wants to hand to
a vendor: the function, the concrete trigger, the compile/run recipe.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

from .klee_runner import CONTAINER_CMD, KLEE_IMAGE
from .models import TaintedInput, VerifyRequest


_OBJECT_RE = re.compile(
    r"^object (\d+): (name|size|data|hex|int|uint|text): (.*)$"
)


def decode_ktest(ktest_abs_path: Path) -> dict[str, dict[str, Any]]:
    """Run ktest-tool in the container; parse into {name: {size, hex, int?}}.

    The ktest file must exist on the host. We bind-mount its parent dir
    read-only and invoke ktest-tool. Empty dict on failure.
    """
    if not ktest_abs_path.exists():
        return {}
    parent = ktest_abs_path.parent.resolve()
    name = ktest_abs_path.name
    cmd = [
        CONTAINER_CMD,
        "run",
        "--rm",
        "--userns=keep-id",
        "-v",
        f"{parent}:/t:Z,ro",
        KLEE_IMAGE,
        "ktest-tool",
        f"/t/{name}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}
    if proc.returncode != 0:
        return {}
    return _parse_ktest_tool_output(proc.stdout)


def _parse_ktest_tool_output(text: str) -> dict[str, dict[str, Any]]:
    """ktest-tool emits per-object lines like:
        object 0: name: 'buf'
        object 0: size: 16
        object 0: data: b'\\x00\\x01...'
        object 0: hex : 0x000100...
        object 0: int : 42
        object 0: uint: 42
        object 0: text: "..."
    """
    by_index: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        m = _OBJECT_RE.match(line)
        if not m:
            continue
        idx = int(m.group(1))
        key = m.group(2).strip()
        val = m.group(3).strip()
        obj = by_index.setdefault(idx, {})
        if key == "name":
            obj["name"] = val.strip("'\"")
        elif key == "size":
            obj["size"] = int(val)
        elif key == "data":
            # Value looks like: b'\\x00\\x01B'
            try:
                raw = ast.literal_eval(val)
                if isinstance(raw, bytes):
                    obj["hex"] = raw.hex()
                    obj["bytes"] = list(raw)
            except (SyntaxError, ValueError):
                obj["hex"] = ""
                obj["bytes"] = []
        elif key == "hex":
            obj["hex_str"] = val
        elif key == "int":
            try:
                obj["int"] = int(val)
            except ValueError:
                pass
        elif key == "uint":
            try:
                obj["uint"] = int(val)
            except ValueError:
                pass
        elif key == "text":
            obj["text"] = val
    # Re-key by name for caller convenience.
    out: dict[str, dict[str, Any]] = {}
    for obj in by_index.values():
        if "name" in obj:
            out[obj["name"]] = obj
    return out


def _c_array_init(byte_values: list[int]) -> str:
    """Format a list of byte ints as `{ 0xXX, 0xXX, ... }`."""
    if not byte_values:
        return "{0}"
    parts = [f"0x{b:02x}" for b in byte_values]
    lines = []
    for i in range(0, len(parts), 16):
        lines.append(", ".join(parts[i : i + 16]))
    return "{\n        " + ",\n        ".join(lines) + "\n    }"


def _pretty_int(obj: dict[str, Any]) -> Optional[int]:
    """Return the integer interpretation of a scalar-sized object, else None."""
    if "int" in obj:
        return obj["int"]
    if "uint" in obj:
        return obj["uint"]
    # Fall back to little-endian decode of up to 8 bytes.
    b = obj.get("bytes") or []
    if 0 < len(b) <= 8:
        n = 0
        for i, v in enumerate(b):
            n |= (v & 0xFF) << (8 * i)
        return n
    return None


def emit_reproducer(
    request: VerifyRequest,
    parsed_inputs: dict[str, dict[str, Any]],
    out_dir: Path,
    source_included_name: Optional[str] = None,
) -> dict[str, str]:
    """Write reproduce.c (+ optional poc.bin) to out_dir.

    reproduce.c inlines concrete values from parsed_inputs and calls the
    target function. Pointer taints become `unsigned char name[N]` with
    the byte sequence from the .ktest; scalar taints become literals.

    Returns a dict with paths of the produced files and a short "run
    recipe" string for the report.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    source = Path(request.source_file)
    source_name = source_included_name or source.name

    # Re-parse the target function prototype to know the parameter list
    # (so we don't miss args that weren't declared as taints).
    from .harness_gen import extract_prototype, parse_args

    source_text = source.read_text(errors="replace")
    proto = extract_prototype(source_text, request.function_name)
    if proto is None:
        raise ValueError(f"function {request.function_name} not found in {source}")
    _, args_str = proto
    parsed_args = parse_args(args_str)

    taint_by_name = {t.name: t for t in request.tainted_inputs}

    decls: list[str] = []
    call_args: list[str] = []
    poc_bytes: Optional[bytes] = None
    poc_var: Optional[str] = None

    for ctype, name in parsed_args:
        t = taint_by_name.get(name)
        obj = parsed_inputs.get(name)

        if t is not None and t.is_pointer and t.size_bytes == 0:
            # NULL pointer taint.
            decls.append(f"    {ctype.strip()} {name} = 0;")
            call_args.append(name)
            continue

        if t is not None and t.is_pointer:
            # Buffer taint. Use concrete bytes from parsed_inputs if present,
            # otherwise zero-fill.
            decl_ctype = (t.c_type or ctype).strip()
            base = re.sub(r"\*\s*$", "", decl_ctype).strip()
            if base == decl_ctype and "*" not in decl_ctype:
                base = "char" if "char" in decl_ctype or decl_ctype.endswith("charp") else "unsigned char"
            if not base:
                base = "char"
            n = max(1, int(t.size_bytes))
            bytes_val = (obj or {}).get("bytes") or [0] * n
            # Right-pad to declared size so the array size matches the harness.
            if len(bytes_val) < n:
                bytes_val = bytes_val + [0] * (n - len(bytes_val))
            init = _c_array_init(bytes_val[:n])
            decls.append(f"    {base} {name}[{n}] = {init};")
            call_args.append(name)
            if poc_bytes is None:
                poc_bytes = bytes(bytes_val[:n])
                poc_var = name
            continue

        # Scalar: emit a literal initialiser.
        literal = "0"
        if obj is not None:
            v = _pretty_int(obj)
            if v is not None:
                literal = f"{v}u" if "unsigned" in ctype or "uint" in ctype or "size_t" in ctype else str(v)
        decls.append(f"    {ctype.strip()} {name} = {literal};")
        call_args.append(name)

    # Harness body.
    body = "\n".join(decls) if decls else "    /* no symbolic inputs */"
    call_line = f"{request.function_name}({', '.join(call_args)});"

    header = f"""/* Auto-generated reproducer for {request.function_name}
 * in {source_name} (CWE: {request.cwe.value}, sink line: {request.sink_line}).
 *
 * Compile with:
 *   gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 \\
 *       reproduce.c {source_name} -o reproduce
 * Run:
 *   ./reproduce
 * Expected: AddressSanitizer reports a memory error matching the CWE.
 *
 * Values were produced by KLEE {source_name}-driven symbolic execution
 * and are byte-for-byte the inputs that trigger the vulnerability.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Pull in the vulnerable TU. If the target ships only as a library,
 * delete this include and link against the real library instead. */
#include "{source_name}"

int main(void) {{
    fprintf(stderr, "[reproducer] calling {request.function_name} with KLEE-synthesised inputs\\n");
{body}
    {call_line}
    fprintf(stderr, "[reproducer] returned normally; run under ASan to see the error\\n");
    return 0;
}}
"""

    c_path = out_dir / "reproduce.c"
    c_path.write_text(header)

    out: dict[str, str] = {"reproduce_c": str(c_path)}

    if poc_bytes is not None:
        bin_path = out_dir / "poc.bin"
        bin_path.write_bytes(poc_bytes)
        out["poc_bin"] = str(bin_path)
        out["poc_variable"] = poc_var or ""

    # Also stage a copy of the source so reproduce.c is self-contained.
    target_src_copy = out_dir / source.name
    if not target_src_copy.exists():
        target_src_copy.write_text(source_text)
    out["source_copy"] = str(target_src_copy)

    run_recipe = (
        f"cd {out_dir} && "
        f"gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 "
        f"reproduce.c {source.name} -o reproduce && "
        f"./reproduce"
    )
    out["run_recipe"] = run_recipe

    return out
