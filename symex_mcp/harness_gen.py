"""Generate a KLEE harness (wrapper main) for a target function.

The harness marks every declared tainted input symbolic with
klee_make_symbolic, optionally null-terminates buffers, and then calls the
target function. We keep it intentionally simple: per-parameter
klee_make_symbolic + a single call site. More complex sequences (stateful
APIs, multi-call protocols) are out of scope for phase 1.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import TaintedInput, VerifyRequest


_PROTOTYPE_RE = re.compile(
    r"""
    (?P<ret>[\w\s\*]+?)       # return type
    \s+
    (?P<name>\b{fname}\b)     # function name (injected)
    \s*\(
    (?P<args>[^)]*)           # args
    \)
    \s*(?:\{|;)
    """,
    re.VERBOSE,
)


def extract_prototype(source: str, function_name: str) -> tuple[str, str] | None:
    """Return (return_type, args_str) if function is defined in `source`."""
    pat = re.compile(
        _PROTOTYPE_RE.pattern.replace("{fname}", re.escape(function_name)),
        re.VERBOSE,
    )
    m = pat.search(source)
    if not m:
        return None
    return m.group("ret").strip(), m.group("args").strip()


def parse_args(args_str: str) -> list[tuple[str, str]]:
    """Crude C arg parser: returns list of (c_type, name)."""
    if not args_str or args_str.strip() == "void":
        return []
    out: list[tuple[str, str]] = []
    for raw in _split_args(args_str):
        raw = raw.strip()
        if not raw:
            continue
        # e.g. "const char *buf" -> type "const char *", name "buf"
        # Handle arrays: "char buf[64]" -> type "char *", name "buf"
        arr_match = re.match(r"(.+?)\s*(\w+)\s*\[[^\]]*\]$", raw)
        if arr_match:
            ctype = arr_match.group(1).strip() + " *"
            name = arr_match.group(2)
            out.append((ctype, name))
            continue
        # Split on last identifier
        m = re.match(r"(.+?[\s\*])(\w+)$", raw)
        if m:
            out.append((m.group(1).strip(), m.group(2)))
        else:
            # no explicit name (just a type) — synthesize
            out.append((raw, f"arg{len(out)}"))
    return out


def _split_args(args_str: str) -> list[str]:
    """Split on commas that aren't inside parens/angle brackets."""
    depth = 0
    cur = []
    out = []
    for ch in args_str:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _infer_taints(
    proto_args: list[tuple[str, str]], declared: list[TaintedInput]
) -> list[TaintedInput]:
    """If the caller didn't declare taints, synthesize one per parameter."""
    if declared:
        return declared
    inferred = []
    for ctype, name in proto_args:
        is_ptr = "*" in ctype or "[" in ctype
        inferred.append(
            TaintedInput(
                name=name,
                c_type=ctype,
                size_bytes=256 if is_ptr else _scalar_size(ctype),
                is_pointer=is_ptr,
                null_terminate=("char" in ctype and is_ptr),
            )
        )
    return inferred


def _scalar_size(ctype: str) -> int:
    t = ctype.replace("const", "").replace("volatile", "").strip()
    if "char" in t:
        return 1
    if "short" in t:
        return 2
    if "long long" in t or "int64" in t:
        return 8
    if "long" in t or "size_t" in t or "ssize_t" in t or "ptr" in t:
        return 8
    if "int" in t or "int32" in t:
        return 4
    if "double" in t:
        return 8
    if "float" in t:
        return 4
    return 4


def generate_harness(req: VerifyRequest) -> str:
    """Build a harness.c string that calls req.function_name with symbolic args.

    Strategy:
      - Include the original source via `#include "source.c"` so we get the
        function definition without having to re-declare it.
      - For each tainted input:
          - scalar: `T name; klee_make_symbolic(&name, sizeof(name), "name");`
          - pointer: `T buf[N]; klee_make_symbolic(buf, N, "name");`
                     optionally buf[N-1]=0 if null_terminate.
      - Call function_name(args...).
    """
    source_path = Path(req.source_file)
    source_text = source_path.read_text(errors="replace")

    proto = extract_prototype(source_text, req.function_name)
    if proto is None:
        raise ValueError(
            f"Could not find prototype of {req.function_name} in {req.source_file}"
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
            # Parameter not marked tainted: concretize to 0 / NULL.
            if "*" in ctype or "[" in ctype:
                decls.append(f"    {ctype.strip()} {name} = 0;")
            else:
                decls.append(f"    {ctype.strip()} {name} = 0;")
            call_args.append(name)
            continue

        if t.is_pointer:
            if t.size_bytes == 0:
                # Convention: size_bytes=0 on a pointer taint means "pass NULL".
                # Useful for CWE-476 harnesses where the bug is exercised by
                # the pointer being NULL, not by the buffer contents.
                decls.append(f"    {ctype.strip()} {name} = 0;")
                call_args.append(name)
            else:
                # Determine the element type for the symbolic buffer.
                # Prefer the caller's explicit c_type (they may have resolved
                # a typedef'd pointer to 'const char *'); otherwise use the
                # prototype ctype. Strip a trailing '*' to get the element
                # type. Fall back to 'char' if stripping yields nothing.
                decl_ctype = (t.c_type or ctype).strip()
                base = re.sub(r"\*\s*$", "", decl_ctype).strip()
                # If the type is a typedef of a pointer (e.g. png_const_charp
                # -> const char *), stripping '*' produces no change. We can't
                # resolve typedefs without a real C front-end, so fall back
                # to a raw byte buffer when the base looks pointer-ish but
                # lost its '*'.
                if base == decl_ctype and "*" not in decl_ctype:
                    # Heuristic: if the original type ends in 'charp', it's a
                    # libpng-style `char *` typedef -> use char.
                    if decl_ctype.endswith("charp") or "char" in decl_ctype:
                        base = "char"
                    else:
                        base = "unsigned char"
                if not base:
                    base = "char"
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

    # LLM-supplied bounds, only when the caller opts in. assumptions are raw
    # C expressions; loop_bounds are sugar for `var <= N`.
    assume_stmts: list[str] = []
    if getattr(req, "use_bounds", False):
        for expr in getattr(req, "assumptions", []):
            expr = expr.strip().rstrip(";")
            if expr:
                assume_stmts.append(f"    klee_assume({expr});")
        for var, bound in getattr(req, "loop_bounds", {}).items():
            assume_stmts.append(f"    klee_assume({var} <= {int(bound)});")

    if assume_stmts:
        decls.append("    /* LLM-supplied bounds (opt-in via use_bounds) */")
        decls.extend(assume_stmts)

    body = "\n".join(decls)
    call = f"{req.function_name}({', '.join(call_args)});"

    harness = f"""/* AUTO-GENERATED KLEE harness for {req.function_name} in {source_path.name} */
#include <klee/klee.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* pull in the target translation unit so we don't have to forward-declare */
#include "{source_path.name}"

int main(void) {{
{body}
    {call}
    return 0;
}}
"""
    return harness
