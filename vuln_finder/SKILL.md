---
name: klee-mcp-triage
description: End-to-end vulnerability triage for C/C++ codebases using the symex-validator MCP. Trigger when the user says "analyze X with klee-mcp", "audit X for vulnerabilities", "find and validate bugs in X", or similar — where X is a path to C/C++ source. Produces a structured disclosure-ready report: candidates found, confirmed bugs with concrete inputs, rescued false-positives, reachability, and per-bug reproducer artefacts (reproduce.c + poc.bin) ready for coordinated disclosure.
---

# klee-mcp-triage — end-to-end orchestrator

You are invoked with a path to a C/C++ codebase (single file, directory,
or subtree). You drive the whole pipeline without further user input:
find candidates, generate harnesses, validate with KLEE, prove
reachability, emit disclosure-ready reproducers, write a report. The
user said "analyze X"; everything else is yours to decide.

## Tools available via the symex-validator MCP

- `auto_harness(source_file, function_name, cwe)` — Phase 0. Returns a
  default KLEE harness + inferred taints. Start here for each candidate.
- `verify_vulnerability(...)` — Phase 1. Runs KLEE. Supports
  `assumptions`, `loop_bounds`, `use_bounds`, `auto_relax_on_infeasible`,
  `extra_bitcodes` for whole-library linking.
- `check_reachability_tool(...)` — Phase 2. Proves a target function is
  reachable from an LLM-picked entry function.
- `emit_reproducer(...)` — Phase 3. Writes `reproduce.c`, `poc.bin`,
  source copy, and a gcc+ASan run recipe for a confirmed bug.
- `list_supported_cwes()` — CWE tokens accepted by the above.
- `generate_harness_tool(...)` — manual harness build with explicit
  taints. Use only when auto_harness's inference is wrong.

## Pipeline

### Step 1 — inventory

Resolve the input path. If it's a file, inventory is just that file.
If it's a directory, Glob for `**/*.{c,cpp,cc,h,hpp}`. Read the files
(or sample them if the codebase is large) and form a mental map of
the code.

### Step 2 — candidate hunting

For each source file, scan for candidates. Target these CWEs: **CWE-121,
CWE-122, CWE-125, CWE-190, CWE-369, CWE-415, CWE-416, CWE-476, CWE-787**.

Patterns to grep and read:

- fixed-size stack buffers written with non-constant indices
- `memcpy`, `strcpy`, `sprintf`, `gets`, `alloca` with attacker-
  influenced lengths
- arithmetic on `size_t` / `int` feeding allocators or array indices
- `free()` followed by a later dereference in the same function
- dereferences of pointers returned from allocators / lookups /
  parsers without a NULL check
- loops whose upper bound is an attacker input

For each candidate, write down: `source_file`, `function_name`,
`sink_line`, `cwe`, `rationale`, `confidence`, any bounds you know
semantically, and a suggested `entry_function` for later reachability.

### Step 3 — Phase 0: auto_harness (or author a wrapper TU)

**Simple case.** If the target function takes scalar arguments or simple
buffers, call `auto_harness(source_file, function_name, cwe)`. Read the
`inferred_tainted_inputs` and adjust:

- pointer argument should be NULL (CWE-476) → `size_bytes: 0`
- scalar is really a bounded mode/flag → add to `assumptions`
- pointer is an output-only scalar → override `c_type` and `size_bytes`

**Wrapper case.** Some functions cannot be symbolically executed
directly — they require library-allocated state (libpng's
`png_create_read_struct`, libxml2's `xmlReadMemory`, etc.). In those
cases **you author a small wrapper C file** that:

1. Declares your own simpler function — e.g.
   `int fuzz_push(const unsigned char *buf, size_t len)`.
2. Does the library-specific setup inside (`png_create_read_struct`,
   callbacks, format detection, etc.).
3. Forward-declares the library APIs it uses; do **not** include the
   library's headers — you'll link the library's whole-program bitcode
   at verify time via `extra_bitcodes`.
4. Is the symbolic attack surface you actually want to validate —
   typically the narrowest wrapper that matches how an attacker feeds
   input to the library (bytes into a push parser, a string into a
   URL parser, etc.).

Then call `auto_harness` on **your wrapper function**, not the
library function. A complete example is in the repo:
`examples/real/libpng_push_read.c` — ~50 lines, drives the full
libpng push parser with 8 symbolic attacker bytes, linked against a
single 2.2 MB `libpng+zlib.bc`.

Ship the wrapper alongside the candidate JSON (its `source_file` is
the wrapper, not the library).

### Step 4 — Phase 1: verify_vulnerability

Call `verify_vulnerability` for every candidate. Default settings:

- `use_bounds=True` when you have any `assumptions` or `loop_bounds`.
  The LLM's semantic knowledge of bounds is the main speedup; use it.
- `auto_relax_on_infeasible=True` so the server automatically retries
  without bounds on infeasible. You get correctness for free.
- `extra_bitcodes=[...]` for whole-library targets (list of pre-built
  `.bc` files).
- `timeout_s=60` to start. Bump to 120–180 for complex wrappers.

Collect responses. Categorise each candidate:

- `verdict == confirmed` — real bug. Capture `concrete_input_hex`,
  `parsed_inputs`, `ktest_path`. **Go to Step 6.**
- `verdict == infeasible` — false positive *rescued*. Paper-worthy.
- `verdict == confirmed && initial_verdict == infeasible` — the LLM's
  bounds were too tight. Flag prominently.
- `verdict == timeout | build_failed | klee_error` — still needs a
  human. Surface in the report.

### Step 5 — Phase 2: reachability for confirmed bugs

For each confirmed bug, pick a plausible `entry_function`: a public
API, a request handler, a parser root. **Do not use `main` unless the
program actually is an executable with a small main.** Call
`check_reachability_tool` with the entry function's taints.

Verdicts: `reached` (with concrete entry input in hex), `not_reached`,
`timeout / build_failed / klee_error`.

### Step 6 — Phase 3: emit disclosure artefacts

For every `confirmed` candidate, call `emit_reproducer` with:

```
emit_reproducer(
    source_file=<candidate source_file>,
    function_name=<candidate function_name>,
    cwe=<candidate cwe>,
    tainted_inputs=<candidate tainted_inputs>,
    parsed_inputs=<verify response's parsed_inputs>,
    out_dir=<e.g. reports/<timestamp>/<bug_name>/>,
    sink_line=<candidate sink_line>,
)
```

The server writes:

- `reproduce.c` — standalone C program with concrete inputs inlined.
- `poc.bin` — raw bytes of the primary symbolic buffer.
- `<source_basename>` — a copy of the vulnerable TU.
- `run_recipe` in the response — the exact
  `gcc -fsanitize=address ... && ./reproduce` invocation.

Include all three artefacts in the report under the disclosure
section for that bug (see template below).

### Step 7 — write the report

Produce a single markdown document under
`reports/klee-mcp-<timestamp>.md` with the sections below. The
disclosure template is what a vendor coordinator sees — use it
verbatim per confirmed bug, filled in.

---

## Report skeleton

```markdown
# klee-mcp triage report — <codebase> @ <commit>

- Generated: <UTC timestamp>
- Pipeline: symex-validator MCP (KLEE 3.1 / LLVM 13) on <host>
- Candidate count: <N>
- Confirmed: <C>   Infeasible: <I>   Unresolved: <U>

## Summary

| # | File | Function | CWE | Verdict | Reachable? | Wall | Confidence |
|---|------|----------|-----|---------|------------|------|------------|
| 1 | ... |

## Confirmed vulnerabilities

<for each confirmed bug, fill in the Disclosure template below>

## Rescued false positives

<one short entry per candidate that the LLM flagged but KLEE ruled
infeasible. Include the candidate's rationale and one line on what
KLEE proved.>

## Unresolved

<candidates where the verdict was timeout / build_failed / klee_error.
Each needs human follow-up.>

## Statistics

- Validation rate: <confirmed+infeasible>/<total>
- Wall time: mean X s, p95 Y s
- LLM bounds hit auto-relax: <N/total>
```

## Per-confirmed-bug disclosure template

Fill this in for every `confirmed` verdict. It is drafted to be the
body of a coordinated-disclosure email or a CVE filing.

```markdown
### Advisory: <short title, e.g. "Stack buffer overflow in vulnerable_copy">

**Component**: <library or project name, version if known>
**Location**: `<file>:<line>` (function `<function_name>`)
**CWE**: <cwe, e.g. CWE-121 Stack-based Buffer Overflow>
**Severity (heuristic)**:
  - CWE-121/122/416/787 → High (memory corruption, potentially RCE)
  - CWE-125 → Medium (info leak or crash)
  - CWE-190/369 → Medium (denial-of-service, logic errors)
  - CWE-476 → Medium (denial-of-service)
**Discovery**: symbolic execution (KLEE 3.1) driven from an
  LLM-proposed candidate. Reproducible in <wall_seconds> s.

#### Root cause

<1–3 sentences from the candidate's rationale, enriched with KLEE's
error message and stack trace. Example:

  `png_format_number` in pngerror.c executes `*--end = '\0'` before
  any size check against `start`. When a caller passes `end == start`,
  the decrement-then-write lands at `start - 1` — one byte below the
  buffer. KLEE confirmed this via symbolic `end_offset`; the minimum
  crashing value is `end_offset = 0`.>

#### Affected code

\```c
// <file>, lines <N-3> .. <N+3>
<snippet>
\```

#### Reproduction

The exact input that triggers the vulnerability was synthesised by
KLEE and is provided below.

Compile and run:

\```
<run_recipe from emit_reproducer response>
\```

Expected output (under AddressSanitizer):

\```
==PID==ERROR: AddressSanitizer: <error-type> on address 0x...
WRITE of size N at 0x... thread T0
    #0 <function_name> <file>:<line>
    ...
\```

Raw input bytes (for byte-oriented consumers) are in `poc.bin`; the
standalone reproducer is `reproduce.c`.

#### Concrete input values (from KLEE)

<for each variable in parsed_inputs, show name, size, hex, and
int value when applicable. Example:

  | Variable   | Size | Hex                | Int |
  |------------|------|--------------------|-----|
  | `len`      | 4 B  | `00 01 00 00`      | 256 |
  | `buf[256]` | 256 B| all zero bytes     |  —  |>

#### Suggested fix

<One paragraph proposed patch. Keep it in the spirit of the
project's code. Example for the png_format_number case:

  Reorder the first two statements so the size check happens before
  the decrement:

  \```diff
  -   *--end = '\0';
  -   while (end > start && (number != 0 || count < mincount))
  +   if (end <= start) return end;
  +   *--end = '\0';
  +   while (end > start && (number != 0 || count < mincount))
  \```
>

#### Discovery context

- Candidate generated by: LLM auditor (Claude) via `klee-mcp-triage` skill.
- Validation engine: KLEE 3.1 (LLVM 13), 16 GB memory cap.
- LLM-supplied bounds used during validation:
  `<assumptions, loop_bounds>` — relevant to the caller contract.
- If `initial_verdict == infeasible` → WARNING: the LLM's bounds
  initially ruled out this input; auto-relax uncovered it. The
  bounded verdict is recorded for transparency.

#### Coordinated disclosure template

> Hello <vendor>,
>
> I am writing to report a <CWE short name> in <project> <version>,
> located in `<file>:<line>` (function `<function_name>`).
>
> A concrete input that triggers the issue under AddressSanitizer is
> attached (`reproduce.c` + `poc.bin`). The same input was produced
> by symbolic execution (KLEE) of an LLM-generated harness against
> the unmodified source.
>
> I am happy to coordinate on a fix and a public advisory. My
> suggested embargo is <30> days. Please acknowledge receipt and
> let me know whether a CVE should be requested by you or by us.
>
> <signature>

#### Artefacts attached

- `reproduce.c` — standalone C reproducer (KLEE-synthesised values inlined).
- `poc.bin` — raw input bytes.
- `<source_basename>` — copy of the vulnerable TU (for self-contained build).
- KLEE log excerpt: `<stderr_tail truncated to ~20 lines>`
```

## Examples

User: "analyze examples/bof_01.c with klee-mcp"
→ Inventory: one file. Scan: find `vulnerable_copy` — stack buffer
  write with attacker length. auto_harness; verify (confirmed in
  ~1 s); emit_reproducer → `reproduce.c` + `poc.bin`; compile under
  ASan; paste the ASan output into the disclosure section.

User: "audit realworld/libpng with klee-mcp"
→ Inventory: identify push-mode as the attack surface. Author
  `whole_lib_push_read.c` wrapper. Build libpng+zlib.bc once with
  `scripts/build_lib_bc.sh`. For each candidate: auto_harness on the
  wrapper, verify with `extra_bitcodes` and `loop_bounds`. For
  confirmed bugs: emit_reproducer, compile, run under ASan, capture
  output, write disclosure.

## Honesty

- If a candidate hit `timeout`, say so. The paper's claim is "triage
  aid", not oracle.
- If `initial_verdict == infeasible` and the relaxed retry confirmed
  the bug, the LLM's bounds were wrong. Record it.
- Per-function validation (Phase 1) is a bug finding; you do not need
  reachability to call a bug real. Reachability strengthens the
  exploitability story for the paper.
- In the disclosure, be explicit about whether the bug requires a
  specific precondition (e.g. contract violation by the caller).
  Vendors care about the distinction between "library bug" and
  "library API misuse makes this bug trigger".
