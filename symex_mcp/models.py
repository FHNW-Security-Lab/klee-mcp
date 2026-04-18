"""Pydantic models shared across the MCP server."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CWE(str, Enum):
    STACK_BOF = "CWE-121"
    HEAP_BOF = "CWE-122"
    INT_OVERFLOW = "CWE-190"
    DOUBLE_FREE = "CWE-415"
    UAF = "CWE-416"
    NULL_DEREF = "CWE-476"
    OOB_WRITE = "CWE-787"
    OOB_READ = "CWE-125"
    DIV_BY_ZERO = "CWE-369"
    OTHER = "OTHER"


class TaintedInput(BaseModel):
    """One attacker-controlled input to the target function."""

    name: str = Field(description="Variable / parameter name")
    c_type: str = Field(description="C type, e.g. 'char *', 'int', 'size_t'")
    size_bytes: int = Field(
        default=256,
        description="For pointer/buffer types, how many symbolic bytes to allocate",
    )
    is_pointer: bool = False
    null_terminate: bool = Field(
        default=False,
        description="If True, force a 0-byte at the end of the symbolic buffer",
    )


class VerifyRequest(BaseModel):
    """Input to verify_vulnerability."""

    source_file: str = Field(
        description="Absolute path to the C/C++ source file containing the bug"
    )
    cwe: CWE
    function_name: str = Field(
        description="Function containing the suspected sink; becomes the symex target",
    )
    sink_line: Optional[int] = Field(
        default=None,
        description="Line number of the suspected sink (for reporting only)",
    )
    tainted_inputs: list[TaintedInput] = Field(
        default_factory=list,
        description="Parameters / globals to mark symbolic. If empty, all "
        "parameters of function_name are made symbolic with default sizes.",
    )
    assumptions: list[str] = Field(
        default_factory=list,
        description="C expressions pasted verbatim into klee_assume(...). Must "
        "reference only tainted_inputs by name. Opt-in: only applied if "
        "use_bounds is True. Example: ['len <= 64', 'mode < 4'].",
    )
    loop_bounds: dict[str, int] = Field(
        default_factory=dict,
        description="LLM-supplied caps on symbolic parameters that drive loops. "
        "Each {var: N} becomes klee_assume(var <= N). Opt-in (use_bounds).",
    )
    use_bounds: bool = Field(
        default=False,
        description="When True, assumptions and loop_bounds are applied. When "
        "False, both are ignored (used for the relaxed retry).",
    )
    auto_relax_on_infeasible: bool = Field(
        default=False,
        description="If True and the bounded run returns 'infeasible', the "
        "server automatically retries once with use_bounds=False. The final "
        "verdict reflects the retry; the initial verdict is preserved in "
        "initial_verdict on the response.",
    )
    extra_sources: list[str] = Field(
        default_factory=list,
        description="Additional .c files that must be linked (same TU set the "
        "bug lives in)",
    )
    extra_bitcodes: list[str] = Field(
        default_factory=list,
        description="Pre-built LLVM bitcode files (.bc) to llvm-link onto the "
        "harness before KLEE runs. Used for whole-library targets: e.g. "
        "realworld/bitcode/libpng.bc. Paths are absolute host paths; the "
        "runner bind-mounts them into the container.",
    )
    include_dirs: list[str] = Field(default_factory=list)
    defines: list[str] = Field(default_factory=list)
    timeout_s: int = Field(default=60, ge=5, le=600)
    max_memory_mb: int = Field(default=2000, ge=256, le=16000)


class VerifyVerdict(str, Enum):
    CONFIRMED = "confirmed"
    INFEASIBLE = "infeasible"
    TIMEOUT = "timeout"
    BUILD_FAILED = "build_failed"
    KLEE_ERROR = "klee_error"


class VerifyResponse(BaseModel):
    verdict: VerifyVerdict
    cwe: CWE
    source_file: str
    function_name: str
    sink_line: Optional[int] = None
    klee_errors: list[dict] = Field(default_factory=list)
    concrete_input_hex: Optional[str] = None
    ktest_path: Optional[str] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    harness_path: Optional[str] = None
    wall_seconds: float = 0.0
    notes: str = ""
    bounds_applied: bool = Field(
        default=False,
        description="True if this run had use_bounds=True (i.e. "
        "assumptions/loop_bounds were inserted as klee_assume).",
    )
    initial_verdict: Optional[VerifyVerdict] = Field(
        default=None,
        description="If the server auto-relaxed after an infeasible bounded "
        "run, this holds the first (bounded) verdict. None otherwise.",
    )
    relaxed_retry_performed: bool = False
    retry_suggestion: Optional[str] = Field(
        default=None,
        description="Hint for the LLM caller. Set when a bounded run came back "
        "infeasible but auto-relax was not requested — tells the LLM it may "
        "want to call verify_vulnerability again with use_bounds=False.",
    )
    parsed_inputs: dict[str, dict] = Field(
        default_factory=dict,
        description="When the verdict is confirmed and a .ktest was produced, "
        "this holds the per-symbolic-variable decoded values: "
        "{var_name: {size, hex, int?, uint?, text?, bytes}}. The reproducer "
        "emitter consumes this directly.",
    )
    exploitability: Optional[dict] = Field(
        default=None,
        description=(
            "Heuristic classification of the primitive the crash exposes. "
            "Populated only on 'confirmed'. Fields: primitive "
            "(arbitrary_write|bounded_write|arbitrary_read|bounded_read|"
            "uaf_read|uaf_write|null_deref|double_free|integer_overflow|"
            "div_by_zero|crash|unknown), severity "
            "(CRITICAL|HIGH|MEDIUM|LOW), attacker_controlled_address, "
            "operation, pc_overwrite_possible, explanation."
        ),
    )


class ReachabilityVerdict(str, Enum):
    REACHED = "reached"
    NOT_REACHED = "not_reached"
    TIMEOUT = "timeout"
    BUILD_FAILED = "build_failed"
    KLEE_ERROR = "klee_error"


class ReachabilityRequest(BaseModel):
    """Input to check_reachability.

    Asks: given that we drive `entry_function` symbolically (with optional
    LLM bounds), does any path reach `target_function`? The whole-program
    reachability problem reduces to: pick a plausible nearby entry
    function (not main), make its args symbolic, and let KLEE go.
    """

    source_file: str
    entry_function: str = Field(
        description="Function where execution starts for this reachability "
        "query. LLM picks a public/exported function near the target.",
    )
    target_function: str = Field(
        description="Function we want to prove is reachable from entry_function.",
    )
    tainted_inputs: list[TaintedInput] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    loop_bounds: dict[str, int] = Field(default_factory=dict)
    use_bounds: bool = False
    extra_sources: list[str] = Field(default_factory=list)
    include_dirs: list[str] = Field(default_factory=list)
    defines: list[str] = Field(default_factory=list)
    timeout_s: int = Field(default=60, ge=5, le=600)
    max_memory_mb: int = Field(default=2000, ge=256, le=16000)


class ReachabilityResponse(BaseModel):
    verdict: ReachabilityVerdict
    source_file: str
    entry_function: str
    target_function: str
    concrete_input_hex: Optional[str] = None
    ktest_path: Optional[str] = None
    harness_path: Optional[str] = None
    patched_source_path: Optional[str] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    wall_seconds: float = 0.0
    bounds_applied: bool = False
    notes: str = ""
