# Deployment manual

End-to-end setup for klee-mcp on Arch Linux with rootless podman. The
same steps work on Debian/Ubuntu with `apt` in place of `pacman` and on
macOS with a Linux VM (KLEE has no native macOS build). All container
invocations target `docker.io/klee/klee:3.1`.

## 1. System packages

```
sudo pacman -S --needed podman python clang llvm make git jq
# optional: used only for inspecting generated bitcode from the host
```

(No local KLEE install needed — the container ships KLEE, clang, STP,
MiniSat, and the KLEE libc/POSIX runtimes.)

## 2. Pull the KLEE container

```
podman pull docker.io/klee/klee:3.1
```

Verify:

```
podman run --rm docker.io/klee/klee:3.1 /bin/bash -lc \
    "klee --version | head -1 && clang --version | head -1"
```

Expected:
```
KLEE 3.1 (https://klee.github.io)
clang version 13.0.1 ...
```

## 3. Clone this repo and set up the Python venv

```
git clone https://github.com/FHNW-Security-Lab/klee-mcp.git
cd klee-mcp
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 4. Smoke test

The repo ships 14 candidate JSONs; the smallest takes <1 s.

```
./scripts/verify_one.py --candidate benchmark/candidates/bof_01.json
```

Expected tail:

```
"verdict": "confirmed",
"exploitability": {
  "primitive": "bounded_write",
  "severity": "HIGH",
  "target_region": "stack",
  "pc_overwrite_possible": true,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  ...
}
```

Run the full benchmark:

```
python benchmark/run_bench.py
# writes benchmark/results.csv
```

On the reference environment (Arch + podman 5.8.2 + klee 3.1) all 14
candidates hit the expected verdict in under 4 minutes total.

## 5. Building a library as LLVM bitcode (optional, for whole-library
targets)

To validate functions inside a real library (libpng, libxml2, …) you
first build the library as a single `.bc`:

```
# Example: libpng + zlib
git clone --depth 1 --branch v1.3.1 https://github.com/madler/zlib.git realworld/zlib-src
git clone --depth 1 --branch v1.6.47 https://github.com/pnggroup/libpng.git realworld/libpng
cp realworld/libpng/scripts/pnglibconf.h.prebuilt realworld/libpng/pnglibconf.h
cp realworld/zlib-src/zlib.h realworld/zlib-src/zconf.h realworld/libpng/

mkdir -p realworld/bitcode
./scripts/build_lib_bc.sh zlib   realworld/zlib-src realworld/bitcode/zlib.bc
./scripts/build_lib_bc.sh libpng realworld/libpng   realworld/bitcode/libpng.bc
# the second run also re-links zlib in; final libpng.bc is ~2.2 MB.
```

Verify the combined bitcode exports the symbols you need:

```
podman run --rm -v $(pwd)/realworld/bitcode:/bc:Z \
    docker.io/klee/klee:3.1 /bin/bash -lc \
    "llvm-nm /bc/libpng.bc | grep -E 'T (png_create_read_struct|inflate)\$'"
```

Then reference the bitcode from a candidate:

```json
{
  "source_file": "examples/real/whole_lib_push_read.c",
  "function_name": "fuzz_push",
  "cwe": "OTHER",
  "tainted_inputs": [...],
  "extra_bitcodes": ["realworld/bitcode/libpng.bc"],
  "max_memory_mb": 16000,
  "timeout_s": 180,
  "use_bounds": true
}
```

## 6. Connecting the server to Claude Code

Claude Code reads MCP server configuration from
`.claude/settings.local.json` in the current project, or from
`~/.claude/settings.json` globally. This repo ships the local config
already pointing at the project-local venv:

```json
{
  "mcpServers": {
    "symex-validator": {
      "command": "./.venv/bin/python",
      "args": ["-m", "symex_mcp.server"],
      "env": {
        "SYMEX_CONTAINER_CMD": "podman",
        "SYMEX_KLEE_IMAGE": "docker.io/klee/klee:3.1",
        "SYMEX_LOG": "INFO"
      }
    }
  }
}
```

Start Claude Code from this directory:

```
cd /path/to/klee-mcp
claude
```

Then verify the server is picked up:

```
/mcp
```

You should see `symex-validator` listed with its 6 tools (`auto_harness`,
`verify_vulnerability`, `check_reachability_tool`, `emit_reproducer`,
`generate_harness_tool`, `list_supported_cwes`).

The orchestrator skill is in `vuln_finder/SKILL.md`. Trigger it with a
natural-language instruction:

> Analyze `examples/toy/bof_01.c` with klee-mcp.

The skill runs Phases 0–3 autonomously and writes a disclosure-ready
report.

## 7. Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SYMEX_CONTAINER_CMD` | `podman` | Set to `docker` if using docker. |
| `SYMEX_KLEE_IMAGE` | `docker.io/klee/klee:3.1` | Override to pin a digest for artifact-evaluation reproducibility. |
| `SYMEX_LOG` | `INFO` | Python logging level for the server. |

## 8. SELinux / rootless notes

All `podman run` invocations use `:Z` on bind mounts and `--userns=keep-id`,
which works on SELinux-enforcing systems and rootless setups. No
capabilities or privileged containers are required.

## 9. Troubleshooting

- **`klee: HaltTimer invoked`** — the candidate is too symbolic for the
  time budget. Tighten `loop_bounds` or reduce buffer sizes on
  `tainted_inputs`.
- **`no klee-out-* directory produced` + `error:` in stderr_tail** —
  the harness did not compile. Check that your source file is in scope
  (use an absolute path or one resolvable from the current working
  directory).
- **`abort` errors ignored by the runner** — expected. KLEE emits
  `.err` files for libpng's / libxml2's own `abort()` on invalid input;
  these are *not* memory-safety bugs. The runner filters them. The
  final response notes them in `notes` for transparency.
- **Paths in the JSON candidates** — the runner calls `Path(...).resolve()`
  on the `source_file`, so run commands from the repo root (or use
  absolute paths).
