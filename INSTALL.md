# Install

Target: Arch Linux, podman, Python via venv.

## 1. System packages (pacman)

```
sudo pacman -S --needed podman python clang llvm make git jq
```

`clang`/`llvm` are only needed locally if you want to inspect bitcode;
the actual KLEE toolchain lives inside the podman image.

Optional (only if you want to run angr as a fallback later without the
container): nothing extra — angr installs from pip.

## 2. Pull the KLEE container

```
podman pull docker.io/klee/klee:3.1
```

If that tag is unavailable, use `klee/klee:latest`. The image ships clang,
opt, klee, and klee-stats.

## 3. Python venv + deps

```
cd /home/blacksheeep/SourceCode/Paper_AI_MCP_SymEx
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 4. Register the MCP server with Claude Code

The project ships `.claude/settings.local.json` that already points at
`./.venv/bin/python -m symex_mcp.server`. Start Claude Code from this
directory and the `symex-validator` MCP server will be available.

Verify with:

```
claude mcp list
```

You should see `symex-validator` in the output.

## 5. Smoke test

```
source .venv/bin/activate
./scripts/run_example.sh examples/bof_01
```

Expected: KLEE reports a memory error on line 12 of `bof_01.c` and writes
a `.ktest` file containing the input that triggers it.

## Notes on podman vs. docker

All scripts invoke `podman`. If you must use docker, export
`SYMEX_CONTAINER_CMD=docker` and the runner will use that instead.
Rootless podman works; the runner bind-mounts the working directory with
`:Z` for SELinux systems and `:U` for uid mapping.
