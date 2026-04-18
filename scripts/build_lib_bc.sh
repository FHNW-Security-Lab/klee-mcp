#!/usr/bin/env bash
# Build a C library as a single LLVM bitcode file suitable for linking
# with a KLEE harness.
#
# Usage:
#   build_lib_bc.sh <name> <src_dir> <out_bc> [compile_flags...]
#
# The script runs clang inside the KLEE container, so the resulting
# bitcode is compatible with whatever clang the klee/klee image ships.
# It compiles every .c under <src_dir> (non-recursive) to a .bc file,
# then llvm-link's them into <out_bc>.
#
# We deliberately skip test/example/fuzzer .c files (pngtest.c, etc.)
# by an exclude list.
set -euo pipefail

name="${1:?name required}"
src_dir="${2:?src dir required}"
out_bc="${3:?out bc path required}"
shift 3
extra_flags=("$@")

CONTAINER_CMD="${SYMEX_CONTAINER_CMD:-podman}"
KLEE_IMAGE="${SYMEX_KLEE_IMAGE:-docker.io/klee/klee:3.1}"

src_dir=$(realpath "$src_dir")
out_bc_abs=$(realpath -m "$out_bc")
out_dir=$(dirname "$out_bc_abs")
mkdir -p "$out_dir"

# Mount the src dir and the output dir; compile inside.
tmp_work=$(mktemp -d /tmp/bcbuild.XXXXXX)
trap 'rm -rf "$tmp_work"' EXIT

# Exclude lists by library name — edit as we add libs.
exclude_regex=""
case "$name" in
    libpng)
        exclude_regex="(example|pngtest|tools/|oss-fuzz)"
        ;;
    zlib)
        exclude_regex="(^$)" # none for now
        ;;
esac

# Collect .c files (non-recursive under src_dir).
mapfile -t c_files < <(ls -1 "$src_dir"/*.c | awk -v re="$exclude_regex" 'BEGIN{IGNORECASE=1} ($0!~re){print}')
if [[ ${#c_files[@]} -eq 0 ]]; then
    echo "no .c files found under $src_dir" >&2
    exit 2
fi

# Write a build script into tmp_work, then exec it in the container.
cat > "$tmp_work/build.sh" <<'EOS'
set -euo pipefail
cd /src
mkdir -p /out/bc_parts
FAIL=0
for f in "$@"; do
    base=$(basename "$f" .c)
    echo "  compiling $base.c" >&2
    if ! clang \
        -emit-llvm -c -g -O0 \
        -Xclang -disable-O0-optnone \
        -Wno-everything \
        -DNDEBUG \
        $EXTRA_FLAGS \
        "$f" -o "/out/bc_parts/$base.bc" 2>/tmp/${base}.stderr; then
        echo "  FAILED: $base" >&2
        head -20 /tmp/${base}.stderr >&2
        FAIL=$((FAIL+1))
        continue
    fi
done
shopt -s nullglob
parts=(/out/bc_parts/*.bc)
if [[ ${#parts[@]} -eq 0 ]]; then
    echo "no bitcode produced" >&2
    exit 3
fi
echo "  linking ${#parts[@]} .bc -> $OUT_BC" >&2
llvm-link "${parts[@]}" -o "$OUT_BC"
echo "  bytes: $(stat -c %s $OUT_BC)" >&2
echo "$FAIL failed compilations" >&2
EOS
chmod +x "$tmp_work/build.sh"

# Convert host paths to container paths for the file list.
mapfile -t container_files < <(printf '%s\n' "${c_files[@]}" | sed "s|^$src_dir/|/src/|")

echo "===== building $name bitcode =====" >&2
echo "  src_dir=$src_dir" >&2
echo "  out_bc=$out_bc_abs" >&2
echo "  files: ${#c_files[@]}" >&2

"$CONTAINER_CMD" run --rm \
    --userns=keep-id \
    -v "$src_dir":/src:Z \
    -v "$out_dir":/out:Z \
    -v "$tmp_work":/work:Z \
    -e EXTRA_FLAGS="${extra_flags[*]}" \
    -e OUT_BC="/out/$(basename "$out_bc_abs")" \
    "$KLEE_IMAGE" \
    /bin/bash /work/build.sh "${container_files[@]}"

echo "built: $out_bc_abs" >&2
