/* Whole-library harness source.
 *
 * This is the "target source" in our pipeline: the runner generates a
 * KLEE harness that includes this file, compiles it, then llvm-links
 * the resulting harness.bc with the pre-built libpng+zlib bitcode.
 *
 * We forward-declare png_check_fp_number against libpng's real ABI,
 * so the symbol resolves at link time. The harness drives it with
 * symbolic attacker input. No png_struct is involved for this target
 * — we are exercising the whole-library bitcode path end-to-end.
 */

#include <stddef.h>

typedef const char *png_const_charp;

extern int png_check_fp_number(png_const_charp string, size_t size,
                               int *statep, size_t *whereami);
