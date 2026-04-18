/* Whole-library harness for png_format_number (pngerror.c:132).
 *
 * libpng's comment says `end should point just *beyond* the end of the
 * buffer`. The first statement of the function is `*--end = '\0';`,
 * which decrements end before any size check. If a caller passes
 * `end == start`, the write lands at `start - 1` — OOB write.
 *
 * We expose this contract by giving KLEE control of the end offset.
 * If KLEE can pick end_offset == 0, the OOB write fires. Expected:
 * confirmed on a symbolic end_offset.
 */
#include <stddef.h>
typedef char *png_charp;
typedef const char *png_const_charp;
typedef size_t png_alloc_size_t;

extern png_charp png_format_number(png_const_charp start, png_charp end,
                                   int format, png_alloc_size_t number);

int fuzz_format_number(int format, size_t number, unsigned int end_offset) {
    char buf[16];
    if (end_offset > 16) return -1;
    png_format_number(buf, buf + end_offset, format, number);
    return 0;
}
