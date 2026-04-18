/* Positive control: png_check_fp_number with a deliberately broken
 * guard. The loop now reads string[i] after skipping the `i < size`
 * check on one path — an OOB read KLEE must catch. This is synthetic,
 * not a real libpng CVE; its job is to demonstrate that the same
 * pipeline that proved the real function infeasible can *confirm* a
 * bug when present, on the same-shape real-library code.
 */

#include <stddef.h>

typedef const char *png_const_charp;

#define PNG_FP_INTEGER    0
#define PNG_FP_STATE      3
#define PNG_FP_SAW_SIGN   4
#define PNG_FP_SAW_DIGIT  8
#define PNG_FP_SAW_ANY   60
#define PNG_FP_WAS_VALID 64
#define PNG_FP_NONZERO  256

int
png_check_fp_number_bug(png_const_charp string, size_t size, int *statep,
    size_t *whereami)
{
   int state = *statep;
   size_t i = *whereami;

   /* BUG: missing `i < size` guard on the first iteration when state has
    * PNG_FP_WAS_VALID already set — classic off-by-check.
    */
   if ((state & PNG_FP_WAS_VALID) != 0) {
      /* OOB read: `i` may equal `size` here, so string[i] is one past end */
      int ch = string[i];
      (void)ch;
   }

   while (i < size) {
      if (string[i] < '0' || string[i] > '9')
         break;
      ++i;
   }

   *statep = state;
   *whereami = i;
   return (state & PNG_FP_SAW_DIGIT) != 0;
}
