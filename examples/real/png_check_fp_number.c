/* Self-contained extraction of png_check_fp_number from libpng 1.6.47.
 *
 * Source: libpng/src/png.c lines 2121-2253 plus PNG_FP_* constants from
 * pngpriv.h lines 1885-1900. Function semantics are IDENTICAL to the
 * upstream implementation; we only dropped the libpng typedefs and the
 * PNG_FP_*_SUPPORTED feature gates so KLEE can compile this as one TU
 * without pulling in zlib or the rest of libpng.
 *
 * Attack surface: caller supplies `string` (attacker-controlled bytes)
 * and `size` (attacker-controlled length). `statep` and `whereami` are
 * in/out scalars.
 */

#include <stddef.h>

typedef const char *png_const_charp;

#define PNG_FP_INTEGER    0
#define PNG_FP_FRACTION   1
#define PNG_FP_EXPONENT   2
#define PNG_FP_STATE      3
#define PNG_FP_SAW_SIGN   4
#define PNG_FP_SAW_DIGIT  8
#define PNG_FP_SAW_DOT   16
#define PNG_FP_SAW_E     32
#define PNG_FP_SAW_ANY   60
#define PNG_FP_WAS_VALID 64
#define PNG_FP_NEGATIVE 128
#define PNG_FP_NONZERO  256
#define PNG_FP_STICKY   448

#define png_fp_add(state, flags) ((state) |= (flags))
#define png_fp_set(state, value) ((state) = (value) | ((state) & PNG_FP_STICKY))

int
png_check_fp_number(png_const_charp string, size_t size, int *statep,
    size_t *whereami)
{
   int state = *statep;
   size_t i = *whereami;

   while (i < size)
   {
      int type;
      switch (string[i])
      {
      case 43:  type = PNG_FP_SAW_SIGN;                   break;
      case 45:  type = PNG_FP_SAW_SIGN + PNG_FP_NEGATIVE; break;
      case 46:  type = PNG_FP_SAW_DOT;                    break;
      case 48:  type = PNG_FP_SAW_DIGIT;                  break;
      case 49: case 50: case 51: case 52:
      case 53: case 54: case 55: case 56:
      case 57:  type = PNG_FP_SAW_DIGIT + PNG_FP_NONZERO; break;
      case 69:
      case 101: type = PNG_FP_SAW_E;                      break;
      default:  goto PNG_FP_End;
      }

      switch ((state & PNG_FP_STATE) + (type & PNG_FP_SAW_ANY))
      {
      case PNG_FP_INTEGER + PNG_FP_SAW_SIGN:
         if ((state & PNG_FP_SAW_ANY) != 0)
            goto PNG_FP_End;
         png_fp_add(state, type);
         break;

      case PNG_FP_INTEGER + PNG_FP_SAW_DOT:
         if ((state & PNG_FP_SAW_DOT) != 0)
            goto PNG_FP_End;
         else if ((state & PNG_FP_SAW_DIGIT) != 0)
            png_fp_add(state, type);
         else
            png_fp_set(state, PNG_FP_FRACTION | type);
         break;

      case PNG_FP_INTEGER + PNG_FP_SAW_DIGIT:
         if ((state & PNG_FP_SAW_DOT) != 0)
            png_fp_set(state, PNG_FP_FRACTION | PNG_FP_SAW_DOT);
         png_fp_add(state, type | PNG_FP_WAS_VALID);
         break;

      case PNG_FP_INTEGER + PNG_FP_SAW_E:
         if ((state & PNG_FP_SAW_DIGIT) == 0)
            goto PNG_FP_End;
         png_fp_set(state, PNG_FP_EXPONENT);
         break;

      case PNG_FP_FRACTION + PNG_FP_SAW_DIGIT:
         png_fp_add(state, type | PNG_FP_WAS_VALID);
         break;

      case PNG_FP_FRACTION + PNG_FP_SAW_E:
         if ((state & PNG_FP_SAW_DIGIT) == 0)
            goto PNG_FP_End;
         png_fp_set(state, PNG_FP_EXPONENT);
         break;

      case PNG_FP_EXPONENT + PNG_FP_SAW_SIGN:
         if ((state & PNG_FP_SAW_ANY) != 0)
            goto PNG_FP_End;
         png_fp_add(state, PNG_FP_SAW_SIGN);
         break;

      case PNG_FP_EXPONENT + PNG_FP_SAW_DIGIT:
         png_fp_add(state, PNG_FP_SAW_DIGIT | PNG_FP_WAS_VALID);
         break;

      default: goto PNG_FP_End;
      }

      ++i;
   }

PNG_FP_End:
   *statep = state;
   *whereami = i;

   return (state & PNG_FP_SAW_DIGIT) != 0;
}
