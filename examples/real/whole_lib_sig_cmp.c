/* Whole-library harness for png_sig_cmp.
 * Trivially-shaped function: caller supplies an 8-byte candidate
 * signature, start offset, count. Function clamps count, then memcmps
 * against the embedded PNG magic. Well-guarded: expected infeasible.
 */
#include <stddef.h>
typedef unsigned char *png_bytep;
typedef const unsigned char *png_const_bytep;
extern int png_sig_cmp(png_const_bytep sig, size_t start, size_t num_to_check);
