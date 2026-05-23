/* Self-contained extraction of png_check_keyword from libpng 1.2.56
 * (pngset.c lines 1271-1346). Same CVE-2015-8540 family bug, different
 * code layout (the 1.2 branch uses png_strlen + for-loop rather than
 * the inline while loop introduced in 1.6.x). We confirm the OOB read
 * is reproducible across both code paths.
 *
 * Stubs for png_warning, png_malloc_warn and png_strlen are inlined so
 * the TU compiles standalone for KLEE.
 */
#include <stddef.h>
#include <stdint.h>

typedef uint32_t      png_size_t;
typedef uint32_t      png_uint_32;
typedef unsigned char png_byte;
typedef char         *png_charp;
typedef char        **png_charpp;
typedef void         *png_structp;

static char scratch_pool[256];
static int  scratch_used = 0;

static void png_warning(png_structp p, const char *m) { (void)p; (void)m; }

static png_size_t png_strlen(png_charp s) {
    png_size_t n = 0;
    while (s[n] != 0) n++;
    return n;
}

static png_charp png_malloc_warn(png_structp p, png_uint_32 size) {
    (void)p;
    if (scratch_used + size > sizeof scratch_pool) return 0;
    png_charp out = &scratch_pool[scratch_used];
    scratch_used += size;
    return out;
}

png_size_t
png_check_keyword_1256(png_structp png_ptr, png_charp key, png_charpp new_key)
{
    png_size_t key_len;
    png_charp kp, dp;

    *new_key = 0;

    if (key == 0 || (key_len = png_strlen(key)) == 0) {
        png_warning(png_ptr, "zero length keyword");
        return (png_size_t)0;
    }

    *new_key = png_malloc_warn(png_ptr, (png_uint_32)(key_len + 2));
    if (*new_key == 0) {
        png_warning(png_ptr, "Out of memory while processing keyword");
        return (png_size_t)0;
    }

    for (kp = key, dp = *new_key; *kp != '\0'; kp++, dp++) {
        if ((png_byte)*kp < 0x20 ||
            ((png_byte)*kp > 0x7E && (png_byte)*kp < 0xA1)) {
            png_warning(png_ptr, "invalid character in keyword");
            *dp = ' ';
        } else {
            *dp = *kp;
        }
    }
    *dp = '\0';

    return key_len;
}
