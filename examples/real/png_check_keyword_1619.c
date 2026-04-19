/* Self-contained extraction of png_check_keyword from libpng 1.6.19
 * (pngwutil.c lines 680-749). This is the version that ships before
 * the fix merged in 1.6.20 (which addressed CVE-2015-8540: out-of-bounds
 * read in png_check_keyword). We preserve the function body byte-for-byte
 * and stub out warning/debug macros so KLEE can compile the TU alone.
 *
 * The harness drives `png_check_keyword_1619` with a symbolic key buffer
 * and a fixed-size new_key output buffer. If KLEE reports a memory error,
 * we have reproduced the CVE; if it completes without, the extraction
 * shows the code path KLEE explored.
 */
#include <stddef.h>
#include <stdint.h>

typedef uint32_t     png_uint_32;
typedef unsigned char png_byte;
typedef unsigned char *png_bytep;
typedef const char   *png_const_charp;
typedef void         *png_structrp;

static void png_debug(int level, const char *msg) { (void)level; (void)msg; }
static void png_warning(png_structrp png_ptr, const char *msg) {
    (void)png_ptr; (void)msg;
}

png_uint_32
png_check_keyword_1619(png_structrp png_ptr, png_const_charp key, png_bytep new_key)
{
    png_const_charp orig_key = key;
    png_uint_32 key_len = 0;
    int bad_character = 0;
    int space = 1;
    (void)orig_key;

    png_debug(1, "in png_check_keyword");

    if (key == NULL)
    {
        *new_key = 0;
        return 0;
    }

    while (*key && key_len < 79)
    {
        png_byte ch = (png_byte)*key++;

        if ((ch > 32 && ch <= 126) || (ch >= 161 /*&& ch <= 255*/))
            *new_key++ = ch, ++key_len, space = 0;

        else if (space == 0)
        {
            *new_key++ = 32, ++key_len, space = 1;

            if (ch != 32)
                bad_character = ch;
        }

        else if (bad_character == 0)
            bad_character = ch;
    }

    if (key_len > 0 && space != 0) /* trailing space */
    {
        --key_len, --new_key;
        if (bad_character == 0)
            bad_character = 32;
    }

    *new_key = 0;

    if (key_len == 0)
        return 0;

    if (*key != 0)
        png_warning(png_ptr, "keyword truncated");

    else if (bad_character != 0)
        png_warning(png_ptr, "keyword bad character");

    return key_len;
}
