/* Self-contained extraction of png_check_keyword from libpng 1.6.47
 * (pngset.c lines 1912-1987). Function body is byte-identical to 1.6.19;
 * we rename to png_check_keyword_1647 to avoid symbol collision.
 */
#include <stddef.h>
#include <stdint.h>

typedef uint32_t     png_uint_32;
typedef unsigned char png_byte;
typedef unsigned char *png_bytep;
typedef const char   *png_const_charp;
typedef void         *png_structrp;

static void png_debug(int l, const char *m) { (void)l; (void)m; }
static void png_warning(png_structrp p, const char *m) { (void)p; (void)m; }

png_uint_32
png_check_keyword_1647(png_structrp png_ptr, png_const_charp key, png_bytep new_key)
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

        if ((ch > 32 && ch <= 126) || (ch >= 161))
        {
            *new_key++ = ch; ++key_len; space = 0;
        }
        else if (space == 0)
        {
            *new_key++ = 32; ++key_len; space = 1;

            if (ch != 32)
                bad_character = ch;
        }
        else if (bad_character == 0)
            bad_character = ch;
    }

    if (key_len > 0 && space != 0) /* trailing space */
    {
        --key_len; --new_key;
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
