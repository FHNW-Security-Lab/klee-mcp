/* Deeper libpng push-mode harness: 32-byte buffer. The skill-level
 * wrapper; taints buf + len as symbolic; LLM constrains buf[0..7] to
 * the PNG signature so KLEE explores chunk dispatch past the magic.
 */
#include <stddef.h>
#include <stdint.h>

typedef struct png_struct_def * png_structrp;
typedef struct png_info_def   * png_inforp;
typedef unsigned char         *png_bytep;
typedef const char            *png_const_charp;

extern png_structrp png_create_read_struct(png_const_charp user_png_ver,
                                           void *error_ptr,
                                           void *error_fn, void *warn_fn);
extern png_inforp   png_create_info_struct(png_structrp png_ptr);
extern void         png_destroy_read_struct(png_structrp *pp, png_inforp *info, png_inforp *end);
extern void         png_process_data(png_structrp png_ptr, png_inforp info_ptr,
                                     png_bytep buffer, size_t buffer_size);
extern int          png_set_progressive_read_fn(png_structrp png_ptr, void *progressive_ptr,
                                                void *info_fn, void *row_fn, void *end_fn);

#define PNG_LIBPNG_VER_STRING "1.6.47"

int fuzz_push(const unsigned char *buf, size_t len) {
    if (len > 32) return -1;

    png_structrp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, 0, 0, 0);
    if (png_ptr == 0) return -2;

    png_inforp info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == 0) {
        png_destroy_read_struct(&png_ptr, 0, 0);
        return -3;
    }

    png_set_progressive_read_fn(png_ptr, 0, 0, 0, 0);
    png_process_data(png_ptr, info_ptr, (png_bytep)buf, len);
    png_destroy_read_struct(&png_ptr, &info_ptr, 0);
    return 0;
}
