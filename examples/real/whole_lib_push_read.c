/* Whole-library push-mode harness.
 *
 * Creates a real libpng read struct + info struct, then feeds a small
 * symbolic byte buffer via png_process_data (push mode). This is the
 * real fuzzer entry point — an attacker controls bytes delivered to a
 * push-mode parser, which is the topology of most libpng integrations.
 *
 * Expected: path explosion. libpng's push parser branches on chunk
 * type, length, CRC, and then per-chunk handlers. Without tight bounds
 * KLEE cannot exhaust; with a small buffer (8 bytes) we at least hit
 * the signature / early-state handlers in bounded time.
 *
 * We drive the "fuzz" function — a self-contained harness body that
 * calls libpng APIs, because harness_gen's auto-harness doesn't know
 * libpng initialization. The taint spec makes `buf` symbolic.
 */
#include <stddef.h>
#include <stdint.h>

typedef struct png_struct_def * png_structrp;
typedef struct png_info_def * png_inforp;
typedef unsigned char *png_bytep;
typedef unsigned char png_byte;
typedef const char *png_const_charp;

/* libpng API surface we touch */
extern png_structrp png_create_read_struct(png_const_charp user_png_ver,
                                           void *error_ptr,
                                           void *error_fn, void *warn_fn);
extern png_inforp png_create_info_struct(png_structrp png_ptr);
extern void png_destroy_read_struct(png_structrp *pp, png_inforp *info, png_inforp *end);
extern void png_process_data(png_structrp png_ptr, png_inforp info_ptr,
                             png_bytep buffer, size_t buffer_size);
extern int png_set_progressive_read_fn(png_structrp png_ptr, void *progressive_ptr,
                                       void *info_fn, void *row_fn, void *end_fn);

#define PNG_LIBPNG_VER_STRING "1.6.47"

/* The "target" function our harness generator will drive. Its parameter
 * is the symbolic attacker input; everything else we set up inside. */
int fuzz_push(const unsigned char *buf, size_t len) {
    if (len > 16) return -1;

    png_structrp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, 0, 0, 0);
    if (png_ptr == 0) return -2;

    png_inforp info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == 0) {
        png_destroy_read_struct(&png_ptr, 0, 0);
        return -3;
    }

    /* progressive callbacks: NULL means libpng will call nothing,
     * just parse chunks for validation. */
    png_set_progressive_read_fn(png_ptr, 0, 0, 0, 0);

    /* Feed the symbolic bytes. png_process_data may longjmp on errors;
     * we don't setjmp here, which means KLEE will see the longjmp as
     * an 'Execution' error. That's fine — we only care about memory
     * safety errors (Ptr / Free / Overflow), which is what our CWE
     * mapping tells --exit-on-error-type to trap on. */
    png_process_data(png_ptr, info_ptr, (png_bytep)buf, len);

    png_destroy_read_struct(&png_ptr, &info_ptr, 0);
    return 0;
}
