/* Whole-library harness for libjpeg-turbo 3.0.4.
 *
 * Standard fuzzer-style entry: create a decompress object, hand it a
 * small symbolic byte buffer via jpeg_mem_src, and call
 * jpeg_read_header. This exercises every marker parser reachable
 * from the SOI/SOF/DHT/DQT/DRI/DAC/SOS dispatch without forcing the
 * LLM to speak libjpeg internals. Expected verdict on a 12-byte
 * buffer under 16 GB memory cap: infeasible (KLEE will reject
 * malformed markers early), or confirmed if a real bug is reached.
 */
#include <stddef.h>
#include <stdint.h>

struct jpeg_decompress_struct;
struct jpeg_error_mgr;

typedef struct jpeg_decompress_struct *j_decompress_ptr;
typedef struct jpeg_error_mgr *j_error_mgr_ptr;
typedef int boolean;

/* libjpeg's error manager is large; we reserve a page-sized blob and
 * cast. Real initialization happens via jpeg_std_error. */
struct _cinfo_blob { unsigned char bytes[4096]; };
struct _err_blob   { unsigned char bytes[ 512]; };

extern struct jpeg_error_mgr *jpeg_std_error(struct jpeg_error_mgr *err);
extern void jpeg_CreateDecompress(j_decompress_ptr cinfo, int version, size_t structsize);
extern void jpeg_mem_src(j_decompress_ptr cinfo, const unsigned char *inbuffer, unsigned long insize);
extern int  jpeg_read_header(j_decompress_ptr cinfo, boolean require_image);
extern void jpeg_destroy_decompress(j_decompress_ptr cinfo);

#define JPEG_LIB_VERSION 80

int fuzz_jpeg_header(const unsigned char *buf, unsigned long len) {
    if (len > 64) return -1;

    struct _cinfo_blob cinfo_blob;
    struct _err_blob   err_blob;
    j_decompress_ptr cinfo = (j_decompress_ptr)&cinfo_blob;

    /* Point cinfo->err at our error manager. Layout note: struct
     * jpeg_decompress_struct begins with `struct jpeg_error_mgr *err`,
     * so the first pointer-sized slot is err. */
    *(void **)&cinfo_blob.bytes[0] = jpeg_std_error((struct jpeg_error_mgr *)&err_blob);

    jpeg_CreateDecompress(cinfo, JPEG_LIB_VERSION, sizeof(struct _cinfo_blob));
    jpeg_mem_src(cinfo, buf, len);
    (void)jpeg_read_header(cinfo, 1 /* TRUE */);
    jpeg_destroy_decompress(cinfo);
    return 0;
}
