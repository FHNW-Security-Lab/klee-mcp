/* Focused libpng audit: build a valid PNG prefix up through PLTE, then
 * push a symbolic tRNS chunk payload. Targets CWE-190 / CWE-125 in
 * png_handle_tRNS (implicit uint32 -> uint16 cast on length field).
 *
 * The fixed prefix (signature + IHDR + PLTE) gets libpng into state
 * `PNG_HAVE_PLTE` with `color_type = PNG_COLOR_TYPE_PALETTE` and
 * `num_palette = 1`, which makes tRNS-palette-mode parsing reachable.
 * Only the 4-byte length field and (up to 4) data bytes of the tRNS
 * chunk are symbolic; KLEE searches that tight state space for an
 * OOB read.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

/* CRC-32/IEEE over `buf[0..len-1]`. Small table-free version is enough
 * — libpng recomputes CRC on receipt, and if ours disagrees libpng
 * raises a benign warning rather than abort. */
static unsigned int simple_crc(const unsigned char *buf, unsigned int len) {
    unsigned int c = 0xFFFFFFFFU;
    for (unsigned int i = 0; i < len; i++) {
        c ^= buf[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320U & -(int)(c & 1));
    }
    return c ^ 0xFFFFFFFFU;
}

int fuzz_trns_payload(const unsigned char *payload, unsigned int payload_len) {
    if (payload_len > 4) return -1;

    /* Fixed prefix: PNG signature, IHDR (1x1, paletted), PLTE (1 entry).
     * Layout per byte:
     *   [8]  signature
     *   [8+13+8+4] IHDR chunk: length=13, "IHDR", 13 bytes of data, CRC
     *   [8+12*2+3+4] PLTE chunk: length=3, "PLTE", 3 bytes RGB, CRC
     */
    unsigned char png_sig[8]  = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    unsigned char ihdr_chunk[12 + 13] = {
        0, 0, 0, 13,                  /* length */
        'I', 'H', 'D', 'R',           /* type */
        0, 0, 0, 1,                   /* width  */
        0, 0, 0, 1,                   /* height */
        8,                            /* bit depth */
        3,                            /* color type = palette */
        0, 0, 0,                      /* compression, filter, interlace */
    };
    unsigned int ihdr_crc = simple_crc(ihdr_chunk + 4, 17);
    ihdr_chunk[21] = (ihdr_crc >> 24) & 0xFF;
    ihdr_chunk[22] = (ihdr_crc >> 16) & 0xFF;
    ihdr_chunk[23] = (ihdr_crc >>  8) & 0xFF;
    ihdr_chunk[24] =  ihdr_crc        & 0xFF;

    unsigned char plte_chunk[12 + 3] = {
        0, 0, 0, 3,
        'P', 'L', 'T', 'E',
        0xFF, 0x00, 0x00,
    };
    unsigned int plte_crc = simple_crc(plte_chunk + 4, 7);
    plte_chunk[11] = (plte_crc >> 24) & 0xFF;
    plte_chunk[12] = (plte_crc >> 16) & 0xFF;
    plte_chunk[13] = (plte_crc >>  8) & 0xFF;
    plte_chunk[14] =  plte_crc        & 0xFF;

    /* tRNS chunk with symbolic length and symbolic payload. We cap
     * payload_len to 4 bytes (which is well below the PLTE palette size
     * of 1, so any length > 1 should trigger a bounds path inside
     * png_handle_tRNS). */
    unsigned char trns_chunk[12 + 4] = {
        0, 0, 0, (unsigned char)payload_len,
        't', 'R', 'N', 'S',
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    for (unsigned int i = 0; i < payload_len && i < 4; i++)
        trns_chunk[8 + i] = payload[i];
    /* bogus CRC; libpng will warn but proceed if we disable CRC check */
    unsigned int trns_crc = simple_crc(trns_chunk + 4, 4 + payload_len);
    unsigned int crc_pos = 8 + payload_len;
    if (crc_pos + 3 < sizeof(trns_chunk)) {
        trns_chunk[crc_pos]     = (trns_crc >> 24) & 0xFF;
        trns_chunk[crc_pos + 1] = (trns_crc >> 16) & 0xFF;
        trns_chunk[crc_pos + 2] = (trns_crc >>  8) & 0xFF;
        trns_chunk[crc_pos + 3] =  trns_crc        & 0xFF;
    }

    png_structrp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, 0, 0, 0);
    if (png_ptr == 0) return -2;
    png_inforp info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == 0) { png_destroy_read_struct(&png_ptr, 0, 0); return -3; }
    png_set_progressive_read_fn(png_ptr, 0, 0, 0, 0);

    png_process_data(png_ptr, info_ptr, png_sig,    sizeof(png_sig));
    png_process_data(png_ptr, info_ptr, ihdr_chunk, sizeof(ihdr_chunk));
    png_process_data(png_ptr, info_ptr, plte_chunk, sizeof(plte_chunk));
    png_process_data(png_ptr, info_ptr, trns_chunk, 8 + payload_len + 4);

    png_destroy_read_struct(&png_ptr, &info_ptr, 0);
    return 0;
}
