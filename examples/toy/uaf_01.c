/* CWE-416 — use after free.
 * The function frees `buf` on an error path but still reads from it when
 * the recovery branch fires. KLEE's posix-runtime libc will flag the
 * load from freed memory as a pointer error.
 */
#include <stdlib.h>
#include <stdint.h>

int process_record(uint8_t mode, uint8_t tag) {
    char *buf = (char *)malloc(32);
    if (!buf) return -1;
    buf[0] = (char)tag;
    if (mode == 0) {
        free(buf);                 /* freed on this path */
    }
    if (tag == 0x42) {
        /* BUG: when mode==0 we reach here with buf dangling */
        return (int)buf[0];        /* UAF read */
    }
    if (mode != 0) free(buf);
    return 0;
}
