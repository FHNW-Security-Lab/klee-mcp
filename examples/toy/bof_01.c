/* CWE-121 — stack buffer overflow.
 * vulnerable_copy copies up to 256 bytes from buf into a 16-byte stack
 * buffer when the caller-supplied length is unconstrained.
 */
#include <string.h>
#include <stddef.h>

int vulnerable_copy(const char *buf, unsigned int len) {
    char stack_dst[16];
    if (len > 256) return -1;          /* caller bound; still > 16 allowed */
    for (unsigned int i = 0; i < len; i++) {
        stack_dst[i] = buf[i];         /* OOB write when len > 16 */
    }
    return (int)stack_dst[0];
}
