/* Negative control: looks similar to bof_01 but is actually safe.
 * If the LLM flags this as vulnerable, KLEE should return INFEASIBLE.
 */
#include <string.h>
#include <stddef.h>

int safe_copy(const char *buf, unsigned int len) {
    char stack_dst[16];
    if (len >= sizeof(stack_dst)) return -1;   /* real bound */
    for (unsigned int i = 0; i < len; i++) {
        stack_dst[i] = buf[i];
    }
    return (int)stack_dst[0];
}
