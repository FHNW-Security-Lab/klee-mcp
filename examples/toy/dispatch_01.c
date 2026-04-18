/* Reachability example.
 * `inner_sink` has a classic stack-bof (CWE-121). It is only called by
 * `outer_dispatch` when opcode == 0x42. A whole-program symex on main
 * would be wasteful; an LLM-guided reachability check from
 * outer_dispatch should find the reaching input quickly.
 */
#include <stddef.h>
#include <stdint.h>

int inner_sink(const char *buf, unsigned int len) {
    char stack_dst[16];
    if (len > 256) return -1;
    for (unsigned int i = 0; i < len; i++) {
        stack_dst[i] = buf[i];                /* OOB when len > 16 */
    }
    return (int)stack_dst[0];
}

int noop_path(const char *buf, unsigned int len) {
    (void)buf; (void)len;
    return 0;
}

int outer_dispatch(uint8_t opcode, const char *buf, unsigned int len) {
    if (opcode == 0x42) {
        return inner_sink(buf, len);          /* reachable only on this branch */
    }
    return noop_path(buf, len);
}
