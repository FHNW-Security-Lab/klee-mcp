/* CWE-190 — integer overflow bypassing a size check.
 * `total = count * per_entry` wraps; if it wraps small, the bound check
 * passes, and then the loop uses `count` (not total) to write into a
 * fixed-size arena. Classic size-check bypass.
 */
#include <stddef.h>
#include <stdint.h>

static uint8_t arena[64];

int compute_capacity(uint32_t count, uint32_t per_entry) {
    uint32_t total = count * per_entry;       /* BUG: multiplies can wrap */
    if (total > sizeof(arena)) return -1;
    for (uint32_t i = 0; i < count; i++) {
        arena[i] = (uint8_t)i;                /* OOB when count >> 64 */
    }
    return (int)total;
}
