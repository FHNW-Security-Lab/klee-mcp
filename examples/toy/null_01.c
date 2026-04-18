/* CWE-476 — NULL pointer dereference.
 * If `cfg` is NULL the function dereferences it directly; there is no
 * guard, just a sloppy length check.
 */
#include <stddef.h>

typedef struct {
    int magic;
    int size;
    char name[32];
} cfg_t;

int read_magic(cfg_t *cfg, int fallback) {
    if (fallback < 0) return -1;
    /* BUG: cfg may be NULL; no check before dereference */
    if (cfg->magic == 0xC0FFEE) {
        return cfg->size;
    }
    return fallback;
}
