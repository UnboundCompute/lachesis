#include <stdlib.h>

/* EXPECT use-after-free @ the deref after free. Guarded (no null-deref),
   freed (no leak) — use-after-free is the only defect. */
int use_after_free_bug(int n) {
    char *p = malloc(n);
    if (!p) return 0;
    free(p);
    return p[0];
}

/* CLEAN: use precedes the free; guarded, freed once. */
int use_after_free_clean(int n) {
    char *p = malloc(n);
    if (!p) return 0;
    int v = p[0];
    free(p);
    return v;
}
