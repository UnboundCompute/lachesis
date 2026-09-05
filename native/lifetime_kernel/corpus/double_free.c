#include <stdlib.h>

/* EXPECT double-free @ the second free. malloc is guarded so no null-deref,
   and the block is freed so no leak — double-free is the only defect. */
void double_free_bug(int n) {
    char *p = malloc(n);
    if (!p) return;
    free(p);
    free(p);
}

/* CLEAN: guarded, freed exactly once. No defect on any path. */
void double_free_clean(int n) {
    char *p = malloc(n);
    if (!p) return;
    free(p);
}
