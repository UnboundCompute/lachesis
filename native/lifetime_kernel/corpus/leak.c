#include <stdlib.h>

/* EXPECT leak @ the allocation. Guarded (no null-deref) but never freed —
   leak is the only defect. */
void leak_bug(int n) {
    char *p = malloc(n);
    if (!p) return;
    p[0] = 1;
}

/* CLEAN: guarded, used, freed. */
void leak_clean(int n) {
    char *p = malloc(n);
    if (!p) return;
    p[0] = 1;
    free(p);
}
