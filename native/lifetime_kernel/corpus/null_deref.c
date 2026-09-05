#include <stdlib.h>

/* EXPECT null-deref @ the unchecked deref. Freed (no leak) — null-deref is
   the only defect. */
int null_deref_bug(int n) {
    char *p = malloc(n);
    int v = p[0];
    free(p);
    return v;
}

/* CLEAN: guarded before use, freed. */
int null_deref_clean(int n) {
    char *p = malloc(n);
    if (!p) return -1;
    int v = p[0];
    free(p);
    return v;
}
