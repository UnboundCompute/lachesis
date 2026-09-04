#include <stdlib.h>

struct box { char *p; };

/* EXPECT aggregate-copy-alias double-free: the struct copy `b = a` aliases the
   pointer, and both copies free the same block. KNOWN FALSE-NEGATIVE today
   (alias through aggregate copy is not tracked) — documented as xfail. */
void aggregate_copy_alias_bug(int n) {
    struct box a;
    a.p = malloc(n);
    if (!a.p) return;
    struct box b = a;
    free(a.p);
    free(b.p);
}

/* CLEAN: single owner freed once. */
void aggregate_copy_alias_clean(int n) {
    struct box a;
    a.p = malloc(n);
    if (!a.p) return;
    free(a.p);
}
