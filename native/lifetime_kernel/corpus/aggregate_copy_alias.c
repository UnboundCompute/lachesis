#include <stdlib.h>

struct box { char *p; };

/* EXPECT double-free: the by-value struct copy `struct box b = a;` aliases the
   pointer field, so `free(a.p)` and `free(b.p)` release the same block. The
   verdict is the double-free that composes through the field alias -- the
   aggregate-copy-alias itself is only a lead (a PARTIAL row), never a verdict. */
void aggregate_copy_alias_bug(int n) {
    struct box a;
    a.p = malloc(n);
    if (!a.p) return;
    struct box b = a;
    free(a.p);
    free(b.p);
}

/* EXPECT double-free (assignment form): same alias, created by `b = a;` rather
   than an initializer, so the assignment arm of the aggregate-copy lowering is
   exercised too. */
void aggregate_copy_assign_bug(int n) {
    struct box a, b;
    a.p = malloc(n);
    if (!a.p) return;
    b = a;
    free(a.p);
    free(b.p);
}

/* CLEAN: a by-value struct copy is made, but only one owner frees. The copy
   creates the field alias (a lead) yet there is no second release, so NO
   COMPLETE verdict may fire -- a struct copy alone is not a bug. */
void aggregate_copy_alias_clean(int n) {
    struct box a;
    a.p = malloc(n);
    if (!a.p) return;
    struct box b = a;
    (void)b;
    free(a.p);
}
