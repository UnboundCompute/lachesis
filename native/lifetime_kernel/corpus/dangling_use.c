#include <stdlib.h>

/* EXPECT use-after-free (dangling-use variant): freed through an alias `q`,
   then the original name `p` is used. Guarded, so the only defect is the
   dangling deref. Dangling-use is reported under the use-after-free family. */
int dangling_use_bug(int n) {
    char *p = malloc(n);
    if (!p) return 0;
    char *q = p;
    free(q);
    return p[0];
}

/* CLEAN: no use after the alias free; guarded, freed once. */
void dangling_use_clean(int n) {
    char *p = malloc(n);
    if (!p) return;
    char *q = p;
    free(q);
}
