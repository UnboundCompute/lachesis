#include <stdlib.h>

/* EXPECT realloc-failure-leak: self-assigning realloc overwrites `buf` with
   NULL on failure, leaking the old block. */
char *realloc_failure_leak_bug(char *buf, int n) {
    buf = realloc(buf, n);
    if (!buf) return NULL;
    return buf;
}

/* CLEAN: the idiomatic distinct-slot realloc keeps the old block on failure.
   This is the regression control for the leak / dangling-use false positive —
   it must yield ZERO temporal findings. */
char *realloc_idiom_clean(char *buf, int n) {
    char *tmp = realloc(buf, n);
    if (!tmp) return buf;
    return tmp;
}
