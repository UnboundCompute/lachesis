#include <stdio.h>

/* EXPECT unchecked-return-deref @ the fseek on an unchecked fopen result.
   The handle is closed so there is no incidental leak. KNOWN FALSE-NEGATIVE
   as a distinct family today — documented as xfail. */
long unchecked_return_deref_bug(const char *path) {
    FILE *f = fopen(path, "r");
    fseek(f, 0, 2);
    long n = ftell(f);
    fclose(f);
    return n;
}

/* CLEAN: checked before use, closed. */
long unchecked_return_deref_clean(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, 2);
    long n = ftell(f);
    fclose(f);
    return n;
}
