/* EXPECT uninitialized-use @ the read of `x` before any store.
   KNOWN FALSE-NEGATIVE today: not yet detected — documented as xfail. */
int uninitialized_use_bug(void) {
    int x;
    return x + 1;
}

/* CLEAN: initialized before read. */
int uninitialized_use_clean(void) {
    int x = 0;
    return x + 1;
}
