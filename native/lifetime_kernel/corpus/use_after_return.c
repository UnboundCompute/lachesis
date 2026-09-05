/* EXPECT use-after-return: address of a stack local escapes the frame. */
int *use_after_return_bug(void) {
    int local = 7;
    return &local;
}

/* CLEAN: returns a value, not a dangling stack address. */
int use_after_return_clean(void) {
    int local = 7;
    return local;
}
