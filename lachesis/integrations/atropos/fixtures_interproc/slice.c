/* Atropos C interprocedural return-summary fixture.
 *
 * Explicit prototypes, no system headers, so clang keeps plain call nodes named
 * exactly as the catalog keys them. The point of the slice: a thin wrapper
 * obtains an untrusted value and returns it; a caller feeds that result to a
 * sink. Without the return-to-callsite edge the getenv source dies at the
 * wrapper's `return` and never reaches `system` in the caller.
 */
char *getenv(const char *name);
int   system(const char *cmd);

char *get_gateway(void) {
    return getenv("GATEWAY");   /* ReturnValue source; flows to this return */
}

void h(void) {
    char *p = get_gateway();    /* call result must carry the wrapped source */
    system(p);                  /* Argument[0] command-injection sink */
}
