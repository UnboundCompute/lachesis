/* Atropos C vertical-slice fixture.
 *
 * Explicit prototypes, no system headers: this keeps clang from rewriting
 * memcpy into a _FORTIFY_SOURCE builtin, so the graph carries plain call nodes
 * named exactly as the Atropos catalog keys them. Exercises the C gold set:
 * memcpy (sink + copy summary), read (buffer source), getenv (return source),
 * strdup (in->return summary), system (command sink).
 */
typedef unsigned long size_t;
typedef long ssize_t;

void   *memcpy(void *dst, const void *src, size_t n);
ssize_t read(int fd, void *buf, size_t count);
char   *getenv(const char *name);
char   *strdup(const char *s);
int     system(const char *cmd);

void f(int fd, char *dst, const char *src, size_t n) {
    char buf[64];
    read(fd, buf, n);          /* Argument[1] (buf) is the untrusted-input sink of the read */
    memcpy(dst, src, n);       /* Argument[2] (n) size sink; Argument[1]->Argument[0] copy */
    char *e = getenv("PATH");  /* ReturnValue is an untrusted-input source */
    char *d = strdup(e);       /* Argument[0]->ReturnValue copy summary */
    system(d);                 /* Argument[0] command-injection sink */
}
