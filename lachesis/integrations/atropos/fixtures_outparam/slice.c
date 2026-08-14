/* Atropos C out-parameter write-back fixture.
 *
 * Explicit prototypes, no system headers, so clang keeps plain call nodes named
 * exactly as the catalog keys them. The point of the slice: `read` does not read
 * `buf`, it *fills* it, and the untrusted bytes must travel through `buf` into
 * the `system` argument. Without the out-param write-back the `read` source
 * strands on its own argument node and never reaches the `system` sink.
 */
typedef unsigned long size_t;
typedef long ssize_t;

ssize_t read(int fd, void *buf, size_t count);
int     system(const char *cmd);

void g(int fd, size_t n) {
    char buf[64];
    read(fd, buf, n);   /* Argument[1] (buf): untrusted-input source, an out-param write */
    system(buf);        /* Argument[0] (buf): command-injection sink */
}
