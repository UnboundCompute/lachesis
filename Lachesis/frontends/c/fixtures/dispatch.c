/* Ops-struct + function-pointer dispatch fixture.
 *
 * Exercises the indirect-dispatch resolution: an ops-struct initializer binds
 * slots to concrete functions (.read = ext4_read), a pointer variable binds to a
 * function (fp = ext4_read), and a function passed by name is a callback. The
 * dispatch call-sites should resolve to MAY_INVOKE; a function handed to a callee
 * should be PASSES_CALLBACK; the raw slots stay visible as READS_CALLEE.
 */
typedef int (*read_fn)(const char *path);

struct file_operations {
    read_fn read;
    read_fn write;
};

static int ext4_read(const char *p) { return p[0]; }
static int ext4_write(const char *p) { return p[1]; }

static const struct file_operations ext4_fops = {
    .read = ext4_read,
    .write = ext4_write,
};

int dispatch_read(struct file_operations *ops, const char *p) {
    return ops->read(p);
}

void register_cb(read_fn cb);

int wire(void) {
    read_fn fp = ext4_read;
    register_cb(ext4_write);
    return fp("/x");
}
