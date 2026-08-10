/* Dispatch-table type defined in a header OUTSIDE the ingested source dir — the
 * kernel shape (e.g. `struct net_device_ops` in netdevice.h). Because this header
 * is never parsed as its own compiler root, its FieldDecls never become graph
 * nodes; the ops-struct binding must recover the slot layout (field names + order)
 * from the .c's own included copy of this RecordDecl. */
struct driver_ops {
    int (*start)(int mode);
    void (*stop)(void);
};
extern void register_driver(const struct driver_ops *ops);
