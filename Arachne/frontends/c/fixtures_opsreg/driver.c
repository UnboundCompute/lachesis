/* Ops-struct registration fixture (indirect dispatch / entry-point reverse nav).
 *
 * `drv_start` / `drv_stop` are entry-point handlers registered into a dispatch
 * table (`driver_ops`) and handed to a registrar; the runtime invokes them
 * through the table, so there is NO in-tree call-site for either. Without a
 * registration edge, callers(drv_start) is empty and an agent cannot walk from a
 * leaf handler back to the ops table it belongs to.
 *
 * The frontend models each slot binding as MAY_INVOKE(driver_ops -> handler), so
 * the handler's fan-in surfaces the table (and slot) it is registered in.
 */
struct driver_ops {
    int (*start)(int mode);
    void (*stop)(void);
};

static int drv_start(int mode)
{
    return mode + 1;
}

static void drv_stop(void)
{
}

static const struct driver_ops driver_ops = {
    .start = drv_start,
    .stop = drv_stop,
};

/* Hand the table to a registrar so it is genuinely "used" — the runtime, not any
 * in-tree caller, dispatches through it later. */
extern void register_driver(const struct driver_ops *ops);

void init_driver(void)
{
    register_driver(&driver_ops);
}
