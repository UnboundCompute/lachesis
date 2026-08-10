/* The ops table lives here; the struct type lives in a header outside this dir.
 * drv_start / drv_stop are entry-point handlers dispatched through the table, with
 * no in-tree call-site — so reverse navigation depends entirely on the
 * MAY_INVOKE(driver_ops -> handler) registration edges. */
#include "../include/driver_ops.h"

static int drv_start(int mode) { return mode + 1; }
static void drv_stop(void) { }

static const struct driver_ops driver_ops = {
    .start = drv_start,
    .stop = drv_stop,
};

void init_driver(void) { register_driver(&driver_ops); }
