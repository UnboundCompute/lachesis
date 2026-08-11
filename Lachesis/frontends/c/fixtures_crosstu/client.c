/* Cross-TU fixture: a caller in a different TU.
 *
 * client_run calls lib_compute, but this TU only sees the lib.h prototype — the
 * definition lives in lib.c. Intra-TU resolution therefore leaves the call
 * "dynamic-or-unresolved"; the cross-TU linker must retarget it to the lib.c
 * definition (resolution="cross-tu") and emit CALLS(client_run -> lib_compute).
 */
#include "lib.h"

int client_run(int n)
{
    return lib_compute(n) + 1;
}
