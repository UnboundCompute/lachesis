/* Cross-TU fixture: the body-bearing definition of lib_compute.
 *
 * declaration_only=False here; this is the node every cross-TU call to
 * `lib_compute` must resolve to.
 */
#include "lib.h"

int lib_compute(int x)
{
    return x * 2;
}
