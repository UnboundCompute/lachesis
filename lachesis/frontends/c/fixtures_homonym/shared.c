/* Calls neither `funcA` -- it cannot, they are static -- but both entry points, so a
 * cone walked from here has to reach both definitions and pick the right one at each
 * hop rather than collapsing them into a single name. */
int alpha_entry(int value);
int beta_entry(int value);

int shared_entry(int value)
{
    return alpha_entry(value) + beta_entry(value);
}
