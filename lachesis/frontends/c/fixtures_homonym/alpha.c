/* Two translation units, one name. `funcA` is `static` in both, so C scoping decides
 * each call exactly and file-locally -- and each call is also *intra*-TU, so clang
 * decides it too and stamps `primary_target_id`. That is worth stating plainly because
 * an earlier note here claimed the opposite: the cross-TU post-pass's `sole_definition`
 * does give up on two same-named definitions, but it never gets asked, because nothing
 * here crosses a translation unit.
 *
 * The fixture is still the one the resolution tier needs, for a sharper reason. It is
 * the case where the name alone is not enough and the file is: strip the frontend's
 * answer out (`HomonymResolutionTests._blinded`) and only `static` in the caller's own
 * file separates the two definitions. So it tests the ladder's second rung in
 * isolation *and* pins the superset property -- blinded and unblinded must agree.
 */
static int funcA(int value)
{
    return value + 1;
}

int alpha_entry(int value)
{
    return funcA(value);
}
