/* Preprocessor macro fixture.
 *
 * The Clang JSON AST is post-preprocessor, so these #defines are expanded and
 * gone by the time the AST is dumped. The dedicated -E -dD macro pass recovers
 * them as first-class `macro` nodes: object-like (MAX_PATH, EMPTY) and
 * function-like (SQUARE, with a parameter list), each attributed to its exact
 * definition line and made addressable to search / read_body.
 */
#define MAX_PATH 4096
#define EMPTY
#define SQUARE(x) ((x) * (x))

int scaled(int n) {
    return SQUARE(n) + MAX_PATH;
}
