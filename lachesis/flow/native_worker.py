"""Child entrypoint that runs one whole-graph native pass and exits.

``native_lifetime._run_isolated`` spawns this as ``python -m lachesis.flow.native_worker
<op> <input> <output> <catalog>`` with ``LACHESIS_ISOLATE_NATIVE`` cleared, so the pass
runs in-process here. The pass allocates a large native arena that the system allocator
keeps resident after the FFI returns; letting this child exit hands that memory straight
back to the OS, so back-to-back passes in ``enrich`` never stack their transients.

Only file paths cross in, and the pass writes the identical sidecar it would have written
in-process -- isolation is byte-transparent. The FFI status is surfaced as the exit code:
0 on success, non-zero on failure, which the parent maps back to a ``RuntimeError``.
"""
from __future__ import annotations

import sys


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(f"usage: {argv[0]} <op> <input> <output> <catalog>", file=sys.stderr)
        return 2
    _, op, input_path, output_path, catalog = argv
    catalog_path = catalog or None  # empty string means "no catalog"

    from lachesis.flow import native_lifetime as nl

    try:
        if op == "pass2":
            nl.run_pass2_path(input_path, output_path, catalog_path)
        elif op == "semantic":
            nl.write_semantic_path(input_path, output_path, catalog_path)
        elif op == "match":
            nl.match_semantic_path(input_path, output_path, catalog_path)
        else:
            print(f"unknown native pass {op!r}", file=sys.stderr)
            return 2
    except Exception as error:  # surface the failure as a non-zero exit
        print(f"native pass {op!r} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
