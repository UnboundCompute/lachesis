#!/usr/bin/env bash
# Verify the source distribution from a clean virtualenv.
#
# A source distribution uses the build backend again when pip installs it, so it can
# contain a different set of files from the wheel. Keep this check intentionally
# separate from verify_wheel.sh: it proves the sdist's build metadata, package data,
# and console-script entry points without depending on the repository checkout.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sdist="${1:-}"
if [[ -z "$sdist" ]]; then
  sdist="$(ls -t "$repo_root"/dist/lachesis_cpg-*.tar.gz 2>/dev/null | head -1 || true)"
fi
if [[ -z "$sdist" || ! -f "$sdist" ]]; then
  echo "no source distribution found; run: python3.11 -m build" >&2
  exit 1
fi
sdist="$(cd "$(dirname "$sdist")" && pwd)/$(basename "$sdist")"
python_bin="${PYTHON:-python3}"

"$python_bin" - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("verify_sdist.sh requires Python 3.10+")
PY

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
cd "$workspace"

echo "installing source distribution into $workspace/v"
"$python_bin" -m venv v
./v/bin/python -m pip install --quiet --disable-pip-version-check --no-input --upgrade pip
./v/bin/python -m pip install --quiet --disable-pip-version-check --no-input "$sdist"

# One console script now: the reader is a single `lachesis` with subcommands.
[[ -x "./v/bin/lachesis" ]] || { echo "FAIL: missing lachesis" >&2; exit 1; }
./v/bin/lachesis --version >/dev/null
for verb in build enrich analyze query plan candidates mcp; do
  ./v/bin/lachesis "$verb" --help >/dev/null || { echo "FAIL: verb $verb" >&2; exit 1; }
done

./v/bin/python - <<'PY'
from pathlib import Path
import lachesis.frontends.typescript as frontend

compiler = Path(frontend.__file__).parent / "vendor" / "typescript" / "lib" / "typescript.js"
if not compiler.is_file():
    raise SystemExit("FAIL: sdist install lost the vendored TypeScript compiler")
print(f"sdist install is usable ({compiler})")
PY

echo "PASS: source distribution installs outside the checkout"
