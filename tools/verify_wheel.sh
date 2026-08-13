#!/usr/bin/env bash
# Verify a built wheel the way a stranger will meet it.
#
# A green test suite in this checkout says nothing about the wheel: the checkout has a
# node_modules, an editable install, fixtures on disk and this repository's root on
# sys.path, and the wheel has none of that. So this installs the built artifact into a
# throwaway virtualenv, cd's somewhere unrelated to this repository, and drives it
# through the console scripts only.
#
# The check that matters most is TypeScript. It is the one that passes here and fails
# for a user, because here the frontend can always fall back to the repo's node_modules
# and on their machine it cannot.
#
# Usage: tools/verify_wheel.sh [path/to/dist/lachesis_cpg-*.whl]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wheel="${1:-}"
if [[ -z "$wheel" ]]; then
  wheel="$(ls -t "$repo_root"/dist/lachesis_cpg-*.whl 2>/dev/null | head -1 || true)"
fi
if [[ -z "$wheel" || ! -f "$wheel" ]]; then
  echo "no wheel found; run: python3 -m build" >&2
  exit 1
fi
wheel="$(cd "$(dirname "$wheel")" && pwd)/$(basename "$wheel")"
python_bin="${PYTHON:-python3}"

say() { printf '\n== %s\n' "$1"; }

say "wheel under test"
echo "$wheel"

say "the distribution claims one top-level name"
# `nav` and `planner` are ordinary English words. If either is ever installed at top
# level again, it silently shadows a module in somebody else's project.
top_level="$("$python_bin" - "$wheel" <<'PY'
import sys, zipfile
names = {n.split("/")[0] for n in zipfile.ZipFile(sys.argv[1]).namelist()}
print(" ".join(sorted(n for n in names if not n.endswith(".dist-info"))))
PY
)"
echo "top-level: $top_level"
[[ "$top_level" == "lachesis" ]] || { echo "FAIL: expected exactly 'lachesis'" >&2; exit 1; }

say "the TypeScript compiler is inside the wheel"
"$python_bin" - "$wheel" <<'PY'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
prefix = "lachesis/frontends/typescript/vendor/typescript/"
if prefix + "lib/typescript.js" not in names:
    sys.exit("FAIL: no vendored typescript.js -- run tools/vendor_typescript.py, rebuild")
declarations = [n for n in names if n.startswith(prefix + "lib/lib.") and n.endswith(".d.ts")]
if not declarations:
    sys.exit("FAIL: vendored compiler has no default library declarations")
if prefix + "LICENSE.txt" not in names:
    sys.exit("FAIL: vendored compiler ships without its licence")
print(f"ok: compiler + {len(declarations)} library declarations + LICENSE.txt")
PY

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
cd "$workspace"

say "install into a clean virtualenv"
"$python_bin" -m venv v
./v/bin/pip install --quiet --upgrade pip
./v/bin/pip install --quiet "$wheel"
echo "installed into $workspace/v"

say "imports resolve"
./v/bin/python -c "import lachesis, lachesis.nav, lachesis.planner; print('ok')"

say "console scripts are on PATH"
for script in lachesis-analyze lachesis-query lachesis-mcp lachesis-plan; do
  [[ -x "./v/bin/$script" ]] || { echo "FAIL: missing $script" >&2; exit 1; }
  echo "  $script"
done

say "analyse a TypeScript project with no npm install anywhere"
mkdir -p project/src
cat > project/src/service.ts <<'TS'
export interface Request { body: { id: string } }

function findById(id: string): string { return id; }

export function handle(request: Request): string {
  return findById(request.body.id);
}
TS
./v/bin/lachesis-analyze project /tmp/verify-wheel.kuzu
./v/bin/lachesis-query --format text /tmp/verify-wheel.kuzu overview | tee overview.txt
grep -q "typescript" overview.txt \
  || { echo "FAIL: TypeScript was not analysed -- vendored compiler not reachable" >&2; exit 1; }

say "analyse a Python project"
mkdir -p pyproject_src
cat > pyproject_src/app.py <<'PY'
def lookup(identifier):
    return identifier


def handle(request):
    return lookup(request["id"])
PY
./v/bin/lachesis-analyze pyproject_src /tmp/verify-wheel-py.kuzu

say "the MCP server speaks MCP over stdio"
./v/bin/python - <<'PY'
import json, os, subprocess, sys

server = subprocess.Popen(
    [os.path.join(os.getcwd(), "v", "bin", "lachesis-mcp"), "/tmp/verify-wheel.kuzu"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)


def call(message):
    server.stdin.write(json.dumps(message) + "\n")
    server.stdin.flush()
    return json.loads(server.stdout.readline())


try:
    initialized = call({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "verify", "version": "0"}}})
    listed = call({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
finally:
    server.terminate()
    server.wait(timeout=10)

tools = sorted(tool["name"] for tool in listed["result"]["tools"])
print("server:", initialized["result"]["serverInfo"])
print(f"{len(tools)} tools: {', '.join(tools)}")
for required in ("search", "callers", "callees", "reaches"):
    if required not in tools:
        sys.exit(f"FAIL: MCP server does not expose {required}")
PY

say "PASS"
echo "the wheel installs and works with no repository, no node_modules and no npm."
