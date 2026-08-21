# Releasing Lachesis

Lachesis publishes to PyPI as [`lachesis-cpg`](https://pypi.org/project/lachesis-cpg/).
This is the checklist for cutting a release. It exists because one step — vendoring the
TypeScript compiler — is invisible from the repository, and a wheel built without it
installs fine and then fails on the first TypeScript project it sees.

## What ships

The distribution is pure Python plus two things that are not Python:

- `lachesis/frontends/typescript/build_graph.mjs`, the Node frontend, and the copy of
  the TypeScript compiler next to it under `vendor/`. The compiler is **not in version
  control** (see `.gitignore`); `tools/vendor_typescript.py` fetches the pinned version
  and `MANIFEST.in` carries it into the sdist.
- the fixture corpora under each frontend, so the parity suite can run from an install.

The C frontend has no vendored component. It shells out to whatever `clang` is on the
machine, and degrades to "no C analysis" when there is none.

## Before you tag

1. Working tree is clean, and you are on the release commit (normally `main` or an
   annotated release candidate branch).
2. Bump `version` in `pyproject.toml`. Lachesis is pre-1.0, so the graph schema and the
   nav tool surface may still change between minor versions; say so in the changelog
   entry rather than in a patch release note nobody reads.
3. Run the parity suite against a clean checkout:
   ```
python3.11 -m pip install -e ".[dev]" && npm install
make PYTHON=python3.11 check
   ```
   It must be fully green. The suite is the release gate — there is no separate one.

## Build

```
python3.11 tools/vendor_typescript.py          # fetch the pinned compiler
python3.11 tools/vendor_typescript.py --check  # confirm it landed
rm -rf dist build *.egg-info
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
python3.11 -m build                            # sdist + wheel
```

`SOURCE_DATE_EPOCH` anchors archive timestamps to the release commit, so rebuilding
the same source produces byte-identical distributions instead of changing hashes on
every run.

`--check` is not ceremony. Everything else in the build fails loudly when it goes
wrong; a missing vendor directory does not, and the symptom surfaces on a stranger's
machine rather than yours.

## Verify the artifacts, not the repo

The point of this section is that a passing test suite in a checkout proves nothing
about a wheel. Test the built artifacts, in a virtualenv that has no relationship to
this repository, from a directory that is not this repository.

```
python3.11 -m twine check dist/*

cd $(mktemp -d)
python3.11 -m venv v && ./v/bin/pip install /path/to/dist/lachesis_cpg-*.whl
```

Then confirm all four of these:

- **The namespace is one name.** `unzip -l dist/*.whl | grep -c '^.*lachesis/'` should
  account for every module, and nothing outside `lachesis/` should be installed.
  ```
  ./v/bin/python -c "import lachesis, lachesis.nav, lachesis.planner"
  ```
- **The console scripts exist and run**: `lachesis-analyze`, `lachesis-query`,
  `lachesis-mcp`, `lachesis-plan`.
- **TypeScript analysis works with no `npm install` anywhere.** This is the vendoring
  check, and it is the one that fails when the vendor step was skipped:
  ```
  mkdir -p src && printf 'export function f(x: string) { return x; }\n' > src/a.ts
  ./v/bin/lachesis-analyze src /tmp/rel.kuzu
  ./v/bin/lachesis-query --format text /tmp/rel.kuzu overview
  ```
  The output must name `typescript-compiler-api` among its frontends.
- **The MCP server starts and lists its tools** over stdio against that graph. The
  verifier also launches the product command (`lachesis mcp <source>`) so the
  source-indexing handoff and the MCP initialize/tools handshake are covered, not
  only the lower-level `lachesis-mcp` entry point.

`tools/verify_wheel.sh` and `tools/verify_sdist.sh` run these checks for both artifact
types. CI runs them on every push and pull request in the `package` job, so a packaging
mistake surfaces long before release day.

The `release artifacts` workflow repeats the artifact gate for every `v*` tag and
uploads the verified wheel and sdist as workflow artifacts. It does not publish
automatically; the TestPyPI and PyPI uploads below remain an explicit release step.

## Publish

Upload to TestPyPI first, install from it, and repeat the four checks above against
*that* install — it is the only way to catch a packaging problem that only appears
after a round trip through an index.

```
python3.11 -m twine upload --repository testpypi dist/*
python3.11 -m twine upload dist/*
```

Use an API token scoped to this project, via `~/.pypirc` or `TWINE_PASSWORD`. Then tag
and push the tag:

```
git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0
```

Tag after a successful upload, not before. A version on PyPI cannot be replaced, so the
upload is the irreversible step and the tag should record what actually shipped.

## If a release is broken

Yank it (`pip` stops resolving to it, existing pins keep working) and release a patch
version. Do not delete it: deletion frees the version number for reuse, which means two
different sets of bytes can answer to the same name.

## Production checklist

- Build from a clean release commit; never publish from a moving branch.
- Run the artifact verifier from outside the checkout and verify the sdist as well as
  the wheel.
- Use an immutable Lachesis tag in production GitHub Action workflows.
- Keep the previous release available for rollback and never overwrite an artifact.
