# Releasing Lachesis

Lachesis publishes to PyPI as [`lachesis-cpg`](https://pypi.org/project/lachesis-cpg/).
A release is **tag-driven**: pushing a `vX.Y.Z` tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds the
platform wheels and the sdist, verifies each one from a clean environment, and publishes
them to PyPI through Trusted Publishing. You do not build or upload by hand — and you
could not build the Linux and Windows wheels from a macOS checkout anyway.

## What ships

The distribution is Python plus three things that are not:

- **The native analysis kernel** (`lachesis/_native/`): a Rust lifetime kernel and a
  clang frontend, one binary per platform. They load through `ctypes`/`subprocess`, not
  as CPython extensions, so a single `py3-none-<platform>` wheel serves every supported
  interpreter (the tag is set in `setup.py`). They are **not in version control** and are
  built into the tree by `tools/stage_native.py --build`; the release build does this per
  platform. A wheel without them installs fine and then crashes on the first `lachesis
  scan` — which is exactly what `lachesis doctor` (run by the artifact verifier and the
  cibuildwheel test step) exists to catch.
- **The TypeScript compiler** next to the Node frontend under `vendor/`. Also **not in
  version control** (see `.gitignore`); `tools/vendor_typescript.py` fetches the pinned
  version, and the release build vendors it on the host before packaging.
- **The Atropos catalog** under `lachesis/_atropos_catalog/` — the sink models, syntactic
  profiles and detection roles/patterns every catalog-keyed judgement reads. Without it an
  installed wheel parses and navigates fine but finds no lifecycle bugs, because each
  catalog table reads empty. Also **not in version control** (see `.gitignore`);
  `tools/vendor_atropos.py` stages the pinned catalog version (from a matching sibling
  checkout, else the pinned public tag), and the release build bundles it on the host
  before packaging. At runtime an explicit `$ATROPOS_ROOT` or a sibling checkout still
  wins; the bundled copy is the fallback that makes a standalone wheel self-contained.
- the fixture corpora under each frontend, so the parity suite can run from an install.

The C frontend degrades to "no C analysis" when there is no `clang` on the machine.

## One-time setup (per PyPI project)

The publish job authenticates with PyPI over OIDC — there is no API token in the repo.
Configure it once:

1. On PyPI, add a **Trusted Publisher** for the project: owner `UnboundCompute`, repo
   `lachesis`, workflow `release.yml`, environment `pypi`.
2. In the GitHub repo, create an **Environment** named `pypi` (Settings → Environments).
   Add required reviewers there if you want a manual approval gate before every publish.

## Before you tag

1. Working tree is clean and you are on the release commit (the `prod` branch after the
   `dev → prod` merge).
2. Bump `version` in `pyproject.toml`. Lachesis is pre-1.0, so the graph schema and the
   nav tool surface may still change between minor versions; say so in the changelog
   entry.
3. Add a `## [X.Y.Z]` heading to `CHANGELOG.md` for the new version. The release workflow
   refuses to build if the tag has no matching version and changelog heading.
4. Run the parity suite against a clean checkout — it is the release gate, there is no
   separate one:
   ```
   python3.11 -m pip install -e ".[dev]" && npm ci
   make PYTHON=python3.11 check
   ```

### Optional local smoke test

You cannot build the Linux or Windows wheels locally, but you can prove your own
platform's wheel before spending a tag on it:

```
python3.11 tools/vendor_typescript.py          # fetch the pinned compiler
python3.11 tools/vendor_atropos.py             # bundle the pinned Atropos catalog
python3.11 tools/stage_native.py --build        # compile + stage the native binaries
python3.11 -m build --wheel                      # -> dist/lachesis_cpg-*-py3-none-<platform>.whl
python3.11 -m twine check dist/*.whl
tools/verify_wheel.sh                            # installs into a clean venv and runs `lachesis doctor`
```

`verify_wheel.sh` is the same check CI runs: it installs the built wheel into a throwaway
virtualenv outside this repository, confirms the one top-level name, that the vendored
TypeScript compiler is present, that the native kernel loads (`lachesis doctor`), and that
a TypeScript and a Python project both analyse with no `npm` anywhere.

## Cut the release

```
git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
```

That triggers `release.yml`:

1. **guard** — the tag matches the `pyproject` version and has a `CHANGELOG` heading.
2. **sdist** — build and reproducibly re-build the sdist, `twine check`, install-verify.
3. **wheels** — a matrix of `ubuntu-latest`, `macos-13` (x86_64), `macos-14` (arm64), and
   `windows-latest`. Each runs `cibuildwheel`, which stages the native binaries for that
   platform, builds one `py3-none-<platform>` wheel, repairs it (auditwheel/delocate), and
   smoke-tests it with `lachesis doctor`.
4. **publish** — downloads every artifact, refuses any `*-none-any.whl`, `twine check`s the
   set, and uploads to PyPI via `pypa/gh-action-pypi-publish` (Trusted Publishing).

A version on PyPI cannot be replaced, so the tag is the irreversible step. Tag from the
release commit, not before it.

> Coverage note: the wheel matrix builds Linux `x86_64`, macOS `x86_64`/`arm64`, and
> Windows `amd64`. Linux `aarch64` and musl (Alpine) are **not** built yet — they need a
> QEMU leg and a musl native-build recipe respectively. On those platforms `pip` falls
> back to the sdist, which builds the native binaries from source if Rust is present.

## If a release is broken

Yank it (`pip` stops resolving to it, existing pins keep working) and release a patch
version. Do not delete it: deletion frees the version number for reuse, so two different
sets of bytes could answer to the same name.

## Production checklist

- Release from a clean `prod` commit; never publish from a moving branch.
- Keep the previous release available for rollback and never overwrite an artifact.
- Use an immutable Lachesis tag in production GitHub Action workflows.
