"""Stage the pinned Atropos catalog into the distribution's bundled directory.

The lifecycle and sink detection this engine performs is entirely catalog-driven: a
call is a *release* because the Atropos catalog says so, a size argument is a size
argument because the catalog labels it. A wheel that does not carry the catalog can
still parse and navigate code, but every catalog-keyed judgement silently reads an
empty table -- no double-free, no use-after-free, no sink model -- because
``ATROPOS_ROOT`` defaulted to a sibling checkout that an installed package does not
have beside it. The catalog therefore ships inside the distribution, and this script
is what puts it there.

It is a build step, not a runtime one, and it mirrors ``vendor_typescript.py``: the
staged tree is deliberately absent from version control -- the catalog is a separate
public repository with its own release cadence, and duplicating it into this repo's
history on every bump is not something a source tree should accumulate -- so this runs
before ``python -m build``, and the release checklist in RELEASING.md says so. A
checkout that never runs it still finds the catalog through a sibling ``atropos``
checkout or ``$ATROPOS_ROOT``, exactly as it did before bundling; the bundled copy is
only ever the last resort a resolver falls back to.

What lands in the bundled directory is the three subtrees the loader actually reads --
``models/`` (the sink oracle), ``profiles/`` (the syntactic form oracle) and
``detection/`` (the language-agnostic role/pattern data) -- and nothing else. The
catalog's findings, candidates, tests and tooling are not part of what the engine keys
on and do not ship.

Usage:
    python3 tools/vendor_atropos.py            # stage the pinned version
    python3 tools/vendor_atropos.py --check    # is the bundled tree correct?
    python3 tools/vendor_atropos.py --clean    # remove it
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import List, Optional

# The catalog version the distribution ships. This is a pin, not a floor: the leads an
# analysis produces are a function of the catalog that labelled the sinks, so users get
# the version this engine's suite was run against rather than whatever the catalog repo
# happened to be at on release day. Bumping it is a deliberate commit -- and if a local
# sibling checkout is ahead of this pin, the pinned tag is fetched instead so the wheel
# stays reproducible.
ATROPOS_VERSION = "1.10.0"

# The public catalog repository. GitHub serves an immutable tarball for a tag, which is
# what a release build with no sibling checkout fetches. No authentication is involved:
# the catalog is public.
ARCHIVE_URL = (
    "https://github.com/UnboundCompute/atropos/archive/refs/tags/v{version}.tar.gz"
)

# Only the three subtrees the loader reads (see lachesis/flow/atropos.py: models/<lang>,
# profiles/<lang>, detection/<name>.json). Everything else in the catalog repo is data
# the engine never keys on.
WANTED_SUBTREES = ("models", "profiles", "detection")

BUNDLE_DIR = Path(__file__).resolve().parents[1] / "lachesis" / "_atropos_catalog"

# A local checkout the maintainer works against, tried before the network. It is used
# only when its VERSION already matches the pin, so a sibling that is intentionally
# ahead of a release does not silently vendor unreleased data into a wheel.
SIBLING_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "atropos",
    Path.home() / "project" / "unboundcompute" / "atropos",
)


def _read_version(root: Path) -> Optional[str]:
    marker = root / "VERSION"
    if not marker.is_file():
        return None
    return marker.read_text(encoding="utf-8").strip()


def _sibling_at_pin() -> Optional[Path]:
    """A sibling catalog checkout whose VERSION equals the pin, or ``None``."""
    for candidate in SIBLING_CANDIDATES:
        if (candidate / "models").is_dir() and _read_version(candidate) == ATROPOS_VERSION:
            return candidate
    return None


def _copy_subtrees(source: Path, destination: Path) -> int:
    """Copy the wanted subtrees from ``source`` into ``destination``. Returns file count."""
    files = 0
    for name in WANTED_SUBTREES:
        src = source / name
        if not src.is_dir():
            raise SystemExit(
                f"catalog source {source} has no {name}/ subtree; the layout may have "
                "changed or the source is not an Atropos checkout."
            )
        dst = destination / name
        shutil.copytree(src, dst)
        files += sum(1 for _ in dst.rglob("*") if _.is_file())
    (destination / "VERSION").write_text(ATROPOS_VERSION + "\n", encoding="utf-8")
    return files


def _fetch_pinned_tarball() -> bytes:
    url = ARCHIVE_URL.format(version=ATROPOS_VERSION)
    print(f"fetching {url}")
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - fixed https host
        return response.read()


def _extract_from_tarball(payload: bytes, destination: Path) -> int:
    """Unpack the wanted subtrees from the GitHub tag tarball into ``destination``.

    The archive's top-level directory is ``atropos-<version>/``. Members are placed by
    their path *below* that root, and a member whose normalised path would escape the
    destination is skipped, so a crafted archive cannot write outside the bundle.
    """
    files = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            parts = member.name.split("/", 1)
            if len(parts) != 2:
                continue
            relative = parts[1]  # strip the atropos-<version>/ prefix
            top = relative.split("/", 1)[0]
            if top not in WANTED_SUBTREES:
                continue
            target = (destination / relative).resolve()
            if not str(target).startswith(str(destination.resolve()) + os.sep):
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())
            files += 1
    (destination / "VERSION").write_text(ATROPOS_VERSION + "\n", encoding="utf-8")
    return files


def vendor() -> int:
    if BUNDLE_DIR.exists():
        shutil.rmtree(BUNDLE_DIR)
    BUNDLE_DIR.mkdir(parents=True)

    sibling = _sibling_at_pin()
    if sibling is not None:
        print(f"staging atropos {ATROPOS_VERSION} from sibling checkout {sibling}")
        files = _copy_subtrees(sibling, BUNDLE_DIR)
    else:
        payload = _fetch_pinned_tarball()
        print(f"fetched pinned tag v{ATROPOS_VERSION} ({len(payload) / 1e6:.1f} MB)")
        files = _extract_from_tarball(payload, BUNDLE_DIR)

    missing = [name for name in WANTED_SUBTREES if not (BUNDLE_DIR / name).is_dir()]
    if missing or files == 0:
        raise SystemExit(
            f"the staged catalog is incomplete (missing {missing}, {files} files). "
            "The upstream catalog layout may have changed."
        )
    print(f"bundled atropos@{ATROPOS_VERSION} -> {BUNDLE_DIR}")
    print(f"  {files} files across {', '.join(WANTED_SUBTREES)}/")
    return 0


def check() -> int:
    """Is a bundled catalog present, and is it the pinned version?

    The release checklist runs this so that "I forgot to bundle the catalog" fails
    before a wheel is uploaded rather than after, when the only symptom is a stranger's
    scan finding no lifecycle bugs because every catalog table read empty.
    """
    version = _read_version(BUNDLE_DIR)
    if version is None:
        print(f"no bundled Atropos catalog at {BUNDLE_DIR}", file=sys.stderr)
        print("run: python3 tools/vendor_atropos.py", file=sys.stderr)
        return 1
    if version != ATROPOS_VERSION:
        print(f"bundled atropos@{version}, pinned atropos@{ATROPOS_VERSION}",
              file=sys.stderr)
        return 1
    missing: List[str] = [name for name in WANTED_SUBTREES
                          if not (BUNDLE_DIR / name).is_dir()]
    if missing:
        print(f"bundled tree at {BUNDLE_DIR} is missing subtrees: {missing}",
              file=sys.stderr)
        return 1
    print(f"bundled atropos@{version} ok ({', '.join(WANTED_SUBTREES)}/)")
    return 0


def clean() -> int:
    if BUNDLE_DIR.exists():
        shutil.rmtree(BUNDLE_DIR)
        print(f"removed {BUNDLE_DIR}")
    else:
        print(f"nothing to remove at {BUNDLE_DIR}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="verify a bundled tree is present and matches the pin")
    parser.add_argument("--clean", action="store_true",
                        help="remove the bundled tree")
    arguments = parser.parse_args()
    if arguments.check and arguments.clean:
        parser.error("--check and --clean are mutually exclusive")
    if arguments.check:
        return check()
    if arguments.clean:
        return clean()
    return vendor()


if __name__ == "__main__":
    raise SystemExit(main())
