"""Fetch the pinned TypeScript compiler into the distribution's vendor directory.

The TypeScript frontend runs against the real compiler API, not a reimplementation of
it, so a wheel that does not carry a compiler cannot analyse TypeScript at all. An
installed package has no `node_modules` above it and no repo to run `npm install` in,
so "install TypeScript yourself" is advice with nowhere to land. The compiler therefore
ships inside the distribution, and this script is what puts it there.

It is a build step, not a runtime one. The vendored tree is deliberately absent from
version control -- 9 MB of generated JavaScript per version bump is not something a
source repository should accumulate -- so this runs before `python -m build`, and the
release checklist in RELEASING.md says so. A checkout that never runs it still analyses
TypeScript through an ordinary `npm install`, exactly as it did before vendoring.

What lands in the vendor directory is a subset, chosen by what the frontend actually
loads: the compiler API and the default library declarations it type-checks against.
The `tsc` and `tsserver` executables are not part of that -- nothing here shells out to
them -- and neither are the localized diagnostic catalogues, which are 40+ copies of
English message text in languages this frontend never asks for. Dropping them is most
of the difference between 45 MB and 13 MB.

Usage:
    python3 tools/vendor_typescript.py            # fetch the pinned version
    python3 tools/vendor_typescript.py --check    # is the vendored tree correct?
    python3 tools/vendor_typescript.py --clean    # remove it
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Dict, Optional

# The compiler version the distribution ships. This is a pin, not a floor: the graph a
# frontend emits is a function of the compiler that produced it, so the version that
# users get is one we have run the parity suite against, rather than whatever the
# registry happened to serve on release day. Bumping it is a deliberate commit that
# re-runs the suite -- and that updates INTEGRITY below, which will otherwise reject the
# download.
TYPESCRIPT_VERSION = "5.9.3"

# The registry's own sha512 for the tarball of exactly that version, in the `sha512-`
# base64 form npm records. A pinned version alone still trusts whatever bytes arrive;
# this makes the fetch verifiable, so a compromised mirror or a truncated transfer fails
# loudly here instead of quietly shipping inside a wheel that we then sign our name to.
# Regenerate with: npm view typescript@<version> dist.integrity
INTEGRITY = (
    "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQd"
    "iaUpFT4bXlb1RHhLpp8wtm6M5TgSw=="
)

REGISTRY = "https://registry.npmjs.org/typescript/-/typescript-{version}.tgz"

VENDOR_DIR = (
    Path(__file__).resolve().parents[1]
    / "lachesis" / "frontends" / "typescript" / "vendor" / "typescript"
)

# Everything the frontend touches, and nothing else. `lib/typescript.js` is the compiler
# API that `build_graph.mjs` requires; the `lib/lib.*.d.ts` files are the default library
# declarations the type checker needs in order to resolve so much as an `Array`. The two
# licence files come along because redistribution is the whole point of this directory.
WANTED_EXACT = {
    "package/package.json": "package.json",
    "package/LICENSE.txt": "LICENSE.txt",
    "package/ThirdPartyNoticeText.txt": "ThirdPartyNoticeText.txt",
    "package/lib/typescript.js": "lib/typescript.js",
}


def wanted_name(member_name: str) -> Optional[str]:
    """Where ``member_name`` belongs in the vendor tree, or ``None`` to skip it."""
    mapped = WANTED_EXACT.get(member_name)
    if mapped is not None:
        return mapped
    # The default library declarations, and only those: `lib/lib.es2022.d.ts` yes,
    # `lib/tsc.js` no, `lib/ko/diagnosticMessages.generated.json` no.
    if member_name.startswith("package/lib/lib.") and member_name.endswith(".d.ts"):
        return member_name[len("package/"):]
    return None


def integrity_of(payload: bytes) -> str:
    """The npm-style ``sha512-<base64>`` integrity string for ``payload``."""
    return "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")


def download(version: str) -> bytes:
    url = REGISTRY.format(version=version)
    print(f"fetching {url}")
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - fixed https host
        payload = response.read()
    actual = integrity_of(payload)
    if actual != INTEGRITY:
        raise SystemExit(
            f"integrity mismatch for typescript@{version}\n"
            f"  expected: {INTEGRITY}\n"
            f"  actual:   {actual}\n"
            "Refusing to vendor bytes that are not the pinned release. If you are "
            "bumping TYPESCRIPT_VERSION, update INTEGRITY in the same commit "
            "(npm view typescript@<version> dist.integrity)."
        )
    print(f"integrity verified ({len(payload) / 1e6:.1f} MB)")
    return payload


def extract(payload: bytes, destination: Path) -> Dict[str, int]:
    """Unpack the wanted subset of the tarball into ``destination``.

    Members are written by their mapped name rather than their name in the archive, so
    a tarball carrying an absolute or `..`-escaping path cannot write outside the vendor
    directory: the archive's own path is used to *decide*, never to *place*.
    """
    written: Dict[str, int] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            relative = wanted_name(member.name)
            if relative is None:
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read()
            target.write_bytes(data)
            written[relative] = len(data)
    return written


def vendor() -> int:
    payload = download(TYPESCRIPT_VERSION)
    if VENDOR_DIR.exists():
        shutil.rmtree(VENDOR_DIR)
    VENDOR_DIR.mkdir(parents=True)
    written = extract(payload, VENDOR_DIR)

    missing = [name for name in WANTED_EXACT.values() if name not in written]
    declarations = [name for name in written if name.startswith("lib/lib.")]
    if missing or not declarations:
        raise SystemExit(
            "the tarball did not contain the expected layout "
            f"(missing {missing}, {len(declarations)} library declarations). "
            "The upstream package layout may have changed."
        )

    total = sum(written.values())
    print(f"vendored typescript@{TYPESCRIPT_VERSION} -> {VENDOR_DIR}")
    print(f"  {len(written)} files, {total / 1e6:.1f} MB "
          f"({len(declarations)} library declarations)")
    return 0


def check() -> int:
    """Is a vendored tree present, and is it the pinned version?

    The release checklist runs this so that "I forgot to vendor" fails before a wheel is
    uploaded rather than after, when the only symptom is a stranger's TypeScript project
    failing to analyse.
    """
    manifest = VENDOR_DIR / "package.json"
    if not manifest.is_file():
        print(f"no vendored TypeScript at {VENDOR_DIR}", file=sys.stderr)
        print("run: python3 tools/vendor_typescript.py", file=sys.stderr)
        return 1
    version = json.loads(manifest.read_text(encoding="utf-8"))["version"]
    if version != TYPESCRIPT_VERSION:
        print(f"vendored typescript@{version}, pinned typescript@{TYPESCRIPT_VERSION}",
              file=sys.stderr)
        return 1
    if not (VENDOR_DIR / "lib" / "typescript.js").is_file():
        print(f"vendored tree at {VENDOR_DIR} has no lib/typescript.js", file=sys.stderr)
        return 1
    # Counted the same way `wanted_name` selects them, so this number and the one
    # the fetch printed are the same number. A glob would quietly disagree by one:
    # `lib.d.ts` is a default library declaration and does not match `lib.*.d.ts`.
    declarations = len([entry for entry in (VENDOR_DIR / "lib").iterdir()
                        if entry.name.startswith("lib.") and entry.name.endswith(".d.ts")])
    if declarations == 0:
        print(f"vendored tree at {VENDOR_DIR} has no library declarations", file=sys.stderr)
        return 1
    print(f"vendored typescript@{version} ok ({declarations} library declarations)")
    return 0


def clean() -> int:
    if VENDOR_DIR.exists():
        shutil.rmtree(VENDOR_DIR)
        print(f"removed {VENDOR_DIR}")
    else:
        print(f"nothing to remove at {VENDOR_DIR}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="verify a vendored tree is present and matches the pin")
    parser.add_argument("--clean", action="store_true",
                        help="remove the vendored tree")
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
