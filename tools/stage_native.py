#!/usr/bin/env python3
"""Build and stage Lachesis's native artifacts into the Python package tree.

Release jobs run this before building a wheel. Source checkouts keep using the
target-directory fallback, while installed wheels resolve these files from
``lachesis/_native`` without requiring Cargo or a repository checkout.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "lachesis" / "_native"


def _platform_names() -> tuple[str, str]:
    if os.name == "nt":
        return "lachesis_lifetime_kernel.dll", "lachesis-clang-frontend.exe"
    if os.uname().sysname == "Darwin":
        return "liblachesis_lifetime_kernel.dylib", "lachesis-clang-frontend"
    return "liblachesis_lifetime_kernel.so", "lachesis-clang-frontend"


def _cargo_build(manifest: Path) -> None:
    subprocess.run(
        ["cargo", "build", "--release", "--manifest-path", str(manifest)],
        cwd=ROOT, check=True,
    )


def stage(*, build: bool) -> list[Path]:
    kernel_name, clang_name = _platform_names()
    if build:
        _cargo_build(ROOT / "native" / "lifetime_kernel" / "Cargo.toml")
        _cargo_build(ROOT / "native" / "clang_frontend" / "Cargo.toml")
    candidates = [
        ROOT / "native" / "lifetime_kernel" / "target" / "release" / kernel_name,
        ROOT / "native" / "clang_frontend" / "target" / "release" / clang_name,
    ]
    missing = [path for path in candidates if not path.is_file()]
    if missing:
        names = ", ".join(str(path) for path in missing)
        raise SystemExit(f"native artifacts missing: {names}; rerun with --build")
    DEST.mkdir(parents=True, exist_ok=True)
    staged = []
    for source in candidates:
        target = DEST / source.name
        shutil.copy2(source, target)
        staged.append(target)
    return staged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true",
                        help="compile both Rust artifacts before staging")
    args = parser.parse_args()
    for path in stage(build=args.build):
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
