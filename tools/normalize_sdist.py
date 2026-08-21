#!/usr/bin/env python3
"""Normalize an sdist archive so repeated release builds are byte-identical."""

from __future__ import annotations

import argparse
import copy
import gzip
import os
import tarfile
from pathlib import Path


def normalize(archive: Path, epoch: int) -> None:
    temporary = archive.with_name(archive.name + ".normalized")
    try:
        with tarfile.open(archive, mode="r:gz") as source, temporary.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target:
                    for member in sorted(source.getmembers(), key=lambda item: item.name):
                        normalized = copy.copy(member)
                        normalized.mtime = epoch
                        normalized.uid = normalized.gid = 0
                        normalized.uname = normalized.gname = ""
                        normalized.pax_headers = {}
                        payload = source.extractfile(member) if member.isfile() else None
                        target.addfile(normalized, payload)
                        if payload is not None:
                            payload.close()
        os.replace(temporary, archive)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    normalize(args.archive, args.epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
