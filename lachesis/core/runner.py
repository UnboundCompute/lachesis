"""Execute an out-of-process compiler frontend without knowing its language."""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Optional, Sequence

from .contract import ContractError, FrontendSnapshot, FrontendSpec
from .snapshot import load_snapshot


def _in_process_applies(
    frontend: FrontendSpec, output_dir: Optional[str],
) -> bool:
    """Whether this frontend may be run here instead of as a child process.

    The subprocess is the contract and the in-process route is an optimisation, so
    each condition below is a reason the two could differ, and any one of them sends
    the work to the child, where the behaviour is the one that has always shipped.

    ``output_dir is None`` is the caller saying it wants the graph and not the
    bundle. When it names a directory it expects files in it, and not writing them
    is the whole saving.

    An empty ``environment`` matters because a spec that sets variables for its child
    is saying something about how that child must run, and this process is not it.
    Roots need no such condition: they go down as an argument rather than through
    ``LACHESIS_ROOTS_FILE``, so both routes compile the same set without this process
    having to mutate its own environment to say so.

    ``LACHESIS_INPROCESS=0`` forces the child unconditionally, so a difference
    between the two routes can be bisected without reverting anything.
    """
    return (
        output_dir is None
        and frontend.in_process is not None
        and not frontend.environment
        and os.environ.get("LACHESIS_INPROCESS") != "0"
    )


def run_frontend(
    frontend: FrontendSpec,
    source_dir: str,
    output_dir: Optional[str] = None,
    timeout_seconds: int = 300,
    roots: Optional[Sequence[str]] = None,
) -> FrontendSnapshot:
    if _in_process_applies(frontend, output_dir):
        return frontend.in_process(source_dir, roots)
    temporary = None
    if output_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="lachesis-frontend-")
        output_dir = temporary.name
    os.makedirs(output_dir, exist_ok=True)
    environment = os.environ.copy()
    environment.update(frontend.environment)
    # When discovery hands us an explicit root set (test files already excluded),
    # write it beside the output and point the frontend at it so a frontend that
    # re-walks the tree compiles exactly this list — one discovery, no drift.
    if roots is not None:
        roots_file = os.path.join(output_dir, "lachesis-roots.txt")
        with open(roots_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(roots))
        environment["LACHESIS_ROOTS_FILE"] = roots_file
    command = frontend.render_command(source_dir, output_dir)
    try:
        completed = subprocess.run(
            command,
            cwd=frontend.working_directory,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        if completed.returncode != 0:
            raise ContractError(
                f"frontend {frontend.frontend_id} exited {completed.returncode}\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        return load_snapshot(output_dir, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as error:
        raise ContractError(
            f"frontend {frontend.frontend_id} exceeded {timeout_seconds}s"
        ) from error
    finally:
        if temporary is not None:
            temporary.cleanup()

