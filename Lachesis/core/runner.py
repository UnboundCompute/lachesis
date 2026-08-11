"""Execute an out-of-process compiler frontend without knowing its language."""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Optional, Sequence

from .contract import ContractError, FrontendSnapshot, FrontendSpec
from .snapshot import load_snapshot


def run_frontend(
    frontend: FrontendSpec,
    source_dir: str,
    output_dir: Optional[str] = None,
    timeout_seconds: int = 300,
    roots: Optional[Sequence[str]] = None,
) -> FrontendSnapshot:
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

