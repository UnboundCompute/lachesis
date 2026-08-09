"""Execute an out-of-process compiler frontend without knowing its language."""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Optional

from .contract import ContractError, FrontendSnapshot, FrontendSpec
from .snapshot import load_snapshot


def run_frontend(
    frontend: FrontendSpec,
    source_dir: str,
    output_dir: Optional[str] = None,
    timeout_seconds: int = 300,
) -> FrontendSnapshot:
    temporary = None
    if output_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="arachne-frontend-")
        output_dir = temporary.name
    os.makedirs(output_dir, exist_ok=True)
    environment = os.environ.copy()
    environment.update(frontend.environment)
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

