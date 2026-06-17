"""Minimal .env loader for local development secrets."""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: str | Path, *, override: bool = False) -> bool:
    """Load KEY=VALUE pairs from one .env-style file if it exists."""
    env_path = Path(path)
    if not env_path.exists():
        return False

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        # Support quoted values while keeping parsing intentionally simple.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        if override or key not in os.environ:
            os.environ[key] = value

    return True


def load_project_env(*, override: bool = False) -> None:
    """Load local environment files from the project root."""
    root = Path(__file__).resolve().parents[3]
    load_env_file(root / ".env", override=override)
    load_env_file(root / ".env.local", override=override)
