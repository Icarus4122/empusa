#!/usr/bin/env python3
"""Static version-consistency check for Empusa releases.

Compares ``[project].version`` in ``pyproject.toml`` against
``__version__`` in ``empusa/__init__.py``.  Both are parsed statically
without importing Empusa, so the check stays fast and cycle-free.

Exit codes:
    0  - versions match
    1  - mismatch or parse failure

Output uses canonical Empusa markers:  [PASS] / [FAIL] / [INFO]
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
INIT_PY = REPO_ROOT / "empusa" / "__init__.py"


def _read(path: Path) -> str:
    if not path.is_file():
        print(f"[FAIL] missing file: {path}")
        raise SystemExit(1)
    return path.read_text(encoding="utf-8")


def _parse_pyproject_version(text: str) -> str:
    """Extract ``version`` from the ``[project]`` table without TOML deps."""
    in_project = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_project = line == "[project]"
            continue
        if not in_project or not line or line.startswith("#"):
            continue
        m = re.match(r'version\s*=\s*"([^"]+)"\s*$', line)
        if m:
            return m.group(1)
    raise ValueError("[project].version not found in pyproject.toml")


def _parse_init_version(text: str) -> str:
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    if not m:
        raise ValueError("__version__ not found in empusa/__init__.py")
    return m.group(1)


def main() -> int:
    try:
        py_version = _parse_pyproject_version(_read(PYPROJECT))
        init_version = _parse_init_version(_read(INIT_PY))
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 1

    print(f"[INFO] pyproject.toml  version = {py_version}")
    print(f"[INFO] empusa/__init__.py     = {init_version}")

    if py_version != init_version:
        print(f"[FAIL] version mismatch: pyproject={py_version!r} __init__={init_version!r}")
        return 1

    print(f"[PASS] empusa version {py_version} is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
