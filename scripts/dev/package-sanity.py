#!/usr/bin/env python3
"""Static content audit for built Empusa wheels.

Walks every ``*.whl`` under ``dist/`` and fails if any path inside the
archive matches a known generated-artifact pattern (``__pycache__/``,
``.pytest_cache/``, ``.ruff_cache/``, ``.coverage``, ``*.egg-info/``,
``/obj/``, ``/bin/``).

Intended module source assets (``module.json``, ``Makefile``, ``*.c``,
``*.cs``, ``*.csproj``, ``*.go``, ``go.mod``, ``*.pl``, ``*.rs``,
``Cargo.toml``, ``README.md``, ...) are explicitly allowed and never
trigger a failure on their own.

Exit codes:
    0  - every wheel is clean
    1  - one or more disallowed entries found, or no wheel built

Output uses canonical Empusa markers:  [PASS] / [FAIL] / [INFO]
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DIST_DIR = REPO_ROOT / "dist"

FORBIDDEN_SUBSTRINGS = (
    "__pycache__/",
    ".pytest_cache/",
    ".ruff_cache/",
    "/obj/",
    "/bin/",
)
FORBIDDEN_BASENAMES = (".coverage",)
FORBIDDEN_DIR_SUFFIX_RE = re.compile(r"\.egg-info/")

# Allow-list documents intent; presence of these files never triggers
# a failure even if they appear under unexpected paths.
ALLOWED_MODULE_ASSETS = (
    "module.json",
    "Makefile",
    "README.md",
    "go.mod",
    "Cargo.toml",
)
ALLOWED_MODULE_EXTS = (".c", ".cpp", ".cs", ".csproj", ".go", ".pl", ".rs")


def _is_forbidden(member: str) -> str | None:
    for sub in FORBIDDEN_SUBSTRINGS:
        if sub in member:
            return f"contains {sub!r}"
    if FORBIDDEN_DIR_SUFFIX_RE.search(member):
        return "egg-info artifact present"
    base = member.rsplit("/", 1)[-1]
    if base in FORBIDDEN_BASENAMES:
        return f"forbidden file {base!r}"
    return None


def _audit_wheel(wheel: Path) -> list[str]:
    failures: list[str] = []
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    for name in names:
        reason = _is_forbidden(name)
        if reason is not None:
            failures.append(f"{name}: {reason}")
    return failures


def main() -> int:
    if not DIST_DIR.is_dir():
        print(f"[FAIL] no dist/ directory at {DIST_DIR}")
        print("[INFO] run 'python -m build' first")
        return 1

    wheels = sorted(DIST_DIR.glob("*.whl"))
    if not wheels:
        print(f"[FAIL] no wheel found under {DIST_DIR}")
        print("[INFO] run 'python -m build' first")
        return 1

    total_failures = 0
    for wheel in wheels:
        print(f"[INFO] auditing {wheel.name}")
        failures = _audit_wheel(wheel)
        if failures:
            total_failures += len(failures)
            for f in failures:
                print(f"  [FAIL] {f}")
        else:
            print(f"  [PASS] {wheel.name}: no forbidden artifacts")

    if total_failures:
        print(f"[FAIL] {total_failures} disallowed entrie(s) across {len(wheels)} wheel(s)")
        return 1
    print(f"[PASS] {len(wheels)} wheel(s) clean")
    print(f"[INFO] allowed module assets: {', '.join(ALLOWED_MODULE_ASSETS + ALLOWED_MODULE_EXTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
