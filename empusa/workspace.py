"""
Empusa - Workspace Lifecycle

Profile-aware workspace creation, template seeding, and metadata
management.  Pure file-system operations — no Docker, no containe
orchestration.

Profiles define the subdirectory skeleton and which templates are
seeded into a new workspace.  The caller (CLI command, lab-bootstrap
script, or plugin) chooses the profile; this module does the I/O.

Usage::

    from empusa.workspace import create_workspace, PROFILES

    result = create_workspace(
        name="box-name",
        profile="htb",
        root=Path("/opt/lab/workspaces"),
    )
    # result.created_paths, result.metadata_path, ...
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

# -- Profile definitions ---------------------------------------------

PROFILES: dict[str, dict[str, Any]] = {
    "htb": {
        "dirs": [
            "notes",
            "scans",
            "web",
            "creds",
            "loot",
            "exploits",
            "screenshots",
            "reports",
            "logs",
        ],
        "templates": [
            "engagement.md",
            "target.md",
            "recon.md",
            "services.md",
            "finding.md",
            "privesc.md",
            "web.md",
        ],
    },
    "build": {
        "dirs": [
            "src",
            "out",
            "notes",
            "logs",
        ],
        "templates": [],
    },
    "research": {
        "dirs": [
            "notes",
            "references",
            "poc",
            "logs",
        ],
        "templates": [
            "recon.md",
        ],
    },
    "internal": {
        "dirs": [
            "notes",
            "scans",
            "creds",
            "loot",
            "evidence",
            "exploits",
            "reports",
            "logs",
        ],
        "templates": [
            "engagement.md",
            "target.md",
            "recon.md",
            "services.md",
            "finding.md",
            "pivot.md",
            "privesc.md",
            "ad.md",
        ],
    },
}

METADATA_FILENAME = ".empusa-workspace.json"

DEFAULT_WORKSPACE_ROOT = Path("/opt/lab/workspaces")

# -- Result dataclass ------------------------------------------------


@dataclass
class WorkspaceResult:
    """Structured return value from workspace creation."""

    name: str
    profile: str
    workspace_root: str
    workspace_path: str
    created_paths: list[str] = field(default_factory=lambda: cast(list[str], []))
    templates_seeded: list[str] = field(default_factory=lambda: cast(list[str], []))
    templates_missing: list[str] = field(default_factory=lambda: cast(list[str], []))
    metadata_path: str = ""
    already_existed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# -- Core API --------------------------------------------------------


def create_workspace(
    name: str,
    profile: str = "htb",
    root: Path | None = None,
    templates_dir: Path | None = None,
    set_active: bool = False,
    template_vars: dict[str, str] | None = None,
) -> WorkspaceResult:
    """Create a profile-aware workspace directory tree.

    Parameters
    ----------
    name:
        Workspace name (used as directory name — sanitised internally).
    profile:
        One of the keys in :data:`PROFILES`.
    root:
        Parent directory under which the workspace folder is created.
        Defaults to :data:`DEFAULT_WORKSPACE_ROOT`.
    templates_dir:
        Directory containing ``.md`` template files.  If *None* no
        templates are seeded (templates are optional).
    set_active:
        Informational flag carried through to the result / events;
        the caller decides what "active" means.
    template_vars:
        Optional ``{{KEY}}`` → ``value`` replacements applied when
        seeding templates.

    Returns
    -------
    WorkspaceResult
        Structured summary of everything that was created.
    """
    if profile not in PROFILES:
        raise ValueError(
            f"Unknown profile {profile!r}. "
            f"Valid profiles: {', '.join(sorted(PROFILES))}"
        )

    safe_name = _sanitize(name)
    ws_root = root or DEFAULT_WORKSPACE_ROOT
    ws_path = ws_root / safe_name

    result = WorkspaceResult(
        name=safe_name,
        profile=profile,
        workspace_root=str(ws_root),
        workspace_path=str(ws_path),
    )

    if ws_path.exists():
        result.already_existed = True
        return result

    profile_def = PROFILES[profile]
    created: list[str] = []

    # -- Scaffold directories ----------------------------------------
    ws_path.mkdir(parents=True, exist_ok=True)
    created.append(str(ws_path))

    for subdir in profile_def["dirs"]:
        d = ws_path / subdir
        d.mkdir(parents=True, exist_ok=True)
        created.append(str(d))

    # -- Seed templates ----------------------------------------------
    seeded: list[str] = []
    missing: list[str] = []
    expected_templates: list[str] = profile_def.get("templates", [])

    if expected_templates and templates_dir is not None:
        if not templates_dir.is_dir():
            # Caller supplied a path that doesn't exist — every
            # expected template counts as missing.
            missing = list(expected_templates)
        else:
            replacements = template_vars or {}
            # Default {{NAME}} to workspace name if not supplied
            replacements.setdefault("NAME", safe_name)
            for tpl_name in expected_templates:
                src = templates_dir / tpl_name
                if not src.is_file():
                    missing.append(tpl_name)
                    continue
                dst = ws_path / tpl_name
                content = src.read_text(encoding="utf-8")
                for key, val in replacements.items():
                    content = content.replace("{{" + key + "}}", val)
                dst.write_text(content, encoding="utf-8")
                seeded.append(tpl_name)
                created.append(str(dst))
    elif expected_templates:
        # No templates_dir supplied — nothing to seed, but note what
        # *would* have been seeded so the caller can decide.
        missing = list(expected_templates)

    # -- Write metadata ----------------------------------------------
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata: dict[str, Any] = {
        "profile": profile,
        "name": safe_name,
        "path": str(ws_path),
        "created_at": now,
        "templates_seeded": seeded,
    }
    meta_path = ws_path / METADATA_FILENAME
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    created.append(str(meta_path))

    result.created_paths = created
    result.templates_seeded = seeded
    result.templates_missing = missing
    result.metadata_path = str(meta_path)
    return result


def load_metadata(workspace_path: Path) -> dict[str, Any]:
    """Read and return the metadata dict for an existing workspace.

    Raises ``FileNotFoundError`` if the metadata file is missing.
    """
    meta = workspace_path / METADATA_FILENAME
    return json.loads(meta.read_text(encoding="utf-8"))


def list_workspaces(root: Path | None = None) -> list[dict[str, Any]]:
    """Return metadata dicts for every workspace under *root*."""
    ws_root = root or DEFAULT_WORKSPACE_ROOT
    results: list[dict[str, Any]] = []
    if not ws_root.is_dir():
        return results
    for child in sorted(ws_root.iterdir()):
        meta_file = child / METADATA_FILENAME
        if child.is_dir() and meta_file.is_file():
            try:
                results.append(json.loads(meta_file.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
    return results


# -- Build layout ----------------------------------------------------


@dataclass
class BuildLayout:
    """Resolved paths for a build environment.

    Returned by :func:`ensure_build_layout` so that callers know
    exactly where per-IP scan directories, credential tracker files,
    and the command log live — regardless of whether the build runs
    inside a workspace or as a standalone flat layout.
    """

    base_dir: Path
    scans_dir: Path
    users_file: Path
    passwords_file: Path
    commands_log: Path
    ip_nmap_dirs: dict[str, Path] = field(default_factory=dict)


def ensure_build_layout(
    env_name: str,
    ips: list[str],
    workspace_path: Path | None = None,
) -> BuildLayout:
    """Create the directory scaffold for a build environment.

    When *workspace_path* points at an existing workspace the per-IP
    scan directories are placed under its ``scans/`` subdirectory (if
    present), credential tracker files under ``creds/``, and the
    command log under ``logs/``.  Otherwise a flat layout rooted at
    *env_name* (resolved against CWD) is created — preserving the
    original ``build_env()`` behaviour.

    Directories and files are created idempotently (``exist_ok``).
    """
    if workspace_path is not None:
        base_dir = Path(workspace_path)
        scans_dir = base_dir / "scans" if (base_dir / "scans").is_dir() else base_dir
        creds_dir = base_dir / "creds" if (base_dir / "creds").is_dir() else base_dir
        logs_dir = base_dir / "logs" if (base_dir / "logs").is_dir() else base_dir
    else:
        base_dir = Path(env_name).absolute()
        scans_dir = base_dir
        creds_dir = base_dir
        logs_dir = base_dir

    base_dir.mkdir(parents=True, exist_ok=True)
    scans_dir.mkdir(parents=True, exist_ok=True)
    creds_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    users_file = creds_dir / f"{env_name}-users.txt"
    passwords_file = creds_dir / f"{env_name}-passwords.txt"
    commands_log = logs_dir / "commands_ran.txt"

    users_file.touch()
    passwords_file.touch()
    commands_log.touch()

    ip_nmap_dirs: dict[str, Path] = {}
    for ip in ips:
        nmap_path = scans_dir / ip / "nmap"
        nmap_path.mkdir(parents=True, exist_ok=True)
        ip_nmap_dirs[ip] = nmap_path

    return BuildLayout(
        base_dir=base_dir,
        scans_dir=scans_dir,
        users_file=users_file,
        passwords_file=passwords_file,
        commands_log=commands_log,
        ip_nmap_dirs=ip_nmap_dirs,
    )


# -- Helpers ---------------------------------------------------------


def _sanitize(name: str) -> str:
    """Strip characters that are unsafe in directory names."""
    # Allow alphanumeric, hyphens, underscores, dots
    return "".join(c for c in name if c.isalnum() or c in "-_.")
