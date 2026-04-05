"""Empusa - Non-interactive workspace CLI commands.

Subcommands::

    empusa workspace init   --name NAME [--profile P] [--root DIR] [--set-active] [--templates-dir DIR]
    empusa workspace list   [--root DIR]
    empusa workspace select --name NAME [--root DIR]
    empusa workspace status --name NAME [--root DIR]

All four are non-interactive and suitable for scripting (e.g. from
``labctl workspace``).  Event emission uses the typed workspace
lifecycle events so plugins can react to workspace changes.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from empusa.cli_common import (
    CONFIG,
    console,
    get_active_workspace,
    log_action,
    log_error,
    log_info,
    log_success,
    log_verbose,
    set_active_workspace,
)
from empusa.workspace import (
    DEFAULT_WORKSPACE_ROOT,
    PROFILES,
    create_workspace,
    list_workspaces,
    load_metadata,
)

# All known template filenames across every profile.
ALL_TEMPLATES = (
    "engagement.md",
    "target.md",
    "recon.md",
    "services.md",
    "web.md",
    "privesc.md",
    "pivot.md",
    "ad.md",
    "finding.md",
)

# -- Type aliases for injected callables ----------------------------

EmitFn = Callable[[str, dict[str, Any]], None]


# -- Subcommand implementations ------------------------------------


def cmd_workspace_init(
    args: argparse.Namespace,
    *,
    emit_fn: EmitFn,
) -> int:
    """``empusa workspace init`` - create a profile-aware workspace."""
    name: str = args.name
    profile: str = args.profile
    root = Path(args.root) if args.root else DEFAULT_WORKSPACE_ROOT
    set_active: bool = args.set_active
    templates_dir = Path(args.templates_dir) if args.templates_dir else None

    if profile not in PROFILES:
        log_error(f"Unknown profile {profile!r}. Valid profiles: {', '.join(sorted(PROFILES))}")
        return 1

    # Warn early if the profile expects templates but no dir was given
    profile_templates = PROFILES[profile].get("templates", [])
    if profile_templates and templates_dir is None:
        log_info(
            f"Profile {profile!r} expects templates but --templates-dir was not supplied. "
            "Workspace will be created without template files.",
            "yellow",
        )
    elif templates_dir is not None and not templates_dir.is_dir():
        log_error(f"Templates directory does not exist: {templates_dir}")
        return 1

    # -- pre_workspace_init event ------------------------------------
    emit_fn("pre_workspace_init", {
        "workspace_name": name,
        "workspace_root": str(root),
        "profile": profile,
        "set_active": set_active,
    })

    try:
        result = create_workspace(
            name=name,
            profile=profile,
            root=root,
            templates_dir=templates_dir,
            set_active=set_active,
        )
    except ValueError as exc:
        log_error(str(exc))
        return 1

    if result.already_existed:
        log_info(f"Workspace already exists: {result.workspace_path}", "yellow")
        return 0

    log_action("Workspace Init", f"{result.name} ({profile})")
    log_success(f"[+] Created workspace: {result.workspace_path}")

    if result.templates_seeded:
        log_info(
            f"    Templates seeded: {', '.join(result.templates_seeded)}",
        )

    if result.templates_missing:
        log_info(
            f"    Templates not found (skipped): {', '.join(result.templates_missing)}",
            "yellow",
        )

    for p in result.created_paths:
        log_verbose(f"    {p}", "dim")

    # -- post_workspace_init event -----------------------------------
    emit_fn("post_workspace_init", {
        "workspace_name": result.name,
        "workspace_root": result.workspace_root,
        "workspace_path": result.workspace_path,
        "profile": profile,
        "set_active": set_active,
        "created_paths": result.created_paths,
    })

    # Optionally mark as active session env
    if set_active:
        set_active_workspace(
            name=result.name,
            root=result.workspace_root,
            path=result.workspace_path,
            profile=profile,
        )
        log_info(f"    Active workspace set to: {result.name}")

    return 0


def cmd_workspace_list(args: argparse.Namespace) -> int:
    """``empusa workspace list`` - list all workspaces under root."""
    root = Path(args.root) if args.root else DEFAULT_WORKSPACE_ROOT

    workspaces = list_workspaces(root)
    if not workspaces:
        log_info(f"No workspaces found under {root}", "yellow")
        return 0

    table = Table(title="Workspaces", show_lines=False)
    table.add_column("Name", style="bold cyan")
    table.add_column("Profile", style="green")
    table.add_column("Created", style="dim")
    table.add_column("Templates", style="dim")
    table.add_column("Path")
    table.add_column("Status", justify="center", width=12)

    active_name = get_active_workspace()["name"]

    for ws in workspaces:
        seeded = ", ".join(ws.get("templates_seeded", [])) or "-"
        ws_name = ws.get("name", "?")
        is_active = ws_name == active_name and active_name != ""
        marker = Text("★ active", style="bold green") if is_active else Text("")
        name_style = "bold cyan" if not is_active else "bold green"
        table.add_row(
            Text(ws_name, style=name_style),
            ws.get("profile", "?"),
            ws.get("created_at", "?"),
            seeded,
            ws.get("path", "?"),
            marker,
        )

    console.print(table)
    if active_name:
        console.print(f"\n  [dim]Active workspace:[/dim] [bold green]{active_name}[/bold green]")
    else:
        console.print(
            "\n  [dim]No workspace is currently active. Use[/dim] [bold]workspace select --name NAME[/bold] [dim]to activate one.[/dim]"
        )
    return 0


def cmd_workspace_select(
    args: argparse.Namespace,
    *,
    emit_fn: EmitFn,
) -> int:
    """``empusa workspace select`` - activate an existing workspace."""
    name: str = args.name
    root = Path(args.root) if args.root else DEFAULT_WORKSPACE_ROOT
    ws_path = root / name

    if not ws_path.is_dir():
        log_error(f"Workspace not found: {ws_path}")
        return 1

    try:
        meta = load_metadata(ws_path)
    except FileNotFoundError:
        log_error(f"No metadata file in {ws_path}. Was this workspace created with 'empusa workspace init'?")
        return 1

    CONFIG["session_env"] = name
    set_active_workspace(
        name=meta.get("name", name),
        root=str(root),
        path=str(ws_path),
        profile=meta.get("profile", ""),
    )
    log_action("Workspace Select", name)
    log_success(f"[+] Active workspace: {name} (profile={meta.get('profile', '?')})")

    emit_fn("on_workspace_select", {
        "workspace_name": meta.get("name", name),
        "workspace_root": str(root),
        "workspace_path": str(ws_path),
        "profile": meta.get("profile", ""),
    })

    return 0


def cmd_workspace_status(args: argparse.Namespace) -> int:
    """``empusa workspace status`` - show metadata for a workspace."""
    name: str = args.name
    root = Path(args.root) if args.root else DEFAULT_WORKSPACE_ROOT
    ws_path = root / name

    if not ws_path.is_dir():
        log_error(f"Workspace not found: {ws_path}")
        return 1

    try:
        meta = load_metadata(ws_path)
    except FileNotFoundError:
        log_error(f"No metadata file in {ws_path}.")
        return 1

    # -- Active / legacy status line ---------------------------------
    active_ws = get_active_workspace()
    meta_name = meta.get("name", "")
    is_workspace_active = active_ws["name"] == meta_name and meta_name != ""
    is_legacy_match = not is_workspace_active and CONFIG.get("session_env", "") == name

    if is_workspace_active:
        status_line = "[bold green]★ Active workspace[/bold green]"
    elif is_legacy_match:
        status_line = (
            "[bold yellow]⚠ Legacy environment only[/bold yellow] "
            "[dim](session_env matches, but workspace was not selected)[/dim]"
        )
    else:
        status_line = "[dim]Not active[/dim]"

    # -- Metadata block ----------------------------------------------
    lines: list[str] = []
    lines.append(f"  [bold]{'Name':<14}[/bold] {meta.get('name', '?')}")
    lines.append(f"  [bold]{'Profile':<14}[/bold] {meta.get('profile', '?')}")
    lines.append(f"  [bold]{'Path':<14}[/bold] {meta.get('path', '?')}")
    lines.append(f"  [bold]{'Created':<14}[/bold] {meta.get('created_at', '?')}")
    seeded = meta.get("templates_seeded", [])
    lines.append(f"  [bold]{'Templates':<14}[/bold] {', '.join(seeded) if seeded else '-'}")
    lines.append(f"  [bold]{'Status':<14}[/bold] {status_line}")

    # -- Directory listing with file counts --------------------------
    dirs = sorted(p for p in ws_path.iterdir() if p.is_dir())
    if dirs:
        lines.append("")
        lines.append("  [bold cyan]Directories[/bold cyan]")
        for d in dirs:
            try:
                count = sum(1 for f in d.iterdir() if f.is_file())
            except OSError:
                count = 0
            count_str = f"{count} file{'s' if count != 1 else ''}" if count else "empty"
            lines.append(f"    {d.name + '/':<20} [dim]{count_str}[/dim]")

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[bold]Workspace: {meta.get('name', '?')}[/bold]",
            border_style="green" if is_workspace_active else "dim",
            padding=(1, 2),
        )
    )

    return 0


# -- Argparse wiring ------------------------------------------------


def register_workspace_parser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add the ``workspace`` subcommand and its sub-subcommands to *subparsers*.

    Called from :func:`empusa.cli.main` during parser construction.
    """
    sp_ws = subparsers.add_parser(
        "workspace",
        help="Workspace lifecycle (non-interactive)",
    )
    ws_sub = sp_ws.add_subparsers(dest="ws_action")

    # -- workspace init ----------------------------------------------
    sp_init = ws_sub.add_parser("init", help="Create a new workspace")
    sp_init.add_argument("--name", required=True, help="Workspace name")
    sp_init.add_argument(
        "--profile",
        default="htb",
        choices=sorted(PROFILES.keys()),
        help="Workspace profile (default: htb)",
    )
    sp_init.add_argument(
        "--root",
        default=None,
        help=f"Parent directory for workspaces (default: {DEFAULT_WORKSPACE_ROOT})",
    )
    sp_init.add_argument(
        "--set-active",
        action="store_true",
        help="Activate this workspace for the current session",
    )
    sp_init.add_argument(
        "--templates-dir",
        default=None,
        help="Directory containing .md template files to seed",
    )

    # -- workspace list ----------------------------------------------
    sp_list = ws_sub.add_parser("list", help="List all workspaces")
    sp_list.add_argument(
        "--root",
        default=None,
        help=f"Parent directory for workspaces (default: {DEFAULT_WORKSPACE_ROOT})",
    )

    # -- workspace select --------------------------------------------
    sp_select = ws_sub.add_parser("select", help="Activate an existing workspace")
    sp_select.add_argument("--name", required=True, help="Workspace name to activate")
    sp_select.add_argument(
        "--root",
        default=None,
        help=f"Parent directory for workspaces (default: {DEFAULT_WORKSPACE_ROOT})",
    )

    # -- workspace status --------------------------------------------
    sp_status = ws_sub.add_parser("status", help="Show workspace metadata")
    sp_status.add_argument("--name", required=True, help="Workspace name")
    sp_status.add_argument(
        "--root",
        default=None,
        help=f"Parent directory for workspaces (default: {DEFAULT_WORKSPACE_ROOT})",
    )
