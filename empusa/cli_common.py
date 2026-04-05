"""
Empusa - Shared CLI Helpers (cli_common)

Symbols shared across the domain-specific CLI modules:

- **CONFIG** / **SESSION_ACTIONS** - global runtime state
- **console** - Rich console singleton
- **log_info / log_error / log_success / log_verbose** - structured output
- **clear_screen** - terminal clear helper
- **pause** - wait for Enter before continuing (prevents output wipe)
- **Path constants** - HOOKS_DIR, MODULES_DIR, PLUGINS_DIR
- **HOOK_EVENTS** - canonical event name list
- **IS_WINDOWS / IS_UNIX** - platform flags
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from rich.console import Console

# -- Global configuration --------------------------------------------

CONFIG: dict[str, Any] = {
    "verbose": False,
    "quiet": False,
    "dry_run": False,
    "no_color": False,
    "max_workers": 8,
    "session_env": "",
    "enable_shell_hooks": False,
    # -- Workspace session state (set by workspace init/select) ------
    "workspace_name": "",
    "workspace_root": "",
    "workspace_path": "",
    "workspace_profile": "",
}

SESSION_ACTIONS: list[dict[str, str]] = []

console = Console()


def set_console(new_console: Console) -> None:
    """Replace the global console singleton.

    Also propagates to every submodule that cached ``console`` at
    import time, so ``--no-color`` takes effect everywhere.
    """
    import sys

    global console
    console = new_console

    # Propagate to modules that did `from empusa.cli_common import console`
    _console_modules = (
        "empusa.cli_build",
        "empusa.cli_modules",
        "empusa.cli_plugins",
        "empusa.cli_hooks",
        "empusa.cli_reports",
        "empusa.cli",
    )
    for mod_name in _console_modules:
        mod = sys.modules.get(mod_name)
        if mod is not None and hasattr(mod, "console"):
            mod.console = new_console  # type: ignore[attr-defined]


def get_console() -> Console:
    """Return the current global console singleton.

    Modules that need the *live* console reference (e.g. for direct
    ``console.print()`` calls) should call this function rather than
    caching the import-time ``console`` object, because
    :func:`set_console` may replace it later (e.g. ``--no-color``).
    """
    return console


# -- Platform flags --------------------------------------------------

IS_WINDOWS = platform.system() == "Windows"
IS_UNIX = platform.system() in ["Linux", "Darwin"]


# -- Path constants --------------------------------------------------

HOOKS_DIR = Path(__file__).resolve().parent / "hooks"
MODULES_DIR = HOOKS_DIR / "modules"
PLUGINS_DIR = Path(__file__).resolve().parent / "plugins"


# -- Event names -----------------------------------------------------

HOOK_EVENTS: list[str] = [
    "on_startup",
    "on_shutdown",
    "pre_build",
    "post_build",
    "pre_scan_host",
    "post_scan",
    "on_loot_add",
    "on_report_generated",
    "pre_report_write",
    "on_env_select",
    "pre_command",
    "post_command",
    "post_compile",
]


# -- Logging helpers -------------------------------------------------


def log_action(action: str, detail: str = "") -> None:
    """Record a session action for the shutdown execution flow."""
    SESSION_ACTIONS.append(
        {
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": action,
            "detail": detail,
        }
    )


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system("cls" if IS_WINDOWS else "clear")


def print_mini_banner() -> None:
    """Print a compact one-line Empusa identity bar.

    Used by submenus (hooks manager, module workshop, loot tracker)
    so the shell identity persists on every redraw without eating
    vertical space the way the full banner does.
    """
    if CONFIG["quiet"]:
        return
    from empusa import __version__ as _ver  # lightweight: __init__.py is metadata-only

    console.print(
        f"[bold red]◆ Empusa[/bold red] [dim]v{_ver}[/dim]  "
        f"[dim]|[/dim]  [italic dim]Shape-shifting Recon & Exploitation Framework[/italic dim]"
    )
    console.print()


def print_section_header(title: str, style: str = "bold cyan") -> None:
    """Print a consistent section header with a horizontal rule.

    Provides visual hierarchy: mini-banner -> section header -> content.
    """
    if CONFIG["quiet"]:
        return
    console.rule(f"[{style}]{title}[/{style}]", style="dim")
    console.print()


def render_screen(title: str, subtitle: str | None = None) -> None:
    """Clear the terminal and draw the standard submenu chrome.

    Sequence: ``clear_screen -> print_mini_banner -> print_section_header``
    plus an optional italic subtitle line.  Every interactive submenu
    should call this once at the top of its redraw loop.
    """
    clear_screen()
    print_mini_banner()
    print_section_header(title)
    if subtitle and not CONFIG["quiet"]:
        console.print(f"[italic dim]{subtitle}[/italic dim]")
        console.print()


def render_kv(label: str, value: str) -> None:
    """Print a key-value row with a fixed-width bold label."""
    if not CONFIG["quiet"]:
        console.print(f"  [bold]{label:<14}[/bold] {value}")


def render_group_heading(label: str, style: str = "bold cyan") -> None:
    """Print a lightweight section-group heading inside a menu."""
    if not CONFIG["quiet"]:
        console.print(f"\n[{style}]{label}[/{style}]")


def pause() -> None:
    """Wait for the user to press Enter before the next screen clear.

    Prevents short action output from being wiped by the next loop
    iteration's ``clear_screen()`` call.  Suppressed in quiet mode.
    """
    if not CONFIG["quiet"]:
        console.print("\n[dim]Press Enter to continue...[/dim]", end="")
        input()


def log_verbose(message: str, style: str = "cyan") -> None:
    """Print message only in verbose mode."""
    if CONFIG["verbose"] and not CONFIG["quiet"]:
        console.print(message, style=style)


def log_info(message: str, style: str = "cyan") -> None:
    """Print message unless in quiet mode."""
    if not CONFIG["quiet"]:
        console.print(message, style=style)


def log_error(message: str) -> None:
    """Always print error messages.

    Uses ``markup=False`` so arbitrary strings (compiler output,
    file paths containing ``[`` / ``]``) are rendered literally
    instead of being interpreted as Rich markup tags.
    """
    console.print(message, style="bold red", markup=False)


def log_success(message: str) -> None:
    """Print success message unless in quiet mode."""
    if not CONFIG["quiet"]:
        console.print(message, style="green")


# -- Executable lookup -----------------------------------------------


def which(cmd: str) -> str | None:
    """Locate an executable on PATH using shutil.which.

    Returns:
        The resolved path as a string, or None if not found.
    """
    return shutil.which(cmd)


def check_tool_exists(tool_name: str) -> bool:
    """Return True if *tool_name* is found on PATH."""
    return which(tool_name) is not None


# -- Filename / loot helpers -----------------------------------------


def sanitize_filename(name: str) -> str:
    """Remove characters that are invalid in filenames."""
    return re.sub(r'[<>:"/\\|?*]', "_", name)


def load_loot(loot_file: Path) -> list[dict[str, Any]]:
    """Load loot entries from a JSON file.

    Returns:
        A list of loot entry dicts, or an empty list on error.
    """
    if loot_file.exists():
        try:
            raw_text = loot_file.read_text(errors="ignore")
            data = json.loads(raw_text)
            if isinstance(data, list):
                return cast(list[dict[str, Any]], data)
        except (json.JSONDecodeError, Exception) as e:
            log_verbose(f"Warning: Could not parse loot file: {e}", "yellow")
    return []


# -- Workspace session helpers ---------------------------------------


def set_active_workspace(
    name: str,
    root: str,
    path: str,
    profile: str,
) -> None:
    """Record the active workspace in CONFIG.

    Also sets ``session_env`` for backward compatibility with
    existing build / scan / report flows that read that key.
    """
    CONFIG["workspace_name"] = name
    CONFIG["workspace_root"] = root
    CONFIG["workspace_path"] = path
    CONFIG["workspace_profile"] = profile
    # Keep session_env in sync so legacy code sees the workspace name.
    CONFIG["session_env"] = name


def clear_active_workspace() -> None:
    """Clear all workspace session keys (and ``session_env``)."""
    CONFIG["workspace_name"] = ""
    CONFIG["workspace_root"] = ""
    CONFIG["workspace_path"] = ""
    CONFIG["workspace_profile"] = ""
    CONFIG["session_env"] = ""


def get_active_workspace() -> dict[str, str]:
    """Return the active workspace fields from CONFIG.

    Returns a dict with ``name``, ``root``, ``path``, ``profile``.
    All values are empty strings when no workspace is active.
    """
    return {
        "name": str(CONFIG.get("workspace_name", "")),
        "root": str(CONFIG.get("workspace_root", "")),
        "path": str(CONFIG.get("workspace_path", "")),
        "profile": str(CONFIG.get("workspace_profile", "")),
    }


def has_active_workspace() -> bool:
    """Return ``True`` if a workspace is currently active."""
    return bool(CONFIG.get("workspace_name", ""))
