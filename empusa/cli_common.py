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
from typing import Any, Dict, List, Optional, cast

from rich.console import Console


# -- Global configuration --------------------------------------------

CONFIG: Dict[str, Any] = {
    "verbose": False,
    "quiet": False,
    "dry_run": False,
    "no_color": False,
    "max_workers": 8,
    "session_env": "",
}

SESSION_ACTIONS: List[Dict[str, str]] = []

console = Console()


# -- Platform flags --------------------------------------------------

IS_WINDOWS = platform.system() == "Windows"
IS_UNIX = platform.system() in ["Linux", "Darwin"]


# -- Path constants --------------------------------------------------

HOOKS_DIR = Path(__file__).resolve().parent / "hooks"
MODULES_DIR = HOOKS_DIR / "modules"
PLUGINS_DIR = Path(__file__).resolve().parent / "plugins"


# -- Event names -----------------------------------------------------

HOOK_EVENTS: List[str] = [
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
    SESSION_ACTIONS.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "action": action,
        "detail": detail,
    })


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system("cls" if IS_WINDOWS else "clear")


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
    """Always print error messages."""
    console.print(message, style="bold red")


def log_success(message: str) -> None:
    """Print success message unless in quiet mode."""
    if not CONFIG["quiet"]:
        console.print(message, style="green")


# -- Executable lookup -----------------------------------------------


def which(cmd: str) -> Optional[str]:
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
    return re.sub(r'[<>:"/\\|?*]', '_', name)


def load_loot(loot_file: Path) -> List[Dict[str, Any]]:
    """Load loot entries from a JSON file.

    Returns:
        A list of loot entry dicts, or an empty list on error.
    """
    if loot_file.exists():
        try:
            raw_text = loot_file.read_text(errors='ignore')
            data = json.loads(raw_text)
            if isinstance(data, list):
                return cast(List[Dict[str, Any]], data)
        except (json.JSONDecodeError, Exception) as e:
            log_verbose(f"Warning: Could not parse loot file: {e}", "yellow")
    return []
