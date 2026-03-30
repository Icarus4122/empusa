"""
Empusa - Hook Management UI (cli_hooks)

Legacy hook management (Layer 2) UI and lifecycle:

- **init_hook_dirs** - create hooks directory structure
- **run_hooks** - emit events through the bus (backward-compatible wrapper)
- **list_hooks** - enumerate installed hook scripts
- **create_example_hook** - scaffold an example hook script
- **list_hooks_ui** - option 1: display hooks table
- **create_hook_ui** - option 2: interactive hook creation
- **open_hooks_dir** - option 3: open hooks in OS file manager
- **test_fire_hook** - option 4: test-fire a hook event
- **delete_hook_ui** - option 5: delete a hook script
"""

from __future__ import annotations

import importlib.util
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from rich.prompt import Prompt, Confirm
from rich.table import Table

from empusa.cli_common import (
    CONFIG,
    console,
    HOOKS_DIR,
    HOOK_EVENTS,
    IS_WINDOWS,
    log_error,
    log_info,
    log_success,
    log_verbose,
)

if TYPE_CHECKING:
    from empusa.bus import EventBus


# -- Bus reference (set by cli.main after initialization) -----------

_event_bus: Optional[EventBus] = None


def set_event_bus(bus: EventBus) -> None:
    """Set the event bus reference for hook dispatch."""
    global _event_bus
    _event_bus = bus


# -- Hook lifecycle --------------------------------------------------


def init_hook_dirs() -> None:
    """Create the hooks directory structure with a README in each event folder."""
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    readme_root = HOOKS_DIR / "README.md"
    if not readme_root.exists():
        readme_root.write_text(
            "# Empusa Hooks\n\n"
            "Drop Python scripts into any event folder below.\n"
            "Each script must define a `run(context)` function.\n\n"
            "## Hook Events\n\n"
            + "\n".join(f"- **{evt}/**" for evt in HOOK_EVENTS)
            + "\n\n"
            "## Context Dict\n\n"
            "Every hook receives a `context` dict with at minimum:\n"
            "```python\n"
            "{\n"
            '    "event": "<event_name>",\n'
            '    "timestamp": "2026-03-29 19:45:12",\n'
            '    "session_env": "kobold",\n'
            '    # ... plus event-specific keys\n'
            "}\n"
            "```\n\n"
            "## Example\n\n"
            "```python\n"
            "# empusa/hooks/on_loot_add/notify.py\n"
            "def run(context):\n"
            '    print(f"[Hook] New loot on {context[\'host\']}: {context[\'username\']}")\n'
            "```\n",
            encoding="utf-8",
        )

    for evt in HOOK_EVENTS:
        evt_dir = HOOKS_DIR / evt
        evt_dir.mkdir(exist_ok=True)
        gitkeep = evt_dir / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.touch()


def run_hooks(event: str, context: Optional[Dict[str, Any]] = None) -> None:
    """Emit an event through the bus (legacy hooks + plugins).

    This is the backward-compatible wrapper. All existing call sites
    continue to work unchanged. The bus handles:
    - Layer 2: legacy run(context) hook scripts
    - Layer 3: plugin dispatch (if PluginManager is attached)

    Args:
        event: One of the HOOK_EVENTS names.
        context: Dict of data passed to each hook's run() function.
    """
    if _event_bus is not None:
        _event_bus.emit_legacy(event, context)
    else:
        # Fallback before bus is initialized (shouldn't happen in normal flow)
        _fire_legacy_hooks_fallback(event, context)


def _fire_legacy_hooks_fallback(event: str, context: Optional[Dict[str, Any]] = None) -> None:
    """Direct hook execution fallback (used before the bus is initialized)."""
    evt_dir = HOOKS_DIR / event
    if not evt_dir.is_dir():
        return

    ctx: Dict[str, Any] = context.copy() if context else {}
    ctx.setdefault("event", event)
    ctx.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ctx.setdefault("session_env", CONFIG.get("session_env", ""))

    scripts = sorted(p for p in evt_dir.iterdir() if p.suffix == ".py" and p.is_file())
    for script in scripts:
        try:
            spec = importlib.util.spec_from_file_location(f"empusa_hook_{event}_{script.stem}", script)
            if spec is None or spec.loader is None:
                log_verbose(f"Warning: Could not load hook {script.name}", "yellow")
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            if hasattr(mod, "run") and callable(mod.run):
                log_verbose(f"Running hook: {event}/{script.name}", "cyan")
                mod.run(ctx)
            else:
                log_verbose(f"Warning: {script.name} has no run(context) function - skipped", "yellow")
        except Exception as e:
            log_error(f"Hook error [{event}/{script.name}]: {e}")


def list_hooks() -> Dict[str, List[str]]:
    """List all installed hook scripts grouped by event.

    Returns:
        Dict mapping event names to lists of script filenames.
    """
    result: Dict[str, List[str]] = {}
    for evt in HOOK_EVENTS:
        evt_dir = HOOKS_DIR / evt
        if evt_dir.is_dir():
            scripts = sorted(p.name for p in evt_dir.iterdir() if p.suffix == ".py" and p.is_file())
            result[evt] = scripts
        else:
            result[evt] = []
    return result


def create_example_hook(event: str) -> Path:
    """Create an example hook script for the given event.

    Args:
        event: Hook event name.

    Returns:
        Path to the created example script.
    """
    evt_dir = HOOKS_DIR / event
    evt_dir.mkdir(parents=True, exist_ok=True)

    # Find a unique filename
    name = "example.py"
    counter = 1
    while (evt_dir / name).exists():
        name = f"example_{counter}.py"
        counter += 1

    example_path = evt_dir / name

    context_hints: Dict[str, str] = {
        "on_startup": '    # context keys: event, timestamp, session_env',
        "on_shutdown": '    # context keys: event, timestamp, session_env, killed_pids, cleaned_hooks',
        "post_build": '    # context keys: event, timestamp, session_env, env_name, env_path, ips',
        "post_scan": '    # context keys: event, timestamp, session_env, ip, scan_output, os_type',
        "on_loot_add": '    # context keys: event, timestamp, session_env, host, cred_type, username, secret, source',
        "on_report_generated": '    # context keys: event, timestamp, session_env, report_path, env_name',
        "on_env_select": '    # context keys: event, timestamp, session_env, env_name',
    }

    hint = context_hints.get(event, '    # context keys: event, timestamp, session_env')

    example_path.write_text(
        f'"""\nEmpusa Hook - {event}\n\n'
        f'This script runs automatically when the \'{event}\' event fires.\n'
        f'Edit the run() function below to add your custom logic.\n"""\n\n\n'
        f'def run(context: dict) -> None:\n'
        f'{hint}\n'
        f'\n'
        f'    print(f"[Hook][{event}] fired at {{context[\'timestamp\']}}"\n'
        f'          f" | env: {{context.get(\'session_env\', \'N/A\')}}"\n'
        f'          )\n'
        f'\n'
        f'    # --- Add your logic below ---\n'
        f'    # Example: send a notification, write to a log, trigger a script, etc.\n'
        f'    pass\n',
        encoding="utf-8",
    )

    return example_path


# -- Option 1: List Installed Hooks ---------------------------------


def list_hooks_ui() -> None:
    """Display a table of all installed hooks grouped by event."""
    hooks = list_hooks()
    table = Table(
        title="Installed Hooks",
        show_lines=True,
        border_style="cyan",
        title_style="bold cyan",
    )
    table.add_column("Event", style="bold white", min_width=20)
    table.add_column("Scripts", style="green")

    total = 0
    for evt in HOOK_EVENTS:
        scripts = hooks.get(evt, [])
        total += len(scripts)
        if scripts:
            table.add_row(evt, "\n".join(scripts))
        else:
            table.add_row(evt, "[dim]- none -[/dim]")

    console.print(table)
    log_info(f"\nTotal: {total} hook script(s) across {len(HOOK_EVENTS)} events", "cyan")


# -- Option 2: Create Example Hook ----------------------------------


def create_hook_ui() -> None:
    """Interactive hook creation wizard."""
    log_info("\n[bold yellow]Create Example Hook[/bold yellow]")
    log_info("Available events:")
    for i, evt in enumerate(HOOK_EVENTS, 1):
        log_info(f"  {i}. {evt}")
    evt_choice = Prompt.ask("Select event #", choices=[str(i) for i in range(1, len(HOOK_EVENTS) + 1)])
    evt_name = HOOK_EVENTS[int(evt_choice) - 1]
    path = create_example_hook(evt_name)
    log_success(f"[+] Created: {path}")
    log_info("Edit this file to add your custom logic.", "yellow")


# -- Option 3: Open Hooks Directory ---------------------------------


def open_hooks_dir() -> None:
    """Open the hooks directory in the OS file manager."""
    try:
        if IS_WINDOWS:
            os.startfile(str(HOOKS_DIR))  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.run(["open", str(HOOKS_DIR)], check=False)
        else:
            subprocess.run(["xdg-open", str(HOOKS_DIR)], check=False)
        log_success(f"[+] Opened: {HOOKS_DIR}")
    except Exception as e:
        log_error(f"Could not open directory: {e}")
        log_info(f"Path: {HOOKS_DIR}", "yellow")


# -- Option 4: Test Fire Hook Event ---------------------------------


def test_fire_hook() -> None:
    """Interactively test-fire a hook event with synthetic context."""
    log_info("\n[bold yellow]Test Fire Hook Event[/bold yellow]")
    log_info("Available events:")
    for i, evt in enumerate(HOOK_EVENTS, 1):
        scripts = list_hooks().get(evt, [])
        count_str = f" ({len(scripts)} script{'s' if len(scripts) != 1 else ''})" if scripts else " [dim](empty)[/dim]"
        log_info(f"  {i}. {evt}{count_str}")
    evt_choice = Prompt.ask("Select event #", choices=[str(i) for i in range(1, len(HOOK_EVENTS) + 1)])
    evt_name = HOOK_EVENTS[int(evt_choice) - 1]
    log_info(f"\nFiring [bold]{evt_name}[/bold] with test context...", "cyan")
    test_ctx: Dict[str, Any] = {
        "event": evt_name,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "session_env": CONFIG.get('session_env', 'test'),
        "_test_fire": True,
        "ip": "10.10.10.10",
        "host": "10.10.10.10",
        "env_name": CONFIG.get('session_env', 'test'),
        "env_path": str(Path.cwd()),
        "username": "test_user",
        "secret": "test_secret",
        "cred_type": "plaintext",
        "source": "test",
    }
    run_hooks(evt_name, test_ctx)
    log_success(f"[+] {evt_name} hooks fired.")


# -- Option 5: Delete Hook Script -----------------------------------


def delete_hook_ui() -> None:
    """Interactively delete a hook script."""
    hooks = list_hooks()
    all_scripts: List[Tuple[str, str]] = []
    for evt in HOOK_EVENTS:
        for s in hooks.get(evt, []):
            all_scripts.append((evt, s))

    if not all_scripts:
        log_info("No hook scripts to delete.", "yellow")
        return

    log_info("\n[bold yellow]Delete Hook Script[/bold yellow]")
    for i, (evt, s) in enumerate(all_scripts, 1):
        log_info(f"  {i}. {evt}/{s}")

    try:
        idx = int(Prompt.ask("Script # to delete")) - 1
        if 0 <= idx < len(all_scripts):
            evt, s = all_scripts[idx]
            target = HOOKS_DIR / evt / s
            if Confirm.ask(f"Delete {evt}/{s}?"):
                target.unlink()
                log_success(f"[-] Deleted: {evt}/{s}")
        else:
            log_error("Invalid selection.")
    except ValueError:
        log_error("Please enter a valid number.")
