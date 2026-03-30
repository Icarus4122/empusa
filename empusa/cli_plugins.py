"""
Empusa - Plugin Manager UI (cli_plugins)

Interactive UI for managing the plugin lifecycle:

- **list_plugins** - option 6: status table of all plugins
- **create_plugin** - option 7: interactive scaffold wizard
- **toggle_plugin** - option 8: enable / disable with blocked guard
- **plugin_info** - option 9: detail view + config editor
- **uninstall_plugin_ui** - option 10: confirm + delete
- **show_registry** - option 11: capability registry table
- **open_plugins_dir** - option 12: open in OS file manager
"""

from __future__ import annotations

import os
import platform
import subprocess
from typing import List, Optional, TYPE_CHECKING

from rich.prompt import Prompt, Confirm
from rich.table import Table

from empusa.cli_common import (
    console,
    HOOK_EVENTS,
    IS_WINDOWS,
    PLUGINS_DIR,
    log_error,
    log_info,
    log_success,
)

if TYPE_CHECKING:
    from empusa.plugins import PluginManager
    from empusa.registry import CapabilityRegistry


# -- Option 6: List / Status Plugins --------------------------------


def list_plugins(plugin_manager: Optional[PluginManager]) -> None:
    """Display a status table of all discovered plugins."""
    if plugin_manager is None:
        log_error("Plugin system not initialized.")
        return
    plugins = plugin_manager.plugins
    if not plugins:
        log_info("No plugins installed.", "yellow")
        log_info(f"Create one with option 7, or drop a folder into:\n  {PLUGINS_DIR}", "dim")
        return

    table = Table(
        title="Installed Plugins",
        show_lines=True,
        border_style="magenta",
        title_style="bold magenta",
    )
    table.add_column("Name", style="bold white")
    table.add_column("Version", style="cyan")
    table.add_column("Status", min_width=10)
    table.add_column("Events", style="dim")
    table.add_column("Description")

    for desc in plugins.values():
        if desc.activated:
            status = "[bold green]● active[/bold green]"
        elif not desc.activatable:
            status = "[bold red]✗ blocked[/bold red]"
        elif desc.enabled:
            status = "[yellow]○ enabled[/yellow]"
        else:
            status = "[dim]✗ disabled[/dim]"
        table.add_row(
            desc.name,
            desc.version,
            status,
            ", ".join(desc.events) if desc.events else "[dim]none[/dim]",
            desc.description,
        )

    console.print(table)
    log_info(
        f"\n{plugin_manager.active_count()} active / "
        f"{plugin_manager.plugin_count()} total",
        "magenta",
    )


# -- Option 7: Create New Plugin ------------------------------------


def create_plugin(plugin_manager: Optional[PluginManager]) -> None:
    """Interactive scaffold wizard for a new plugin."""
    if plugin_manager is None:
        log_error("Plugin system not initialized.")
        return

    log_info("\n[bold magenta]Create New Plugin[/bold magenta]")
    name = Prompt.ask("Plugin name (slug)").strip().lower().replace(" ", "_")
    if not name:
        log_error("Name required.")
        return
    desc_text = Prompt.ask("Description", default="").strip()
    author = Prompt.ask("Author", default="").strip()

    log_info("\nSubscribe to events (comma-separated, or blank):")
    for i, evt in enumerate(HOOK_EVENTS, 1):
        log_info(f"  {i}. {evt}")
    evt_input = Prompt.ask("Event numbers", default="").strip()
    selected_events: List[str] = []
    if evt_input:
        for part in evt_input.split(","):
            try:
                idx = int(part.strip()) - 1
                if 0 <= idx < len(HOOK_EVENTS):
                    selected_events.append(HOOK_EVENTS[idx])
            except ValueError:
                pass

    log_info("\nPermissions (comma-separated, or blank):")
    log_info("  Available: network, filesystem, subprocess, loot_read, loot_write, registry")
    perm_input = Prompt.ask("Permissions", default="").strip()
    perms = [p.strip() for p in perm_input.split(",") if p.strip()] if perm_input else []

    path = plugin_manager.create_plugin_scaffold(
        name=name,
        description=desc_text,
        events=selected_events,
        permissions=perms,
        author=author,
    )
    log_success(f"[+] Created plugin scaffold: {path}")
    log_info("Edit plugin.py to implement your logic.", "yellow")

    # Re-discover so it shows up
    plugin_manager.discover()


# -- Option 8: Enable / Disable Plugin ------------------------------


def toggle_plugin(plugin_manager: Optional[PluginManager]) -> None:
    """Enable or disable a plugin, with blocked-state guard."""
    if plugin_manager is None:
        log_error("Plugin system not initialized.")
        return
    plugins = plugin_manager.plugins
    if not plugins:
        log_info("No plugins installed.", "yellow")
        return

    log_info("\n[bold magenta]Enable / Disable Plugin[/bold magenta]")
    names = list(plugins.keys())
    for i, n in enumerate(names, 1):
        d = plugins[n]
        if d.activated:
            status = "[green]active[/green]"
        elif not d.activatable:
            status = "[bold red]blocked[/bold red]"
        elif d.enabled:
            status = "[yellow]enabled[/yellow]"
        else:
            status = "[dim]disabled[/dim]"
        log_info(f"  {i}. {n} [{status}]")

    try:
        idx = int(Prompt.ask("Plugin #")) - 1
        if 0 <= idx < len(names):
            pname = names[idx]
            d = plugins[pname]
            if not d.activatable:
                log_error(
                    f"Plugin {pname!r} is blocked "
                    f"(unmet deps, cycle, or bad permissions). "
                    f"Use option 9 for details."
                )
            elif d.enabled or d.activated:
                if Confirm.ask(f"Disable {pname}?"):
                    plugin_manager.disable_plugin(pname)
                    log_success(f"[-] Disabled: {pname}")
            else:
                if Confirm.ask(f"Enable {pname}?"):
                    plugin_manager.enable_plugin(pname)
                    log_success(f"[+] Enabled: {pname}")
        else:
            log_error("Invalid selection.")
    except ValueError:
        log_error("Please enter a valid number.")


# -- Option 9: Plugin Info & Config ---------------------------------


def plugin_info(plugin_manager: Optional[PluginManager]) -> None:
    """Show plugin detail table and offer config editing."""
    if plugin_manager is None:
        log_error("Plugin system not initialized.")
        return
    plugins = plugin_manager.plugins
    if not plugins:
        log_info("No plugins installed.", "yellow")
        return

    names = list(plugins.keys())
    for i, n in enumerate(names, 1):
        log_info(f"  {i}. {n}")
    try:
        idx = int(Prompt.ask("Plugin #")) - 1
        if 0 <= idx < len(names):
            d = plugins[names[idx]]
            table = Table(
                title=f"Plugin: {d.name}",
                show_lines=True,
                border_style="magenta",
                title_style="bold magenta",
            )
            table.add_column("Field", style="bold white", min_width=15)
            table.add_column("Value", style="green")
            table.add_row("Name", d.name)
            table.add_row("Version", d.version)
            table.add_row("Author", d.author or "[dim]-[/dim]")
            table.add_row("Description", d.description)
            if d.activated:
                _ps = "active"
            elif not d.activatable:
                _ps = "blocked (unmet deps, cycle, or bad permissions)"
            elif d.enabled:
                _ps = "enabled"
            else:
                _ps = "disabled"
            table.add_row("Status", _ps)
            table.add_row("Events", ", ".join(d.events) if d.events else "none")
            table.add_row("Requires", ", ".join(d.requires) if d.requires else "none")
            table.add_row("Permissions", ", ".join(d.permissions) if d.permissions else "none")
            table.add_row("Path", str(d.path))
            console.print(table)

            if d.config:
                log_info("\n[bold]Config:[/bold]")
                for k, v in d.config.items():
                    log_info(f"  {k}: {v}")

            if Confirm.ask("\nEdit a config value?", default=False):
                key = Prompt.ask("Key").strip()
                val = Prompt.ask("Value").strip()
                plugin_manager.set_plugin_config(d.name, key, val)
                log_success(f"[+] Set {key} = {val}")
        else:
            log_error("Invalid selection.")
    except ValueError:
        log_error("Please enter a valid number.")


# -- Option 10: Uninstall Plugin ------------------------------------


def uninstall_plugin_ui(plugin_manager: Optional[PluginManager]) -> None:
    """Confirm and delete a plugin."""
    if plugin_manager is None:
        log_error("Plugin system not initialized.")
        return
    plugins = plugin_manager.plugins
    if not plugins:
        log_info("No plugins installed.", "yellow")
        return

    log_info("\n[bold red]Uninstall Plugin[/bold red]")
    names = list(plugins.keys())
    for i, n in enumerate(names, 1):
        log_info(f"  {i}. {n}")
    try:
        idx = int(Prompt.ask("Plugin #")) - 1
        if 0 <= idx < len(names):
            pname = names[idx]
            if Confirm.ask(f"[bold red]Permanently delete {pname}?[/bold red]"):
                if plugin_manager.uninstall_plugin(pname):
                    log_success(f"[-] Uninstalled: {pname}")
                else:
                    log_error(f"Failed to uninstall {pname}")
        else:
            log_error("Invalid selection.")
    except ValueError:
        log_error("Please enter a valid number.")


# -- Option 11: Capability Registry ---------------------------------


def show_registry(reg: Optional[CapabilityRegistry]) -> None:
    """Display a table of all registered capabilities."""
    if reg is None:
        log_error("Registry not available.")
        return
    summary = reg.summary()
    total = sum(summary.values())

    if total == 0:
        log_info("Capability registry is empty.", "yellow")
        log_info("Plugins register capabilities when activated.", "dim")
        return

    table = Table(
        title="Capability Registry",
        show_lines=True,
        border_style="yellow",
        title_style="bold yellow",
    )
    table.add_column("Category", style="bold white")
    table.add_column("Count", style="cyan", justify="right")
    table.add_column("Entries", style="green")

    for cat, count in summary.items():
        entries = reg.get(cat)
        names_str = ", ".join(e.name for e in entries) if entries else "[dim]-[/dim]"
        table.add_row(cat, str(count), names_str)

    console.print(table)
    log_info(f"\nTotal: {total} registered capability/ies", "yellow")


# -- Option 12: Open Plugins Directory ------------------------------


def open_plugins_dir() -> None:
    """Open the plugins directory in the OS file manager."""
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if IS_WINDOWS:
            os.startfile(str(PLUGINS_DIR))  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.run(["open", str(PLUGINS_DIR)], check=False)
        else:
            subprocess.run(["xdg-open", str(PLUGINS_DIR)], check=False)
        log_success(f"[+] Opened: {PLUGINS_DIR}")
    except Exception as e:
        log_error(f"Could not open directory: {e}")
        log_info(f"Path: {PLUGINS_DIR}", "yellow")
