from __future__ import annotations

import argparse
import atexit
import os
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from empusa.bus import EventBus
from empusa.cli_build import (
    ad_enum_playbook,
    build_env,
    build_reverse_tunnel,
    generate_hashcat_rules,
    hash_crack_builder,
    loot_tracker,
    privesc_enum_generator,
    search_exploits_from_nmap,
    summarize_hosts,
)
from empusa.cli_common import (
    CONFIG,
    HOOKS_DIR,
    IS_UNIX,
    IS_WINDOWS,
    PLUGINS_DIR,
    SESSION_ACTIONS,
    clear_screen,
    console,
    load_loot,
    log_action,
    log_error,
    log_info,
    log_success,
    log_verbose,
    pause,
    render_group_heading,
    render_kv,
    render_screen,
    set_console,
)
from empusa.cli_hooks import (
    create_hook_ui,
    delete_hook_ui,
    init_hook_dirs,
    list_hooks_render,
    manager_overview_render,
    open_hooks_dir,
    set_event_bus,
    test_fire_hook,
)
from empusa.cli_hooks import (
    run_hooks as _run_hooks,
)
from empusa.cli_modules import module_workshop
from empusa.cli_plugins import (
    create_plugin,
    list_plugins_render,
    open_plugins_dir,
    plugin_info,
    show_registry_render,
    toggle_plugin,
    uninstall_plugin_ui,
)
from empusa.cli_reports import report_builder
from empusa.cli_workspace import (
    cmd_workspace_init,
    cmd_workspace_list,
    cmd_workspace_select,
    cmd_workspace_status,
    register_workspace_parser,
)
from empusa.plugins import PluginManager

# Plugin framework imports
from empusa.registry import registry
from empusa.services import (
    ArtifactWriter,
    CommandRunner,
    EnvResolver,
    LoggerService,
    LootAccessor,
    Services,
)

# Global state (CONFIG, SESSION_ACTIONS, console, IS_WINDOWS, IS_UNIX,
# HOOKS_DIR, MODULES_DIR, PLUGINS_DIR, HOOK_EVENTS, logging helpers)
# are now imported from empusa.cli_common.


# Global framework singletons (initialized in main())
event_bus: EventBus | None = None
plugin_manager: PluginManager | None = None
services: Services | None = None


def manage_hooks() -> None:
    """Interactive plugin & hook manager (panel controller).

    Mirrors the module workshop pattern:
    render_screen -> render_kv -> one Rich table -> flat menu -> Prompt.
    """
    # Default content: overview table
    content: Any = manager_overview_render(plugin_manager, registry)

    while True:
        render_screen("Plugin & Hook Manager")
        render_kv("Hooks dir", f"[dim]{HOOKS_DIR}[/dim]")
        render_kv("Plugins dir", f"[dim]{PLUGINS_DIR}[/dim]")
        console.print("")

        # -- Content area --
        if content is not None:
            console.print(content)
            console.print("")

        log_info("[bold]Plugin & Hook Manager Menu:[/]")
        log_info("1. View Hooks")
        log_info("2. Create Hook")
        log_info("3. Test Hook Event")
        log_info("4. Delete Hook")
        log_info("5. Open Hooks Folder")
        log_info("6. View Plugins")
        log_info("7. Create Plugin")
        log_info("8. Enable / Disable Plugin")
        log_info("9. Plugin Info & Config")
        log_info("10. Uninstall Plugin")
        log_info("11. Open Plugins Folder")
        log_info("12. View Capability Registry")
        log_info("0. Back to Main Menu")

        valid = [str(i) for i in range(13)]
        choice = Prompt.ask("Select an option", choices=valid)

        if choice == "0":
            break
        elif choice == "1":
            content = list_hooks_render()
        elif choice == "2":
            create_hook_ui()
            content = list_hooks_render()
        elif choice == "3":
            test_fire_hook()
            content = list_hooks_render()
        elif choice == "4":
            delete_hook_ui()
            content = list_hooks_render()
        elif choice == "5":
            open_hooks_dir()
            content = "[green]✔[/green] Opened hooks folder"
        elif choice == "6":
            content = list_plugins_render(plugin_manager)
        elif choice == "7":
            create_plugin(plugin_manager)
            content = list_plugins_render(plugin_manager)
        elif choice == "8":
            toggle_plugin(plugin_manager)
            content = list_plugins_render(plugin_manager)
        elif choice == "9":
            plugin_info(plugin_manager)
            content = list_plugins_render(plugin_manager)
        elif choice == "10":
            uninstall_plugin_ui(plugin_manager)
            content = list_plugins_render(plugin_manager)
        elif choice == "11":
            open_plugins_dir()
            content = "[green]✔[/green] Opened plugins folder"
        elif choice == "12":
            content = show_registry_render(registry)


def print_banner() -> None:
    """Display the Empusa banner."""
    if CONFIG["quiet"]:
        return
    banner = r"""
[bold red]
              ▄████████████▄
          ▄███▀▀        ▀▀███▄
        ▄██▀    ▄▄▄▄▄▄     ▀██▄
       ██▀    ▄█▀    ▀█▄     ▀██
      ██     ▄█        █▄     ██
     ██     ███  ▄▄▄▄  ███     ██
     ██     ███ ██████ ███     ██   [dim]“She shifts form... beauty, beast, and death.”[/dim]
     ██     ███  ▀▀▀▀  ███     ██
     ██     ▀█▄        ▄█▀     ██   [italic red]Empusa - Devourer of Men, Feeder on Fear[/italic red]
      ██▄     ▀█▄▄▄▄▄▄█▀     ▄██
       ▀██▄     ▀▀▀▀▀▀     ▄██▀
         ▀███▄▄        ▄▄▄██▀
             ▀▀████████▀▀
[/bold red]

[bold magenta]
███████╗   ███╗   ███╗   ██████╗   ██╗   ██╗   ███████╗    █████╗
██╔════╝   ████╗ ████║   ██╔══██╗  ██║   ██║   ██╔════╝   ██╔══██╗
█████╗     ██╔████╔██║   ██████╔╝  ██║   ██║   ███████╗   ███████║
██╔══╝     ██║╚██╔╝██║   ██╔═══╝   ██║   ██║   ╚════██║   ██╔══██║
███████╗   ██║ ╚═╝ ██║   ██║       ╚██████╔╝   ███████║   ██║  ██║
╚══════╝   ╚═╝     ╚═╝   ╚═╝        ╚═════╝    ╚══════╝   ╚═╝  ╚═╝
[/bold magenta]

[bold cyan]  Shape-shifting Recon & Exploitation Framework[/bold cyan]
[green]  Inspired by Empusa - vampire, demon, and sorceress of stealth[/green]
[yellow]  https://github.com/Icarus4122/empusa  |  v{version}[/yellow]
"""
    from empusa import __version__ as version  # lightweight: __init__.py is metadata-only

    banner = banner.replace("{version}", version)
    console.print(Panel.fit(banner, border_style="red"))


def _cleanup_shell_history() -> list[str]:
    """Remove Empusa Command Logging blocks from shell RC files.

    Returns:
        List of RC file paths that were cleaned.
    """
    marker_start = "# Empusa Command Logging"
    cleaned_files: list[str] = []

    if IS_WINDOWS:
        profile_path = (
            Path(os.environ.get("USERPROFILE", ""))
            / "Documents"
            / "WindowsPowerShell"
            / "Microsoft.PowerShell_profile.ps1"
        )
        target_files = [profile_path]
    elif IS_UNIX:
        target_files = [Path.home() / ".bashrc", Path.home() / ".zshrc"]
    else:
        target_files = []

    for rc in target_files:
        if not rc.exists():
            continue
        try:
            original = rc.read_text(errors="ignore")
            if marker_start not in original:
                continue

            cleaned_lines: list[str] = []
            skip = False
            for line in original.splitlines(True):
                if marker_start in line:
                    skip = True
                    continue
                if skip:
                    stripped = line.strip()
                    if stripped == "" or (
                        not stripped.startswith("#")
                        and not stripped.startswith("$")
                        and not stripped.startswith("export ")
                        and not stripped.startswith("shopt ")
                        and not stripped.startswith("setopt ")
                        and not stripped.startswith("PROMPT_COMMAND")
                        and not stripped.startswith("Register-")
                        and not stripped.startswith("Get-History")
                        and not stripped.startswith("}")
                    ):
                        skip = False
                        cleaned_lines.append(line)
                    continue
                cleaned_lines.append(line)

            rc.write_text("".join(cleaned_lines))
            cleaned_files.append(str(rc))
            log_verbose(f"Removed Empusa logging hooks from {rc}", "green")
        except Exception as e:
            log_verbose(f"Warning: Could not clean {rc}: {e}", "yellow")

    return cleaned_files


def _kill_child_processes() -> list[str]:
    """Terminate any lingering child processes spawned by Empusa.

    Returns:
        List of descriptive strings for each killed process.
    """
    tool_names = ["nmap", "searchsploit"]
    killed: list[str] = []

    for tool in tool_names:
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["tasklist", "/FI", f"IMAGENAME eq {tool}.exe", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for csv_line in result.stdout.strip().splitlines():
                    if tool in csv_line.lower():
                        parts = csv_line.split('"')
                        if len(parts) >= 4:
                            pid = parts[3].strip()
                            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, timeout=5)
                            killed.append(f"{tool}.exe (PID {pid})")
            else:
                # Grab PIDs before killing so we can report them
                pgrep = subprocess.run(
                    ["pgrep", "-a", "-f", tool],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                pids_found: list[str] = []
                for pline in pgrep.stdout.strip().splitlines():
                    parts = pline.strip().split(None, 1)
                    if parts:
                        pids_found.append(parts[0])
                if pids_found:
                    subprocess.run(
                        ["pkill", "-f", tool],
                        capture_output=True,
                        timeout=5,
                    )
                    for p in pids_found:
                        killed.append(f"{tool} (PID {p})")
        except Exception:
            pass  # Best-effort cleanup

    if killed:
        log_verbose(f"Terminated lingering processes: {', '.join(killed)}", "yellow")

    return killed


def _build_execution_flow() -> str:
    """Build an ASCII art execution flow from session actions."""
    if not SESSION_ACTIONS:
        return ""

    flow_lines: list[str] = []
    flow_lines.append("[bold cyan]Session Execution Flow[/bold cyan]")
    flow_lines.append("")

    total = len(SESSION_ACTIONS)
    for i, action in enumerate(SESSION_ACTIONS):
        time_str = f"[dim]{action['time']}[/dim]"
        act_str = f"[bold white]{action['action']}[/bold white]"
        detail_str = f"  [dim]{action['detail']}[/dim]" if action.get("detail") else ""

        is_last = i == total - 1

        if i == 0:
            # Top of the flow
            flow_lines.append(f"  {time_str}  ┌-▶  {act_str}{detail_str}")
        elif is_last:
            # Bottom of the flow
            flow_lines.append(f"  {time_str}  └-▶  {act_str}{detail_str}")
        else:
            flow_lines.append(f"  {time_str}  ├-▶  {act_str}{detail_str}")

        # Draw connector to next node (unless last)
        if not is_last:
            flow_lines.append("             │")

    return "\n".join(flow_lines)


def _shutdown() -> None:
    """Graceful shutdown: kill children, remove shell hooks, print farewell."""
    if getattr(_shutdown, "_done", False):
        return  # Prevent double-run via atexit + explicit call
    _shutdown._done = True  # type: ignore[attr-defined]

    log_verbose("Running shutdown cleanup...", "dim")

    # 1. Kill lingering child processes
    killed = _kill_child_processes()

    # 2. Remove shell history hooks (only if explicitly enabled)
    cleaned: list[str] = []
    if CONFIG.get("enable_shell_hooks", False):
        cleaned = _cleanup_shell_history()
    else:
        log_verbose("Shell hook cleanup skipped (enable with --enable-shell-hooks)", "dim")

    # 3. Fire on_shutdown hooks
    _run_hooks(
        "on_shutdown",
        {
            "killed_pids": killed,
            "cleaned_hooks": cleaned,
        },
    )

    # 3b. Deactivate plugins
    if plugin_manager is not None:
        deactivated = plugin_manager.deactivate_all()
        if deactivated:
            log_verbose(f"Deactivated {deactivated} plugin(s)", "dim")

    # 4. Log the shutdown action itself
    log_action("Shutdown", "Graceful exit")

    # 5. Build farewell panel
    if not CONFIG["quiet"]:
        session_env = CONFIG.get("session_env", "")
        ws_name = CONFIG.get("workspace_name", "")
        ws_profile = CONFIG.get("workspace_profile", "")
        panel_lines: list[str] = []
        panel_lines.append("[bold red]Empusa[/bold red] session ended.")
        if ws_name:
            panel_lines.append(
                f"Active workspace: [cyan]{ws_name}[/cyan]"
                f" [dim](profile={ws_profile})[/dim]"
            )
        elif session_env:
            panel_lines.append(f"Active environment: [cyan]{session_env}[/cyan]")
        panel_lines.append(f"Timestamp: [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        panel_lines.append("")

        # Processes section
        if killed:
            panel_lines.append("[bold yellow]Processes Terminated:[/bold yellow]")
            for k in killed:
                panel_lines.append(f"  [red]✘[/red]  {k}")
        else:
            panel_lines.append("[green]✔[/green]  No lingering child processes found.")
        panel_lines.append("")

        # Shell hooks section
        if cleaned:
            panel_lines.append("[bold yellow]Shell Hooks Removed:[/bold yellow]")
            for rc_path in cleaned:
                panel_lines.append(f"  [red]✘[/red]  {rc_path}")
        else:
            panel_lines.append("[green]✔[/green]  No shell logging hooks to remove.")
        panel_lines.append("")

        # Execution flow
        flow = _build_execution_flow()
        if flow:
            panel_lines.append("-" * 50)
            panel_lines.append("")
            panel_lines.append(flow)
            panel_lines.append("")

        panel_lines.append('[italic dim]"She fades back into shadow…"[/italic dim]')
        console.print(
            Panel(
                "\n".join(panel_lines),
                title="[bold yellow]Shutdown Complete[/bold yellow]",
                border_style="red",
                padding=(1, 2),
            )
        )


def _handle_sigint(sig: int, frame: Any) -> None:
    """Handle Ctrl+C gracefully."""
    console.print("\n")
    log_info("Caught interrupt - shutting down...", "bold yellow")
    _shutdown()
    raise SystemExit(0)


def _detect_environments() -> list[str]:
    """Detect existing environments built by Empusa in the current directory."""
    envs: list[str] = []
    try:
        for entry in sorted(Path.cwd().iterdir()):
            if not entry.is_dir():
                continue
            # An environment dir contains at least one sub-dir with an nmap/ folde
            try:
                for sub in entry.iterdir():
                    if sub.is_dir() and (sub / "nmap").is_dir():
                        envs.append(entry.name)
                        break
            except Exception:
                continue
    except Exception:
        pass
    return envs


def _show_environments(envs: list[str]) -> None:
    """Display detected environments as a rich table with an active marker."""
    if not envs:
        return
    table = Table(
        title="Available Environments",
        show_lines=False,
        border_style="green",
        title_style="bold green",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Environment", style="bold white")
    table.add_column("Active", style="green", justify="center", width=8)

    for i, env in enumerate(envs, 1):
        marker = "✔" if env == CONFIG["session_env"] else ""
        table.add_row(str(i), env, marker)

    if not CONFIG["quiet"]:
        console.print(table)
        console.print("")


def summarize_command() -> None:
    """Display the main menu options grouped by category."""
    render_group_heading("Operations", "bold blue")
    log_info("  1. Build New Environment")
    log_info("  2. Build Reverse Tunnel")
    log_info("  3. Generate Hashcat Rules")
    log_info("  4. Search Exploits from Nmap Results")
    render_group_heading("Analysis & Tracking", "bold green")
    log_info("  5. Loot Tracker")
    log_info("  6. Report Builder")
    log_info("  10. Privesc Enumeration Generator")
    log_info("  11. Hash Identifier + Crack Builder")
    log_info("  12. AD Enumeration Playbook")
    render_group_heading("Framework", "bold yellow")
    log_info("  7. Select / Switch Environment")
    log_info("  8. Manage Hooks / Plugins")
    log_info("  9. Module Workshop")
    log_info("  0. Exit")


def _render_session_status() -> None:
    """Print a compact session status bar below the banner.

    Shows the active workspace (name + profile) when present,
    falls back to legacy session_env, or shows 'no active session'.
    """
    if CONFIG["quiet"]:
        return

    ws_name = CONFIG.get("workspace_name", "")
    ws_profile = CONFIG.get("workspace_profile", "")
    session_env = CONFIG.get("session_env", "")

    if ws_name:
        console.print(
            f"  [bold green]★[/bold green] Workspace: [bold cyan]{ws_name}[/bold cyan]"
            f"  [dim]profile={ws_profile}[/dim]"
        )
    elif session_env:
        console.print(
            f"  [yellow]▸[/yellow] Environment: [bold]{session_env}[/bold]"
            f"  [dim](legacy — no workspace selected)[/dim]"
        )
    else:
        console.print("  [dim]No active workspace or environment[/dim]")
    console.print()


def _ask_env(prompt_text: str = "Enter environment name") -> str:
    """Prompt for environment name, defaulting to the session env if set."""
    default = CONFIG["session_env"] if CONFIG["session_env"] else ""
    name = Prompt.ask(prompt_text, default=default).strip() if default else Prompt.ask(prompt_text).strip()
    if name:
        CONFIG["session_env"] = name
    return name


def _select_environment(envs: list[str]) -> None:
    """Let the user pick an environment from the detected list."""
    if not envs:
        log_info("No environments detected. Build one first.", "yellow")
        return

    _show_environments(envs)
    choices = [str(i) for i in range(len(envs) + 1)]
    log_info("0. None / clear active environment")
    pick = Prompt.ask("Select environment #", choices=choices, default="0")
    idx = int(pick)
    if idx == 0:
        CONFIG["session_env"] = ""
        log_info("Active environment cleared.", "yellow")
    else:
        CONFIG["session_env"] = envs[idx - 1]
        log_success(f"Active environment set to: {CONFIG['session_env']}")
        _run_hooks(
            "on_env_select",
            {
                "env_name": CONFIG["session_env"],
            },
        )


def main_menu() -> None:
    """Run the interactive main menu loop."""
    log_action("Session Start", "Empusa launched")

    # On first launch, detect environments and offer selection
    envs = _detect_environments()
    if envs and not CONFIG["session_env"]:
        print_banner()
        log_info(f"Detected {len(envs)} existing environment(s):\n", "green")
        _select_environment(envs)
        if CONFIG["session_env"]:
            log_action("Select Environment", CONFIG["session_env"])

    content: Any = None  # content buffer for action summaries

    while True:
        # Clear the previous iteration's output, then show fresh context
        clear_screen()
        print_banner()
        _render_session_status()
        envs = _detect_environments()
        if envs:
            _show_environments(envs)
        if CONFIG["session_env"]:
            summarize_hosts(CONFIG["session_env"])
            console.print("")
        summarize_command()

        # -- Content area --
        if content is not None:
            console.print("")
            console.print(content)

        choice = Prompt.ask("Select an option")
        content = None  # reset each iteration

        if choice == "1":
            env_name = _ask_env()
            ip_input = Prompt.ask("Enter IPs (comma-separated)")
            ips = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
            log_action("Build Environment", f"{env_name} -> {', '.join(ips)}")
            ws_path: Path | None = Path(CONFIG["workspace_path"]) if CONFIG["workspace_path"] else None
            layout = build_env(env_name, ips, run_hooks_fn=_run_hooks, workspace_path=ws_path)
            # Offer next steps if environment was created
            check_dir = layout.base_dir if layout is not None else Path(env_name).absolute()
            if check_dir.exists():
                # Re-detect so the fresh environment appears in the table
                envs = _detect_environments()
                render_screen(f"Post-Build — {env_name}")
                if envs:
                    _show_environments(envs)
                summarize_hosts(env_name, scans_dir=layout.scans_dir if layout else None)
                render_group_heading("Next Steps", "bold green")
                log_info("  1. Search Exploits from Nmap Results")
                log_info("  2. Build Reverse Tunnel")
                log_info("  3. Generate Hashcat Rules")
                log_info("  4. Open Loot Tracker")
                log_info("  5. Build Report")
                log_info("  0. Back to Main Menu")
                nxt = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5"], default="0")
                if nxt == "1":
                    log_action("Exploit Search", f"Post-build -> {env_name}")
                    scan_root = layout.scans_dir if layout else check_dir
                    for sub in sorted(scan_root.iterdir()):
                        if sub.is_dir() and "-" in sub.name:
                            nmap_f = sub / "nmap" / "full_scan.txt"
                            if nmap_f.exists():
                                search_exploits_from_nmap(nmap_f, services=services)
                    pause()
                    content = "[green]✔[/green] Exploit search complete"
                elif nxt == "2":
                    log_action("Reverse Tunnel", "Post-build")
                    build_reverse_tunnel()
                    pause()
                    content = "[green]✔[/green] Reverse tunnel configured"
                elif nxt == "3":
                    log_action("Hashcat Rules", "Post-build")
                    generate_hashcat_rules()
                    pause()
                    content = "[green]✔[/green] Hashcat rules generated"
                elif nxt == "4":
                    log_action("Loot Tracker", "Post-build")
                    loot_tracker(run_hooks_fn=_run_hooks, ask_env_fn=_ask_env)
                elif nxt == "5":
                    log_action("Report Builder", "Post-build")
                    report_builder(registry=registry, run_hooks_fn=_run_hooks, ask_env_fn=_ask_env)
            else:
                pause()
        elif choice == "2":
            log_action("Reverse Tunnel", "Builder")
            clear_screen()
            build_reverse_tunnel()
            pause()

        elif choice == "3":
            log_action("Hashcat Rules", "Generator")
            clear_screen()
            generate_hashcat_rules()
            pause()

        elif choice == "4":
            env_name = _ask_env()
            ip_target = Prompt.ask("Enter target IP or folder format (e.g., 10.10.10.10-Windows)")
            log_action("Exploit Search", f"{env_name}/{ip_target}")
            clear_screen()
            nmap_path = Path(env_name) / ip_target / "nmap" / "full_scan.txt"
            search_exploits_from_nmap(nmap_path, services=services)
            pause()

        elif choice == "5":
            log_action("Loot Tracker", CONFIG.get("session_env", ""))
            loot_tracker(run_hooks_fn=_run_hooks, ask_env_fn=_ask_env)
        elif choice == "6":
            log_action("Report Builder", CONFIG.get("session_env", ""))
            report_builder(registry=registry, run_hooks_fn=_run_hooks, ask_env_fn=_ask_env)
        elif choice == "7":
            if not envs:
                content = "[yellow]No environments detected. Build one first.[/yellow]"
            else:
                _select_environment(envs)
                if CONFIG["session_env"]:
                    log_action("Switch Environment", CONFIG["session_env"])
                content = (
                    f"[green]✔[/green] Active environment: {CONFIG['session_env']}"
                    if CONFIG["session_env"]
                    else "[yellow]Active environment cleared.[/yellow]"
                )
        elif choice == "8":
            log_action("Manage Hooks", "Plugin manager")
            manage_hooks()
        elif choice == "9":
            log_action("Module Workshop", "Compiler / builder")
            module_workshop(services=services, run_hooks_fn=_run_hooks)
        elif choice == "10":
            log_action("Privesc Enum", CONFIG.get("session_env", ""))
            clear_screen()
            privesc_enum_generator()
            pause()

        elif choice == "11":
            log_action("Hash Crack Builder", CONFIG.get("session_env", ""))
            clear_screen()
            hash_crack_builder()
            pause()

        elif choice == "12":
            log_action("AD Playbook", CONFIG.get("session_env", ""))
            clear_screen()
            ad_enum_playbook()
            pause()

        elif choice == "0":
            _shutdown()
            break
        else:
            log_error("Invalid choice. Try again.")


def init_framework() -> None:
    """Initialize hook system, event bus, services, and plugin manager.

    Must be called after CONFIG is populated from CLI args. Sets the
    module-level ``event_bus``, ``plugin_manager``, and ``services``
    globals.

    .. note:: Also accessible as ``_init_framework`` for backward compat.
    """
    global event_bus, plugin_manager, services

    # Re-propagate console in case set_console() was called before all
    # modules were loaded (belt-and-suspenders for --no-color).
    set_console(console)

    # Initialize hook system (Layer 2 - legacy hooks)
    init_hook_dirs()

    # Layer 5 - Runtime services
    _logger_svc = LoggerService(console, verbose=CONFIG["verbose"], quiet=CONFIG["quiet"])
    _env_svc = EnvResolver(CONFIG)
    _artifact_svc = ArtifactWriter(_env_svc)
    _loot_svc = LootAccessor(_env_svc)

    # Layer 1 - Event bus
    event_bus = EventBus(
        hooks_dir=HOOKS_DIR,
        verbose=CONFIG["verbose"],
        quiet=CONFIG["quiet"],
        log_verbose=log_verbose,
        log_error=log_error,
        session_env_fn=lambda: str(CONFIG.get("session_env", "")),
    )

    # Wire bus reference into cli_hooks for _run_hooks dispatch
    set_event_bus(event_bus)

    # Layer 5 - Command runner (wired to bus for pre/post_command events)
    def _bus_emit_void(evt: str, ctx: dict[str, Any]) -> None:
        if event_bus is not None:
            event_bus.emit_legacy(evt, ctx)

    _runner_svc = CommandRunner(
        logger=_logger_svc,
        dry_run=CONFIG["dry_run"],
        emit_fn=_bus_emit_void,
    )

    services = Services(
        logger=_logger_svc,
        artifact=_artifact_svc,
        loot=_loot_svc,
        env=_env_svc,
        runner=_runner_svc,
    )

    # Layer 3 - Plugin manager
    plugin_manager = PluginManager(
        plugins_dir=PLUGINS_DIR,
        services=services,
        registry=registry,
        bus=event_bus,
        log_verbose=log_verbose,
        log_error=log_error,
        log_info=log_info,
        log_success=log_success,
    )
    plugin_manager.init_dirs()

    # Attach plugin manager to bus so events route to plugins
    event_bus.attach_plugin_manager(plugin_manager)

    # Discover and activate plugins
    plugin_manager.discover()
    dep_warnings = plugin_manager.resolve_dependencies()
    for warn in dep_warnings:
        log_verbose(f"[Plugin] {warn}", "yellow")
    activated = plugin_manager.activate_all()
    if activated and CONFIG["verbose"]:
        log_verbose(f"[Plugin] {activated} plugin(s) activated", "green")


_init_framework = init_framework  # backward-compat alias


# -- Non-interactive subcommand handlers -----------------------------


def _cmd_build(args: argparse.Namespace) -> int:
    """Non-interactive build: ``empusa build --env NAME --ips IP,...``."""
    CONFIG["session_env"] = args.env
    ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
    if not ips:
        log_error("No IPs provided.")
        return 1
    _init_framework()
    _run_hooks("on_startup")
    log_action("Build Environment", f"{args.env} -> {', '.join(ips)}")
    ws_path: Path | None = Path(CONFIG["workspace_path"]) if CONFIG["workspace_path"] else None
    build_env(args.env, ips, run_hooks_fn=_run_hooks, workspace_path=ws_path)
    _shutdown()
    return 0


def _cmd_exploit_search(args: argparse.Namespace) -> int:
    """Non-interactive exploit search."""
    CONFIG["session_env"] = args.env
    _init_framework()
    _run_hooks("on_startup")
    nmap_path = Path(args.env) / args.host / "nmap" / "full_scan.txt"
    if not nmap_path.exists():
        log_error(f"Nmap results not found: {nmap_path}")
        _shutdown()
        return 1
    log_action("Exploit Search", f"{args.env}/{args.host}")
    search_exploits_from_nmap(nmap_path, services=services)
    _shutdown()
    return 0


def _cmd_loot(args: argparse.Namespace) -> int:
    """Non-interactive loot operations."""
    CONFIG["session_env"] = args.env
    _init_framework()
    _run_hooks("on_startup")

    if args.loot_action == "list":
        loot_file = Path(args.env) / "loot.json"
        entries = load_loot(loot_file)
        if not entries:
            log_info("No loot entries found.", "yellow")
        for entry in entries:
            console.print(entry)
    elif args.loot_action == "add":
        assert services is not None, "Services not initialized"
        new_entry: dict[str, Any] = {
            "host": args.loot_host or "",
            "cred_type": args.cred_type or "password",
            "username": args.username or "",
            "secret": args.secret or "",
            "source": args.source or "",
        }
        services.loot.append(new_entry)
        log_success(f"[+] Loot added: {new_entry}")
        _run_hooks(
            "on_loot_add",
            {
                **new_entry,
                "env_name": args.env,
                "env_path": str(Path(args.env).absolute()),
            },
        )
    else:
        log_error(f"Unknown loot action: {args.loot_action}")
        _shutdown()
        return 1

    _shutdown()
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Non-interactive report generation."""
    CONFIG["session_env"] = args.env
    _init_framework()
    _run_hooks("on_startup")
    log_action("Report Builder", args.env)
    from empusa.cli_reports import build_host_md, gather_env_host_data

    env_path = Path(args.env).absolute()
    if not env_path.exists():
        log_error(f"Environment not found: {env_path}")
        _shutdown()
        return 1

    assessment = args.assessment or args.env
    hosts = gather_env_host_data(env_path)
    if not hosts:
        log_info("No hosts found in environment.", "yellow")

    # Build a minimal report
    lines: list[str] = [f"# {assessment} - Penetration Test Report", ""]
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    for i, host in enumerate(hosts, 1):
        lines.extend(build_host_md(host, 3, i, "Target"))
    report_path = env_path / f"{assessment.replace(' ', '_')}_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log_success(f"[+] Report written: {report_path}")

    _run_hooks(
        "on_report_generated",
        {
            "report_path": str(report_path),
            "env_name": args.env,
        },
    )
    _shutdown()
    return 0


def _cmd_plugins_refresh(args: argparse.Namespace) -> int:
    """Non-interactive plugin refresh."""
    _init_framework()
    assert plugin_manager is not None
    warnings = plugin_manager.refresh()
    for w in warnings:
        log_info(f"  ⚠ {w}", "yellow")
    log_success(
        f"[+] Plugins refreshed: {plugin_manager.active_count()} active / {plugin_manager.plugin_count()} total"
    )
    _shutdown()
    return 0


def _cmd_workspace(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Non-interactive workspace subcommand dispatcher."""
    action = getattr(args, "ws_action", None)
    if action is None:
        parser.parse_args(["workspace", "--help"])
        return 1

    _init_framework()

    def _emit(evt: str, ctx: dict[str, Any]) -> None:
        if event_bus is not None:
            event_bus.emit_legacy(evt, ctx)

    rc: int
    if action == "init":
        rc = cmd_workspace_init(args, emit_fn=_emit)
    elif action == "list":
        rc = cmd_workspace_list(args)
    elif action == "select":
        rc = cmd_workspace_select(args, emit_fn=_emit)
    elif action == "status":
        rc = cmd_workspace_status(args)
    else:
        parser.parse_args(["workspace", "--help"])
        rc = 1

    _shutdown()
    return rc


def main() -> None:
    """Main entry point for the Empusa CLI."""
    from empusa import __version__

    parser = argparse.ArgumentParser(
        prog="empusa",
        description="Empusa - Shape-shifting Recon & Exploitation Automation Framework",
        epilog="Use responsibly and only with explicit authorization.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (detailed logging)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Maximum number of concurrent scan workers (default: 8)",
    )
    parser.add_argument(
        "--enable-shell-hooks",
        action="store_true",
        help="Allow Empusa to install/remove shell history logging hooks on exit (default: off)",
    )

    # -- Non-interactive subcommands ---------------------------------
    subparsers = parser.add_subparsers(dest="command", help="Non-interactive subcommands")

    # empusa build --env NAME --ips IP,IP,...
    sp_build = subparsers.add_parser("build", help="Build environment (non-interactive)")
    sp_build.add_argument("--env", required=True, help="Environment name")
    sp_build.add_argument("--ips", required=True, help="Comma-separated target IPs")

    # empusa exploit-search --env NAME --host FOLDER
    sp_exploit = subparsers.add_parser("exploit-search", help="Search exploits from nmap results")
    sp_exploit.add_argument("--env", required=True, help="Environment name")
    sp_exploit.add_argument("--host", required=True, help="Host folder (e.g. 10.10.10.10-Linux)")

    # empusa loot --env NAME list|add [--host H --cred-type T --username U --secret S --source SRC]
    sp_loot = subparsers.add_parser("loot", help="Loot operations (non-interactive)")
    sp_loot.add_argument("--env", required=True, help="Environment name")
    sp_loot.add_argument("loot_action", choices=["list", "add"], help="Loot action")
    sp_loot.add_argument("--host", dest="loot_host", default="", help="Host IP (for add)")
    sp_loot.add_argument("--cred-type", default="password", help="Credential type (for add)")
    sp_loot.add_argument("--username", default="", help="Username (for add)")
    sp_loot.add_argument("--secret", default="", help="Secret / password / hash (for add)")
    sp_loot.add_argument("--source", default="", help="Source description (for add)")

    # empusa report --env NAME [--assessment TITLE]
    sp_report = subparsers.add_parser("report", help="Generate report (non-interactive)")
    sp_report.add_argument("--env", required=True, help="Environment name")
    sp_report.add_argument("--assessment", default="", help="Assessment / report title")

    # empusa plugins refresh
    sp_plugins = subparsers.add_parser("plugins", help="Plugin management (non-interactive)")
    sp_plugins_sub = sp_plugins.add_subparsers(dest="plugins_action")
    sp_plugins_sub.add_parser("refresh", help="Refresh plugin lifecycle")

    # empusa workspace init|list|select|status
    register_workspace_parser(subparsers)

    args = parser.parse_args()

    # Update global configuration
    CONFIG["verbose"] = args.verbose
    CONFIG["quiet"] = args.quiet
    CONFIG["dry_run"] = args.dry_run
    CONFIG["no_color"] = args.no_color
    CONFIG["max_workers"] = max(1, args.workers)
    CONFIG["enable_shell_hooks"] = args.enable_shell_hooks

    # Configure console based on settings
    if args.no_color:
        _no_color_console = Console(no_color=True, force_terminal=False)
        set_console(_no_color_console)  # propagates to all submodules

    if args.verbose and args.quiet:
        log_error("Cannot use --verbose and --quiet together")
        raise SystemExit(1)

    if args.dry_run:
        log_info("[DRY RUN MODE] No changes will be made", "bold yellow")

    # Register cleanup handlers
    atexit.register(_shutdown)
    signal.signal(signal.SIGINT, _handle_sigint)

    # -- Dispatch subcommand or fall through to interactive menu ------
    if args.command == "build":
        raise SystemExit(_cmd_build(args))
    elif args.command == "exploit-search":
        raise SystemExit(_cmd_exploit_search(args))
    elif args.command == "loot":
        raise SystemExit(_cmd_loot(args))
    elif args.command == "report":
        raise SystemExit(_cmd_report(args))
    elif args.command == "plugins":
        if getattr(args, "plugins_action", None) == "refresh":
            raise SystemExit(_cmd_plugins_refresh(args))
        else:
            parser.parse_args(["plugins", "--help"])
            return
    elif args.command == "workspace":
        raise SystemExit(_cmd_workspace(args, parser))

    # -- No subcommand: interactive mode -----------------------------
    _init_framework()
    _run_hooks("on_startup")
    main_menu()


if __name__ == "__main__":
    main()
