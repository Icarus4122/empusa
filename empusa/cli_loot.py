"""Empusa - Loot tracker for managing credentials, hashes, and flags."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from rich.prompt import Confirm, Prompt
from rich.table import Table

from empusa.cli_common import (
    console,
    load_loot,
    log_error,
    log_info,
    log_success,
    log_verbose,
    render_screen,
)


def _save_loot(loot_file: Path, entries: list[dict[str, Any]]) -> None:
    """Save loot entries to JSON file."""
    try:
        loot_file.write_text(json.dumps(entries, indent=2, default=str))
    except Exception as e:
        log_error(f"Error saving loot file: {e}")


def _display_loot_table(entries: list[dict[str, Any]], title: str = "Loot Tracker") -> None:
    """Render loot entries as a rich table."""
    if not entries:
        log_info("No loot entries found.", "yellow")
        return

    table = Table(title=title, show_lines=True, border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Host", style="bold white", min_width=15)
    table.add_column("Type", style="magenta", min_width=10)
    table.add_column("Username", style="green", min_width=12)
    table.add_column("Secret", style="red", min_width=16)
    table.add_column("Source", style="yellow", min_width=10)
    table.add_column("Notes", style="dim", min_width=12)
    table.add_column("Timestamp", style="dim cyan", width=19)

    for i, entry in enumerate(entries, 1):
        table.add_row(
            str(i),
            entry.get("host", ""),
            entry.get("cred_type", ""),
            entry.get("username", ""),
            entry.get("secret", ""),
            entry.get("source", ""),
            entry.get("notes", ""),
            entry.get("timestamp", ""),
        )

    console.print(table)


def _import_env_creds(env_path: Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Import credentials from existing environment user/password files."""
    users_files = list(env_path.rglob("*-users.txt"))
    password_files = list(env_path.rglob("*-passwords.txt"))

    if not users_files and not password_files:
        log_info("No user/password files found in this environment.", "yellow")
        return entries

    existing_secrets: set[str] = set()
    for e in entries:
        key = f"{e.get('username', '')}:{e.get('secret', '')}:{e.get('host', '')}"
        existing_secrets.add(key)

    imported = 0

    for uf in users_files:
        try:
            for line in uf.read_text(errors="ignore").splitlines():
                username = line.strip()
                if not username or username.startswith("#"):
                    continue
                key = f"{username}::env-import"
                if key not in existing_secrets:
                    entries.append(
                        {
                            "host": "unknown",
                            "cred_type": "username",
                            "username": username,
                            "secret": "",
                            "source": uf.name,
                            "notes": "Imported from env users file",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )
                    existing_secrets.add(key)
                    imported += 1
        except Exception as e:
            log_verbose(f"Warning: Could not read {uf}: {e}", "yellow")

    for pf in password_files:
        try:
            for line in pf.read_text(errors="ignore").splitlines():
                password = line.strip()
                if not password or password.startswith("#"):
                    continue
                key = f":{password}:env-import"
                if key not in existing_secrets:
                    entries.append(
                        {
                            "host": "unknown",
                            "cred_type": "plaintext",
                            "username": "",
                            "secret": password,
                            "source": pf.name,
                            "notes": "Imported from env passwords file",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )
                    existing_secrets.add(key)
                    imported += 1
        except Exception as e:
            log_verbose(f"Warning: Could not read {pf}: {e}", "yellow")

    log_success(f"[+] Imported {imported} new entries")
    return entries


def _sync_loot_to_env_files(env_path: Path, entries: list[dict[str, Any]]) -> None:
    """Write loot usernames/passwords back to the environment user/password files."""
    env_name = env_path.name

    users_file = env_path / f"{env_name}-users.txt"
    passwords_file = env_path / f"{env_name}-passwords.txt"

    existing_users: set[str] = set()
    existing_passwords: set[str] = set()

    if users_file.exists():
        existing_users = set(
            line.strip()
            for line in users_file.read_text(errors="ignore").splitlines()
            if line.strip() and not line.startswith("#")
        )
    if passwords_file.exists():
        existing_passwords = set(
            line.strip()
            for line in passwords_file.read_text(errors="ignore").splitlines()
            if line.strip() and not line.startswith("#")
        )

    new_users = 0
    new_passwords = 0

    for entry in entries:
        username = entry.get("username", "").strip()
        secret = entry.get("secret", "").strip()
        cred_type = entry.get("cred_type", "")

        if username and username not in existing_users:
            existing_users.add(username)
            new_users += 1

        if secret and cred_type in ("plaintext", "password") and secret not in existing_passwords:
            existing_passwords.add(secret)
            new_passwords += 1

    try:
        if new_users > 0 or not users_file.exists():
            with users_file.open("w") as f:
                f.write(f"# Users for {env_name} - synced by Empusa Loot Tracker\n")
                for u in sorted(existing_users):
                    f.write(u + "\n")
            log_verbose(f"Synced {new_users} new usernames to {users_file}", "green")

        if new_passwords > 0 or not passwords_file.exists():
            with passwords_file.open("w") as f:
                f.write(f"# Passwords for {env_name} - synced by Empusa Loot Tracker\n")
                for p in sorted(existing_passwords):
                    f.write(p + "\n")
            log_verbose(f"Synced {new_passwords} new passwords to {passwords_file}", "green")
    except Exception as e:
        log_error(f"Error syncing to env files: {e}")


def _export_loot_markdown(entries: list[dict[str, Any]], export_path: Path) -> None:
    """Export loot to a Markdown file suitable for reports."""
    try:
        hosts: dict[str, list[dict[str, Any]]] = {}
        for entry in entries:
            host = entry.get("host", "unknown")
            hosts.setdefault(host, []).append(entry)

        with export_path.open("w") as f:
            f.write("# Loot Report\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total entries: {len(entries)}\n\n")

            for host in sorted(hosts.keys()):
                f.write(f"## {host}\n\n")
                f.write("| Type | Username | Secret | Source | Notes |\n")
                f.write("|------|----------|--------|--------|-------|\n")
                for e in hosts[host]:
                    f.write(
                        f"| {e.get('cred_type', '')} "
                        f"| {e.get('username', '')} "
                        f"| {e.get('secret', '')} "
                        f"| {e.get('source', '')} "
                        f"| {e.get('notes', '')} |\n"
                    )
                f.write("\n")

            user_hosts: dict[str, list[str]] = {}
            for entry in entries:
                username = entry.get("username", "")
                host = entry.get("host", "unknown")
                if username:
                    user_hosts.setdefault(username, []).append(host)

            reused = {u: h for u, h in user_hosts.items() if len(set(h)) > 1}
            if reused:
                f.write("## Credential Reuse\n\n")
                f.write("| Username | Found On |\n")
                f.write("|----------|----------|\n")
                for user, host_list in sorted(reused.items()):
                    f.write(f"| {user} | {', '.join(sorted(set(host_list)))} |\n")
                f.write("\n")

        log_success(f"[+] Loot report exported to: {export_path}")
    except Exception as e:
        log_error(f"Error exporting loot: {e}")


# -- Loot render helpers (panel controller) --------------------------


def _display_loot_table_render(
    entries: list[dict[str, Any]],
    title: str = "Loot Tracker",
) -> Any:
    """Return loot entries as a Rich Table, or a message if empty."""
    if not entries:
        return "[yellow]No loot entries found.[/yellow]"

    table = Table(title=title, show_lines=True, border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Host", style="bold white", min_width=15)
    table.add_column("Type", style="magenta", min_width=10)
    table.add_column("Username", style="green", min_width=12)
    table.add_column("Secret", style="red", min_width=16)
    table.add_column("Source", style="yellow", min_width=10)
    table.add_column("Notes", style="dim", min_width=12)
    table.add_column("Timestamp", style="dim cyan", width=19)

    for i, entry in enumerate(entries, 1):
        table.add_row(
            str(i),
            entry.get("host", ""),
            entry.get("cred_type", ""),
            entry.get("username", ""),
            entry.get("secret", ""),
            entry.get("source", ""),
            entry.get("notes", ""),
            entry.get("timestamp", ""),
        )

    return table


def _reuse_analysis_render(entries: list[dict[str, Any]]) -> str:
    """Return credential reuse analysis as formatted Rich markup text."""
    lines: list[str] = ["[bold yellow]Credential Reuse Analysis[/bold yellow]", ""]

    user_hosts: dict[str, list[str]] = {}
    secret_hosts: dict[str, list[str]] = {}

    for entry in entries:
        username = entry.get("username", "")
        secret_val = entry.get("secret", "")
        host = entry.get("host", "unknown")
        if username:
            user_hosts.setdefault(username, []).append(host)
        if secret_val:
            secret_hosts.setdefault(secret_val, []).append(host)

    reused_users = {u: list(set(h)) for u, h in user_hosts.items() if len(set(h)) > 1}
    reused_secrets = {s: list(set(h)) for s, h in secret_hosts.items() if len(set(h)) > 1}

    if reused_users:
        lines.append("[bold green]Usernames found on multiple hosts:[/bold green]")
        for user, hosts_list in sorted(reused_users.items()):
            lines.append(f"  {user}: {', '.join(sorted(hosts_list))}")
    else:
        lines.append("[dim]No username reuse detected across hosts.[/dim]")

    if reused_secrets:
        lines.append("\n[bold green]Secrets/hashes reused across hosts:[/bold green]")
        for secret_val, hosts_list in sorted(reused_secrets.items()):
            masked = secret_val[:4] + "****" if len(secret_val) > 4 else "****"
            lines.append(f"  {masked}: {', '.join(sorted(hosts_list))}")
    else:
        lines.append("\n[dim]No secret reuse detected across hosts.[/dim]")

    # Suggestions
    all_hosts: set[str] = set()
    for entry in entries:
        h = entry.get("host", "unknown")
        if h != "unknown":
            all_hosts.add(h)

    if all_hosts and entries:
        tested_combos: set[str] = {f"{e.get('username', '')}@{e.get('host', '')}" for e in entries}
        suggestions: list[str] = []
        for entry in entries:
            username = entry.get("username", "")
            secret_val = entry.get("secret", "")
            if not username or not secret_val:
                continue
            for h in all_hosts:
                combo = f"{username}@{h}"
                if combo not in tested_combos:
                    suggestions.append(f"  Try {username}:{secret_val[:4]}**** -> {h}")

        if suggestions:
            lines.append("\n[bold yellow]Suggested credential sprays:[/bold yellow]")
            for s in suggestions[:15]:
                lines.append(s)
            if len(suggestions) > 15:
                lines.append(f"  [dim]... and {len(suggestions) - 15} more[/dim]")

    return "\n".join(lines)


def loot_tracker(
    *,
    run_hooks_fn: Callable[..., Any] | None = None,
    ask_env_fn: Callable[..., str] | None = None,
) -> None:
    """Interactive loot tracker for managing credentials, hashes, and flags."""
    env_name = ask_env_fn() if ask_env_fn is not None else Prompt.ask("Enter environment name").strip()

    env_path = Path(env_name).absolute()

    if not env_path.exists():
        log_error(f"Environment '{env_name}' not found.")
        if not Confirm.ask("Create it anyway?"):
            return
        env_path.mkdir(parents=True, exist_ok=True)

    loot_file = env_path / "loot.json"
    entries = load_loot(loot_file)

    log_info(f"Loaded {len(entries)} loot entries from {loot_file.name}", "cyan")

    cred_types = [
        "plaintext",
        "ntlm",
        "netntlm",
        "kerberos",
        "aes-key",
        "ssh-key",
        "hash-other",
        "token",
        "flag",
        "username",
        "other",
    ]

    # Default content: loot table
    content: Any = _display_loot_table_render(entries, title=f"Loot - {env_name}")

    while True:
        render_screen(f"Loot Tracker [{env_name}] \u2014 {len(entries)} entries")

        # -- Content area --
        if content is not None:
            console.print(content)
            console.print("")

        log_info("[bold]Loot Tracker Menu:[/]")
        log_info("1. Add Loot Entry")
        log_info("2. View All Loot")
        log_info("3. Search Loot")
        log_info("4. Delete Entry")
        log_info("5. Import from Environment Files")
        log_info("6. Sync Loot -> Environment Files")
        log_info("7. Credential Reuse Check")
        log_info("8. Export Loot Report (Markdown)")
        log_info("0. Back to Main Menu")

        choice = Prompt.ask("Select an option", choices=[str(i) for i in range(9)])

        if choice == "0":
            _save_loot(loot_file, entries)
            log_success(f"Loot saved to {loot_file}")
            break

        elif choice == "1":
            log_info("\n[bold yellow]Add Loot Entry[/bold yellow]")
            host = Prompt.ask("Host IP/hostname", default="unknown")
            cred_type = Prompt.ask(
                f"Credential type ({', '.join(cred_types)})",
                default="plaintext",
            )
            username = Prompt.ask("Username (blank if N/A)", default="")
            secret = Prompt.ask("Secret (password/hash/flag/key)", default="")
            source = Prompt.ask("Source (where you found it)", default="")
            notes = Prompt.ask("Notes (optional)", default="")

            entry: dict[str, Any] = {
                "host": host,
                "cred_type": cred_type,
                "username": username,
                "secret": secret,
                "source": source,
                "notes": notes,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            entries.append(entry)
            _save_loot(loot_file, entries)
            log_success("[+] Loot entry added and saved!")

            if run_hooks_fn is not None:
                run_hooks_fn("on_loot_add", {
                    "host": host,
                    "cred_type": cred_type,
                    "username": username,
                    "secret": secret,
                    "source": source,
                    "env_name": env_name,
                    "env_path": str(env_path),
                })

            if cred_type == "ntlm":
                log_info("  Tip: nxc smb <targets> -u <user> -H '<hash>'", "yellow")
            elif cred_type == "kerberos":
                log_info(
                    "  Tip: export KRB5CCNAME=<ticket> && impacket-psexec <domain>/<user>@<ip> -k -no-pass", "yellow"
                )
            elif cred_type == "ssh-key":
                log_info("  Tip: chmod 600 <key> && ssh -i <key> <user>@<host>", "yellow")
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == "2":
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == "3":
            log_info("\n[bold yellow]Search Loot[/bold yellow]")
            log_info("Search by: 1=Host, 2=Username, 3=Type, 4=Keyword (any field)")
            search_type = Prompt.ask("Search by", choices=["1", "2", "3", "4"])
            query = Prompt.ask("Search term").strip().lower()

            if search_type == "1":
                results = [e for e in entries if query in e.get("host", "").lower()]
            elif search_type == "2":
                results = [e for e in entries if query in e.get("username", "").lower()]
            elif search_type == "3":
                results = [e for e in entries if query in e.get("cred_type", "").lower()]
            else:
                results = [e for e in entries if any(query in str(v).lower() for v in e.values())]

            _display_loot_table(results, title=f"Search results: '{query}'")
            content = _display_loot_table_render(results, title=f"Search results: '{query}'")

        elif choice == "4":
            if not entries:
                content = "[yellow]No entries to delete.[/yellow]"
                continue

            _display_loot_table(entries, title=f"Loot - {env_name}")
            try:
                idx = int(Prompt.ask("Entry # to delete")) - 1
                if 0 <= idx < len(entries):
                    removed = entries.pop(idx)
                    _save_loot(loot_file, entries)
                    log_success(
                        f"[-] Removed: {removed.get('username', '')}@{removed.get('host', '')} "
                        f"({removed.get('cred_type', '')})"
                    )
                else:
                    log_error("Invalid entry number.")
            except ValueError:
                log_error("Please enter a valid number.")
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == "5":
            entries = _import_env_creds(env_path, entries)
            _save_loot(loot_file, entries)
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == "6":
            _sync_loot_to_env_files(env_path, entries)
            content = "[green]✔[/green] Loot synced to environment files"

        elif choice == "7":
            content = _reuse_analysis_render(entries)

        elif choice == "8":
            export_path = env_path / "loot_report.md"
            _export_loot_markdown(entries, export_path)
            content = f"[green]✔[/green] Loot report exported to: {export_path}"
