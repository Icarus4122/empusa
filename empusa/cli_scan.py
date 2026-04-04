"""Empusa - Scanning, environment build, and network utilities."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
)

from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich.table import Table

from empusa.cli_common import (
    CONFIG,
    IS_UNIX,
    IS_WINDOWS,
    check_tool_exists,
    console,
    log_error,
    log_info,
    log_success,
    log_verbose,
    sanitize_filename,
)

if TYPE_CHECKING:
    from empusa.services import Services


# ═══════════════════════════════════════════════════════════════════
#  IP / Port / Hostname validation
# ═══════════════════════════════════════════════════════════════════


def validate_ip(ip: str) -> bool:
    """Validate if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port_str: str) -> bool:
    """Validate if string is a valid port number (1-65535)."""
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """Validate if string is a valid IP or hostname."""
    if validate_ip(hostname):
        return True
    return bool(
        re.match(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?" r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
            hostname,
        )
    )


# ═══════════════════════════════════════════════════════════════════
#  OS detection & Nmap integration
# ═══════════════════════════════════════════════════════════════════


def detect_os(nmap_output: Path) -> str:
    """Detect OS from nmap output file.

    Returns:
        "Windows", "Linux", or "Unknown"
    """
    nmap_path = Path(nmap_output)
    if not nmap_path.exists():
        log_verbose(f"Warning: {nmap_output} not found for OS detection", "yellow")
        return "Unknown"

    try:
        content = nmap_path.read_text(errors="ignore").lower()
        if "microsoft" in content or "windows" in content:
            return "Windows"
        elif any(x in content for x in ["linux", "unix", "ubuntu", "debian", "centos", "apache"]):
            return "Linux"
        else:
            return "Unknown"
    except Exception as e:
        log_verbose(f"Warning: Could not read {nmap_output}: {e}", "yellow")
        return "Unknown"


def search_exploits_from_nmap(
    nmap_file: Path,
    *,
    services: Services | None = None,
) -> None:
    """Parse nmap results and search for exploits using searchsploit."""
    nmap_path = Path(nmap_file)
    if not nmap_path.exists():
        log_error(f"Nmap file not found: {nmap_file}")
        return

    if not check_tool_exists("searchsploit"):
        log_error("Error: searchsploit not found on PATH.")
        log_info("Install exploit-db or skip this step.", "yellow")
        return

    if CONFIG["dry_run"]:
        log_info("[DRY RUN] Would search exploits from nmap results", "yellow")
        return

    log_info(f"[*] Parsing services from {nmap_file} and searching exploits...")

    try:
        lines = nmap_path.read_text(errors="ignore").splitlines()
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        return

    found_terms: set[str] = set()
    service_regex = re.compile(r"(\d+)/(tcp|udp)\s+open\s+([\w\-]+)(\s+([\w\-\.]+))?")

    for line in lines:
        match = service_regex.search(line)
        if match:
            service = match.group(3)
            version = match.group(5) if match.group(5) else ""
            query = f"{service} {version}".strip()
            found_terms.add(query)

    exploit_log = nmap_path.parent / "searchsploit_results.md"

    try:
        with exploit_log.open("w") as out:
            out.write("# Exploit Search Results\n")
            out.write(f"Generated: {datetime.now().isoformat()}\n\n")

            for term in sorted(found_terms):
                log_info(f"\n>> searchsploit {term}", "bold yellow")
                out.write(f"## Exploits for: {term}\n")
                try:
                    if services is not None:
                        result = services.runner.run(
                            ["searchsploit", term],
                            timeout=30,
                        )
                    else:
                        result = subprocess.run(
                            ["searchsploit", term],
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=30,
                        )
                    if not CONFIG["quiet"]:
                        console.print(result.stdout)
                    out.write(f"```\n{result.stdout}\n```\n\n")
                except subprocess.TimeoutExpired:
                    msg = "searchsploit timed out\n"
                    log_verbose(msg, "yellow")
                    out.write(msg + "\n")
                except Exception as e:
                    msg = f"Error running searchsploit: {e}\n"
                    log_verbose(msg, "yellow")
                    out.write(msg + "\n")

        log_success(f"[+] Saved exploit suggestions to: {exploit_log}")
    except Exception as e:
        log_error(f"Error writing exploit log: {e}")


def run_nmap(
    ip: str,
    output_path: Path,
    *,
    run_hooks_fn: Callable[..., Any] | None = None,
) -> tuple[str, Path]:
    """Run nmap scan against target IP.

    Returns:
        Tuple of (ip, output_file_path)
    """
    output_path = Path(output_path)
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = output_path / "full_scan.txt"
    greppable = output_path / "ports_grep.txt"

    if not check_tool_exists("nmap"):
        log_error("Error: nmap not found on PATH.")
        log_info("Install nmap before running scans.", "yellow")
        return ip, output_file

    if CONFIG["dry_run"]:
        log_info(f"[DRY RUN] Would scan {ip}", "yellow")
        return ip, output_file

    def _run_nmap_cmd(cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
        """Run nmap command with error handling."""
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                timeout=600,  # 10 minute timeout
            )
        except subprocess.TimeoutExpired:
            log_verbose(f"Warning: Nmap scan timed out for {ip}", "yellow")
            return subprocess.CompletedProcess(cmd, 1, b"", b"Timeout")
        except Exception as e:
            log_error(f"Error running nmap: {e}")
            return subprocess.CompletedProcess(cmd, 1, b"", str(e).encode())

    def _parse_greppable(path: Path) -> list[str]:
        """Parse greppable nmap output for open ports."""
        ports: set[str] = set()
        rx = re.compile(r"(\d+)/open/(?:tcp|udp)", re.IGNORECASE)

        if not path.exists():
            return []

        try:
            for line in path.read_text(errors="ignore").splitlines():
                if "Ports:" not in line:
                    continue
                for m in rx.finditer(line):
                    ports.add(m.group(1))
        except Exception as e:
            log_verbose(f"Warning: Could not parse {path}: {e}", "yellow")

        return sorted(ports, key=int)

    if run_hooks_fn is not None:
        run_hooks_fn(
            "pre_scan_host",
            {
                "ip": ip,
                "env_name": CONFIG.get("session_env", ""),
            },
        )

    log_info(f"[*] Scanning (fast discovery) on {ip}...")

    disc_cmd = [
        "nmap",
        "-n",
        "-T4",
        "-Pn",
        "-A",
        ip,
        "-oG",
        str(greppable),
    ]
    _run_nmap_cmd(disc_cmd)
    open_ports = _parse_greppable(greppable)

    if not open_ports:
        log_verbose("No ports found, retrying discovery with higher retries…", "yellow")
        disc_cmd_retry = [
            "nmap",
            "-n",
            "-T5",
            "-Pn",
            "-p-",
            "--max-rtt-timeout",
            "1000ms",
            "-sS",
            ip,
            "-oG",
            str(greppable),
        ]
        _run_nmap_cmd(disc_cmd_retry)
        open_ports = _parse_greppable(greppable)

    if not open_ports:
        log_verbose("Discovery still empty. Falling back to -A (full) so you get results.", "red")
        _run_nmap_cmd(["nmap", "-A", "-T5", "-Pn", "-p-", ip, "-oN", str(output_file)])
    else:
        ports_csv = ",".join(open_ports)
        log_info(f"[*] Enriching {ip} (ports: {ports_csv})...")
        enrich_cmd = [
            "nmap",
            "-n",
            "-T4",
            "-Pn",
            "-sV",
            "--version-light",
            "--script-timeout",
            "5s",
            "-p",
            ports_csv,
            ip,
            "-oN",
            str(output_file),
        ]
        _run_nmap_cmd(enrich_cmd)

    ports_dir = output_path / "ports"
    ports_dir.mkdir(exist_ok=True)
    environment = output_path.parent.parent.name

    nmap_line = re.compile(r"(\d+)/(tcp|udp)\s+open\s+([\w\-\._]+)(\s+(.*))?")

    if not output_file.exists():
        log_verbose(f"Warning: {output_file} not created", "yellow")
        return ip, output_file

    try:
        file_lines = output_file.read_text(errors="ignore").splitlines()
    except Exception as e:
        log_verbose(f"Warning: Could not read {output_file}: {e}", "yellow")
        return ip, output_file

    for line in file_lines:
        match = nmap_line.search(line)
        if not match:
            continue
        port = match.group(1)
        proto = match.group(2)
        service = sanitize_filename(match.group(3).lower())
        version_info = match.group(5) if match.group(5) else ""

        filename = f"{port}-{service}.txt"
        port_file_path = ports_dir / filename

        try:
            with port_file_path.open("w") as pf:
                pf.write(f"# Environment: {environment}\n")
                pf.write(f"# Host: {ip}\n")
                pf.write(f"# Port: {port}/{proto}\n")
                pf.write(f"# Service: {service}\n")
                if version_info:
                    pf.write(f"# Version: {version_info}\n")
                pf.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
                pf.write(line.strip() + "\n")
                pf.write("\n# === Suggested Next Steps ===\n")
                if service in ["http", "https"]:
                    pf.write("# - Run dirsearch or gobuster for content discovery\n")
                    pf.write("# - Scan with Nikto, Nuclei, or Wapiti for vulnerabilities\n")
                    pf.write("# - Loot: robots.txt, config files, login panels, backups\n")
                    pf.write("# - Try default creds or admin/admin on CMS\n")
                elif service == "ssh":
                    pf.write("# - Check for weak/default SSH credentials\n")
                    pf.write("# - Loot: ~/.ssh/id_rsa, authorized_keys, bash_history\n")
                    pf.write("# - Post-exploitation: SSH pivot or key reuse\n")
                elif service in ["smb", "microsoft-ds", "microsoft_ds"]:
                    pf.write("# - Enum with smbmap, enum4linux-ng, NetExec (nxc)\n")
                    pf.write("# - Loot: shares, SAM/NTDS.dit, SYSVOL, GPP passwords\n")
                    pf.write("# - Check for null sessions and guest access\n")
                elif service == "ftp":
                    pf.write("# - Check for anonymous login\n")
                    pf.write("# - Loot: upload directories, backup archives, creds.txt\n")
                    pf.write("# - Post-exploitation: file upload for persistence\n")
                elif service == "rdp":
                    pf.write("# - Confirm NLA status and CredSSP vulnerabilities\n")
                    pf.write("# - Brute force with Hydra or Crowbar (if permitted)\n")
                    pf.write("# - Loot: screenshots, clipboard access, session hijack\n")
                elif service == "mysql":
                    pf.write("# - Attempt login with root/root or no password\n")
                    pf.write("# - Loot: mysql.user table, sensitive schema dumps\n")
                    pf.write("# - Post-exploitation: data exfil or local file read\n")
                elif service == "telnet":
                    pf.write("# - WARNING: Telnet is plaintext and sniffable\n")
                    pf.write("# - Try common creds: admin:admin, root:root\n")
                    pf.write("# - Loot: configs, debug menus, motd banners\n")
                elif service == "winrm":
                    pf.write("# - Test with evil-winrm or NetExec (nxc)\n")
                    pf.write("# - Loot: PowerShell history, execution context\n")
                    pf.write("# - Post-exploitation: PS credential injection\n")
                elif service == "ldap":
                    pf.write("# - Use ldapsearch or nmap --script=ldap* for info leak\n")
                    pf.write("# - Loot: usernames, OU structure, domain policies\n")
                    pf.write("# - Check for anonymous binds or ASREPRoastable users\n")
                else:
                    pf.write("# - Investigate service manually or with nmap scripts\n")
                    pf.write("# - Loot: banners, misconfigurations, leaks\n")
                pf.write("# ============================\n")
        except Exception as e:
            log_verbose(f"Warning: Could not write port file {port_file_path}: {e}", "yellow")

    if run_hooks_fn is not None:
        run_hooks_fn(
            "post_scan",
            {
                "ip": ip,
                "scan_output": str(output_file),
                "os_type": detect_os(output_file),
                "ports_dir": str(ports_dir),
            },
        )

    return ip, output_file


# ═══════════════════════════════════════════════════════════════════
#  Host summary
# ═══════════════════════════════════════════════════════════════════


def summarize_hosts(env_name: str) -> None:
    """Summarize scan results for all hosts in an environment."""
    base_dir = Path(env_name).absolute()
    if not base_dir.exists():
        return

    host_rows: list[tuple[str, str, str]] = []
    try:
        for entry in sorted(base_dir.iterdir()):
            if not entry.is_dir() or "-" not in entry.name:
                continue
            nmap_dir = entry / "nmap"
            if not nmap_dir.is_dir():
                continue
            parts = entry.name.rsplit("-", 1)
            ip_part = parts[0]
            os_part = parts[1] if len(parts) > 1 else "Unknown"
            nmap_file = entry / "nmap" / "full_scan.txt"
            ports_list: list[str] = []
            if nmap_file.exists():
                try:
                    for line in nmap_file.read_text(errors="ignore").splitlines():
                        if "/tcp" in line and "open" in line:
                            line_parts = line.split()
                            if len(line_parts) >= 3:
                                ports_list.append(f"{line_parts[0]} {line_parts[2]}")
                except Exception as e:
                    log_verbose(f"Warning: Could not read {nmap_file}: {e}", "yellow")
            ports_display = ", ".join(ports_list) if ports_list else "No open ports"
            host_rows.append((ip_part, os_part, ports_display))
    except Exception as e:
        log_error(f"Error listing environment: {e}")

    if host_rows:
        table = Table(
            title="Host Summary",
            show_lines=True,
            border_style="blue",
            title_style="bold blue",
        )
        table.add_column("IP", style="bold white", min_width=15)
        table.add_column("OS", style="magenta", min_width=8)
        table.add_column("Open Ports", style="cyan")
        for ip_val, os_type, ports_str in host_rows:
            table.add_row(ip_val, os_type, ports_str)
        if not CONFIG["quiet"]:
            console.print(table)
    else:
        log_info("No scan results found to summarize.", "bold yellow")


# ═══════════════════════════════════════════════════════════════════
#  Shell history configuration
# ═══════════════════════════════════════════════════════════════════


def configure_shell_history(hist_file: Path) -> None:
    """Configure shell history logging for cross-platform support."""
    hist_file = Path(hist_file).absolute()

    if IS_WINDOWS:
        profile_path = (
            Path(os.environ.get("USERPROFILE", ""))
            / "Documents"
            / "WindowsPowerShell"
            / "Microsoft.PowerShell_profile.ps1"
        )
        profile_path.parent.mkdir(parents=True, exist_ok=True)

        if profile_path.exists():
            content = profile_path.read_text(errors="ignore")
            if str(hist_file) in content:
                log_verbose(f"PowerShell profile already configured for {hist_file}", "yellow")
                return

        config = f'''
# Empusa Command Logging
$EmpusaHistoryFile = "{hist_file}"
Register-EngineEvent PowerShell.Exiting -Action {{
    Get-History | Export-Csv -Path $EmpusaHistoryFile -Append -NoTypeInformation
}}
'''
        if CONFIG["dry_run"]:
            log_info(f"[DRY RUN] Would configure PowerShell profile: {profile_path}", "yellow")
            return

        try:
            with profile_path.open("a", encoding="utf-8") as f:
                f.write(config)
            log_success(f"[+] PowerShell profile configured: {profile_path}")
            log_info("Restart PowerShell or run: . $PROFILE", "yellow")
        except Exception as e:
            log_error(f"Error configuring PowerShell profile: {e}")
            log_info("You can manually log commands to the file.", "yellow")

    elif IS_UNIX:
        shell = os.environ.get("SHELL", "/bin/bash")
        if "bash" in shell:
            rc_file = Path.home() / ".bashrc"
            config = f'''
# Empusa Command Logging
export HISTFILE="{hist_file}"
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%F %T "
shopt -s histappend
PROMPT_COMMAND="history -a; ${{PROMPT_COMMAND}}"
'''
        elif "zsh" in shell:
            rc_file = Path.home() / ".zshrc"
            config = f'''
# Empusa Command Logging
export HISTFILE="{hist_file}"
export HISTSIZE=10000
export SAVEHIST=20000
export HISTTIMEFORMAT="%F %T "
setopt EXTENDED_HISTORY
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY
'''
        else:
            log_verbose(f"Unsupported shell: {shell}. Command logging may not work.", "yellow")
            return

        if rc_file.exists():
            content = rc_file.read_text(errors="ignore")
            if str(hist_file) in content:
                log_verbose(f"Shell RC file already configured for {hist_file}", "yellow")
                return

        if CONFIG["dry_run"]:
            log_info(f"[DRY RUN] Would configure shell logging in {rc_file}", "yellow")
            return

        try:
            with rc_file.open("a") as f:
                f.write(config)
            log_success(f"[+] Shell logging hook written to {rc_file}")
            log_info(f"Please run: source {rc_file}", "yellow")
        except Exception as e:
            log_error(f"Error configuring shell: {e}")
    else:
        log_verbose("Unknown platform. Command logging not configured.", "yellow")


# ═══════════════════════════════════════════════════════════════════
#  Environment build
# ═══════════════════════════════════════════════════════════════════


def build_env(
    env_name: str,
    ips: list[str],
    *,
    run_hooks_fn: Callable[..., Any] | None = None,
) -> None:
    """Build penetration testing environment with scanning and file structure."""
    valid_ips: list[str] = []
    for ip in ips:
        if validate_ip(ip):
            valid_ips.append(ip)
        else:
            log_error(f"Invalid IP address: {ip} - skipping")

    if not valid_ips:
        log_error("No valid IP addresses provided. Aborting.")
        return

    if not check_tool_exists("nmap"):
        log_error("Error: nmap not found. Please install nmap first.")
        return

    if CONFIG["dry_run"]:
        log_info(f"[DRY RUN] Would build environment '{env_name}' for IPs: {', '.join(valid_ips)}", "yellow")
        return

    base_dir = Path(env_name).absolute()

    if base_dir.exists() and any(base_dir.iterdir()):
        if CONFIG["dry_run"]:
            log_info(f"[DRY RUN] Environment '{env_name}' already exists", "yellow")
        elif not Confirm.ask(f"[yellow]Environment '{env_name}' already exists. Continue?[/yellow]"):
            return

    base_dir.mkdir(parents=True, exist_ok=True)

    users_file = base_dir / f"{env_name}-users.txt"
    passwords_file = base_dir / f"{env_name}-passwords.txt"
    commands_log_file = base_dir / "commands_ran.txt"

    users_file.touch()
    passwords_file.touch()
    commands_log_file.touch()

    # Shell history logging is opt-in to avoid mutating the operator's
    # shell profile (especially important in CI / containers).
    if Confirm.ask(
        "[yellow]Enable shell history logging for this env?[/yellow]",
        default=False,
    ):
        configure_shell_history(commands_log_file)

    ip_dirs: dict[str, Path] = {}
    for ip in valid_ips:
        temp_path = base_dir / ip
        nmap_path = temp_path / "nmap"
        nmap_path.mkdir(parents=True, exist_ok=True)
        ip_dirs[ip] = nmap_path

    if run_hooks_fn is not None:
        run_hooks_fn(
            "pre_build",
            {
                "env_name": env_name,
                "ips": valid_ips,
            },
        )

    log_info("\n[*] Starting threaded Nmap scanning...", "bold green")
    scan_results: dict[str, Path] = {}
    max_workers = min(CONFIG["max_workers"], len(valid_ips))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(run_nmap, ip, nmap_path, run_hooks_fn=run_hooks_fn): ip for ip, nmap_path in ip_dirs.items()
        }

        if not CONFIG["quiet"]:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {len(valid_ips)} hosts...", total=len(valid_ips))
                for future in as_completed(future_to_ip):
                    ip, scan_output = future.result()
                    scan_results[ip] = scan_output
                    progress.advance(task)
        else:
            for future in as_completed(future_to_ip):
                ip, scan_output = future.result()
                scan_results[ip] = scan_output

    for ip, scan_output in scan_results.items():
        os_type = detect_os(scan_output)
        old_path = base_dir / ip
        new_path = base_dir / f"{ip}-{os_type}"

        if new_path.exists():
            log_verbose(f"Warning: {new_path} already exists. Skipping rename.", "bold red")
        else:
            try:
                old_path.rename(new_path)
                log_success(f"[+] {ip} classified as {os_type} -> {new_path}")
            except Exception as e:
                log_error(f"Error renaming {old_path}: {e}")

    try:
        with commands_log_file.open("a") as f:
            f.write(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"Built environment '{env_name}' with IPs: {', '.join(valid_ips)}\n"
            )
    except Exception as e:
        log_verbose(f"Warning: Could not write to command log: {e}", "yellow")

    if run_hooks_fn is not None:
        run_hooks_fn(
            "post_build",
            {
                "env_name": env_name,
                "env_path": str(base_dir),
                "ips": valid_ips,
            },
        )
