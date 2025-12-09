import os
import subprocess
import argparse
import re
import platform
import ipaddress
import shutil
from typing import List, Tuple, Optional, Set
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import Counter
from datetime import datetime

# Global configuration
CONFIG = {
    'verbose': False,
    'quiet': False,
    'dry_run': False,
    'no_color': False,
    'max_workers': 8
}

console = Console()

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_UNIX = platform.system() in ["Linux", "Darwin"]


def log_verbose(message: str, style: str = "cyan") -> None:
    """Print message only in verbose mode."""
    if CONFIG['verbose'] and not CONFIG['quiet']:
        console.print(message, style=style)


def log_info(message: str, style: str = "cyan") -> None:
    """Print message unless in quiet mode."""
    if not CONFIG['quiet']:
        console.print(message, style=style)


def log_error(message: str) -> None:
    """Always print error messages."""
    console.print(message, style="bold red")


def log_success(message: str) -> None:
    """Print success message unless in quiet mode."""
    if not CONFIG['quiet']:
        console.print(message, style="green")


def check_tool_exists(tool_name: str) -> bool:
    """Check if a command-line tool exists on PATH."""
    return shutil.which(tool_name) is not None


def validate_ip(ip: str) -> bool:
    """Validate if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sanitize_filename(name: str) -> str:
    """Remove characters that are invalid in filenames."""
    return re.sub(r'[<>:"/\\|?*]', '_', name)


def print_banner() -> None:
    """Display the Empusa banner."""
    if CONFIG['quiet']:
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
     ██     ▀█▄        ▄█▀     ██   [italic red]Empusa — Devourer of Men, Feeder on Fear[/italic red]
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
[green]  Inspired by Empusa — vampire, demon, and sorceress of stealth[/green]
[yellow]  https://github.com/Icarus4122/empusa  |  v1.0.0[/yellow]
"""
    console.print(Panel.fit(banner, border_style="red"))

def detect_os(nmap_output: Path) -> str:
    """
    Detect OS from nmap output file.
    
    Args:
        nmap_output: Path to nmap output file
        
    Returns:
        "Windows", "Linux", or "Unknown"
    """
    nmap_path = Path(nmap_output)
    if not nmap_path.exists():
        log_verbose(f"Warning: {nmap_output} not found for OS detection", "yellow")
        return "Unknown"
    
    try:
        content = nmap_path.read_text(errors='ignore').lower()
        if "microsoft" in content or "windows" in content:
            return "Windows"
        elif any(x in content for x in ["linux", "unix", "ubuntu", "debian", "centos", "apache"]):
            return "Linux"
        else:
            return "Unknown"
    except Exception as e:
        log_verbose(f"Warning: Could not read {nmap_output}: {e}", "yellow")
        return "Unknown"

def search_exploits_from_nmap(nmap_file: Path) -> None:
    """
    Parse nmap results and search for exploits using searchsploit.
    
    Args:
        nmap_file: Path to nmap scan output
    """
    nmap_path = Path(nmap_file)
    if not nmap_path.exists():
        log_error(f"Nmap file not found: {nmap_file}")
        return
    
    if not check_tool_exists("searchsploit"):
        log_error("Error: searchsploit not found on PATH.")
        log_info("Install exploit-db or skip this step.", "yellow")
        return
    
    if CONFIG['dry_run']:
        log_info("[DRY RUN] Would search exploits from nmap results", "yellow")
        return
    
    log_info(f"[*] Parsing services from {nmap_file} and searching exploits...")
    
    try:
        lines = nmap_path.read_text(errors='ignore').splitlines()
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        return
    
    found_terms: Set[str] = set()
    # Fixed regex - removed double escaping in raw string
    service_regex = re.compile(r'(\d+)/(tcp|udp)\s+open\s+([\w\-]+)(\s+([\w\-\.]+))?')
    
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
            out.write(f"# Exploit Search Results\n")
            out.write(f"Generated: {datetime.now().isoformat()}\n\n")
            
            for term in sorted(found_terms):
                log_info(f"\n>> searchsploit {term}", "bold yellow")
                out.write(f"## Exploits for: {term}\n")
                try:
                    result = subprocess.run(
                        ["searchsploit", term], 
                        capture_output=True, 
                        text=True, 
                        check=False,
                        timeout=30
                    )
                    if not CONFIG['quiet']:
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

def run_nmap(ip: str, output_path: Path) -> Tuple[str, Path]:
    """
    Run nmap scan against target IP.
    
    Args:
        ip: Target IP address
        output_path: Directory to save results
        
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
    
    if CONFIG['dry_run']:
        log_info(f"[DRY RUN] Would scan {ip}", "yellow")
        return ip, output_file

    def _run_nmap(cmd: List[str]) -> subprocess.CompletedProcess:
        """Run nmap command with error handling."""
        try:
            return subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=600  # 10 minute timeout
            )
        except subprocess.TimeoutExpired:
            log_verbose(f"Warning: Nmap scan timed out for {ip}", "yellow")
            return subprocess.CompletedProcess(cmd, 1, b"", b"Timeout")
        except Exception as e:
            log_error(f"Error running nmap: {e}")
            return subprocess.CompletedProcess(cmd, 1, b"", str(e).encode())

    def _parse_greppable(path: Path) -> List[str]:
        """Parse greppable nmap output for open ports."""
        ports: Set[str] = set()
        rx = re.compile(r'(\d+)/open/(?:tcp|udp)', re.IGNORECASE)
        
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

    log_info(f"[*] Scanning (fast discovery) on {ip}...")

    disc_cmd = [
            "nmap", "-n", "-T4", "-Pn", "-A",
            ip, "-oG", str(greppable)
        ]
    _run_nmap(disc_cmd)
    open_ports = _parse_greppable(greppable)

    if not open_ports:
        log_verbose("No ports found, retrying discovery with higher retries…", "yellow")
        disc_cmd_retry = [
            "nmap", "-n", "-T5", "-Pn", "-p-",
            "--max-rtt-timeout", "1000ms",
            "-sS",
            ip, "-oG", str(greppable)
        ]
        _run_nmap(disc_cmd_retry)
        open_ports = _parse_greppable(greppable)

    if not open_ports:
        log_verbose("Discovery still empty. Falling back to -A (full) so you get results.", "red")
        _run_nmap(["nmap", "-A", "-T5", "-Pn", "-p-", ip, "-oN", str(output_file)])
    else:
        ports_csv = ",".join(open_ports)
        log_info(f"[*] Enriching {ip} (ports: {ports_csv})...")
        enrich_cmd = [
            "nmap", "-n", "-T4", "-Pn",
            "-sV", "--version-light",
            "--script-timeout", "5s",
            "-p", ports_csv,
            ip, "-oN", str(output_file)
        ]
        _run_nmap(enrich_cmd)

    ports_dir = output_path / "ports"
    ports_dir.mkdir(exist_ok=True)
    environment = output_path.parent.parent.name

    nmap_line = re.compile(r'(\d+)/(tcp|udp)\s+open\s+([\w\-\._]+)(\s+(.*))?')
    
    if not output_file.exists():
        log_verbose(f"Warning: {output_file} not created", "yellow")
        return ip, output_file
    
    try:
        lines = output_file.read_text(errors='ignore').splitlines()
    except Exception as e:
        log_verbose(f"Warning: Could not read {output_file}: {e}", "yellow")
        return ip, output_file
        
    for line in lines:
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
            with port_file_path.open('w') as pf:
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
                    pf.write("# - Enum with smbmap, enum4linux-ng, CrackMapExec\n")
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
                    pf.write("# - Test with evil-winrm or CrackMapExec\n")
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

    return ip, output_file

def summarize_hosts(env_name: str) -> None:
    """
    Summarize scan results for all hosts in an environment.
    
    Args:
        env_name: Name of the environment directory
    """
    base_dir = Path(env_name).absolute()
    if not base_dir.exists():
        log_error(f"Environment folder '{env_name}' does not exist.")
        return

    output_lines = []
    try:
        for entry in base_dir.iterdir():
            if entry.is_dir() and "-" in entry.name:
                nmap_file = entry / "nmap" / "full_scan.txt"
                if nmap_file.exists():
                    try:
                        ports = []
                        for line in nmap_file.read_text(errors='ignore').splitlines():
                            if "/tcp" in line and "open" in line:
                                parts = line.split()
                                if len(parts) >= 3:
                                    ports.append(f"{parts[0]}/{parts[2]}")
                        ports_display = ", ".join(ports) if ports else "No open ports"
                        output_lines.append(f"{entry.name}: {ports_display}")
                    except Exception as e:
                        log_verbose(f"Warning: Could not read {nmap_file}: {e}", "yellow")
    except Exception as e:
        log_error(f"Error listing environment: {e}")

    if output_lines:
        log_info("== Host Summary ==", "bold blue")
        if not CONFIG['quiet']:
            console.print("```", highlight=False)
            for line in output_lines:
                console.print(line, highlight=False)
            console.print("```", highlight=False)
    else:
        log_info("No scan results found to summarize.", "bold yellow")

def configure_shell_history(hist_file: Path) -> None:
    """
    Configure shell history logging for cross-platform support.
    
    Args:
        hist_file: Path to the history file
    """
    hist_file = Path(hist_file).absolute()
    
    if IS_WINDOWS:
        # Windows PowerShell configuration
        profile_path = Path(os.environ.get("USERPROFILE", "")) / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if already configured
        if profile_path.exists():
            content = profile_path.read_text(errors='ignore')
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
        if CONFIG['dry_run']:
            log_info(f"[DRY RUN] Would configure PowerShell profile: {profile_path}", "yellow")
            return
        
        try:
            with profile_path.open("a", encoding='utf-8') as f:
                f.write(config)
            log_success(f"[+] PowerShell profile configured: {profile_path}")
            log_info("Restart PowerShell or run: . $PROFILE", "yellow")
        except Exception as e:
            log_error(f"Error configuring PowerShell profile: {e}")
            log_info("You can manually log commands to the file.", "yellow")
    
    elif IS_UNIX:
        # Unix shell configuration
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
        
        # Check if already configured
        if rc_file.exists():
            content = rc_file.read_text(errors='ignore')
            if str(hist_file) in content:
                log_verbose(f"Shell RC file already configured for {hist_file}", "yellow")
                return
        
        if CONFIG['dry_run']:
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

def build_env(env_name: str, ips: List[str]) -> None:
    """
    Build penetration testing environment with scanning and file structure.
    
    Args:
        env_name: Name of the environment
        ips: List of IP addresses to scan
    """
    # Validate IPs
    valid_ips = []
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
    
    if CONFIG['dry_run']:
        log_info(f"[DRY RUN] Would build environment '{env_name}' for IPs: {', '.join(valid_ips)}", "yellow")
        return
    
    base_dir = Path(env_name).absolute()
    
    # Check if environment already exists
    if base_dir.exists() and any(base_dir.iterdir()):
        if CONFIG['dry_run']:
            log_info(f"[DRY RUN] Environment '{env_name}' already exists", "yellow")
        elif not Confirm.ask(f"[yellow]Environment '{env_name}' already exists. Continue?[/yellow]"):
            return
    
    base_dir.mkdir(parents=True, exist_ok=True)

    users_file = base_dir / f"{env_name}-users.txt"
    passwords_file = base_dir / f"{env_name}-passwords.txt"
    commands_log_file = base_dir / "commands_ran.txt"

    # Create files
    users_file.touch()
    passwords_file.touch()
    commands_log_file.touch()

    # Configure shell history
    configure_shell_history(commands_log_file)

    ip_dirs = {}

    for ip in valid_ips:
        temp_path = base_dir / ip
        nmap_path = temp_path / "nmap"
        nmap_path.mkdir(parents=True, exist_ok=True)
        ip_dirs[ip] = nmap_path

    log_info("\n[*] Starting threaded Nmap scanning...", "bold green")
    scan_results = {}
    max_workers = min(CONFIG['max_workers'], len(valid_ips))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(run_nmap, ip, nmap_path): ip for ip, nmap_path in ip_dirs.items()}
        
        if not CONFIG['quiet']:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
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
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Built environment '{env_name}' with IPs: {', '.join(valid_ips)}\n")
    except Exception as e:
        log_verbose(f"Warning: Could not write to command log: {e}", "yellow")

def validate_port(port_str: str) -> bool:
    """Validate if string is a valid port number (1-65535)."""
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """Validate if string is a valid IP or hostname."""
    # Try as IP first
    if validate_ip(hostname):
        return True
    # Basic hostname validation
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', hostname):
        return True
    return False


def build_reverse_tunnel() -> None:
    """Interactive builder for reverse tunnels and port forwarding with multiple tools."""
    log_info("\n== Reverse Tunnel & Port Forward Builder ==", "bold cyan")
    log_info("\n[bold]Choose Tunnel Type:[/]")
    log_info("1. Chisel (SOCKS5 proxy)")
    log_info("2. SSH Reverse Tunnel (-R)")
    log_info("3. SSH Local Tunnel (-L)")
    log_info("4. SSH Dynamic SOCKS (-D)")
    log_info("5. Ligolo-ng")
    log_info("6. Socat Port Forward")
    log_info("7. Netsh PortProxy (Windows)")
    log_info("8. Metasploit Autoroute")
    log_info("0. Back to Main Menu")

    choice = Prompt.ask("Select an option", choices=['0', '1', '2', '3', '4', '5', '6', '7', '8'])
    
    if choice == '0':
        return
    
    commands = []
    tunnel_name = ""
    save_file = None

    if choice == '1':
        # Chisel SOCKS5
        tunnel_name = "Chisel"
        log_info("\n[bold yellow]Chisel SOCKS5 Proxy Setup[/bold yellow]")
        
        attacker_ip = Prompt.ask("Enter your attacking machine IP/hostname")
        if not validate_hostname(attacker_ip):
            log_error("Invalid IP/hostname")
            return
        
        chisel_port = Prompt.ask("Enter Chisel listener port", default="8080")
        if not validate_port(chisel_port):
            log_error("Invalid port number")
            return
        
        socks_port = Prompt.ask("Enter SOCKS proxy port", default="1080")
        if not validate_port(socks_port):
            log_error("Invalid port number")
            return
        
        commands = [
            ("Attacker", f"./chisel server -p {chisel_port} --socks5 --reverse"),
            ("Target", f"./chisel client {attacker_ip}:{chisel_port} R:{socks_port}:socks"),
            ("Configure Proxy", f"# Set browser/tools to use SOCKS5 proxy: localhost:{socks_port}"),
            ("ProxyChains", f"# Add to /etc/proxychains.conf: socks5 127.0.0.1 {socks_port}")
        ]

    elif choice == '2':
        # SSH Reverse Tunnel
        tunnel_name = "SSH_Reverse"
        log_info("\n[bold yellow]SSH Reverse Tunnel (-R)[/bold yellow]")
        log_info("Expose a target port on your attacker machine")
        
        attacker_user = Prompt.ask("Enter your username on attacker machine")
        attacker_host = Prompt.ask("Enter your attacker IP/hostname")
        if not validate_hostname(attacker_host):
            log_error("Invalid IP/hostname")
            return
        
        remote_port = Prompt.ask("Enter port to open on attacker machine", default="8888")
        if not validate_port(remote_port):
            log_error("Invalid port number")
            return
        
        local_port = Prompt.ask("Enter target port to expose", default="80")
        if not validate_port(local_port):
            log_error("Invalid port number")
            return
        
        target_host = Prompt.ask("Enter target host", default="127.0.0.1")
        
        commands = [
            ("Target", f"ssh -R {remote_port}:{target_host}:{local_port} {attacker_user}@{attacker_host} -N -f"),
            ("Alternative (no background)", f"ssh -R {remote_port}:{target_host}:{local_port} {attacker_user}@{attacker_host}"),
            ("Access", f"# Connect to localhost:{remote_port} on attacker machine"),
            ("Keep Alive", f"ssh -R {remote_port}:{target_host}:{local_port} {attacker_user}@{attacker_host} -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3")
        ]

    elif choice == '3':
        # SSH Local Tunnel
        tunnel_name = "SSH_Local"
        log_info("\n[bold yellow]SSH Local Tunnel (-L)[/bold yellow]")
        log_info("Access a remote service through SSH tunnel")
        
        attacker_user = Prompt.ask("Enter your username on pivot/SSH server")
        pivot_host = Prompt.ask("Enter pivot/SSH server IP/hostname")
        if not validate_hostname(pivot_host):
            log_error("Invalid IP/hostname")
            return
        
        local_port = Prompt.ask("Enter local port on your machine", default="8080")
        if not validate_port(local_port):
            log_error("Invalid port number")
            return
        
        target_host = Prompt.ask("Enter target host (from pivot's perspective)", default="127.0.0.1")
        target_port = Prompt.ask("Enter target port", default="80")
        if not validate_port(target_port):
            log_error("Invalid port number")
            return
        
        commands = [
            ("Attacker", f"ssh -L {local_port}:{target_host}:{target_port} {attacker_user}@{pivot_host} -N -f"),
            ("Alternative (no background)", f"ssh -L {local_port}:{target_host}:{target_port} {attacker_user}@{pivot_host}"),
            ("Access", f"# Connect to localhost:{local_port} on your machine"),
            ("Multiple Ports", f"ssh -L {local_port}:{target_host}:{target_port} -L 8081:target2:443 {attacker_user}@{pivot_host} -N")
        ]

    elif choice == '4':
        # SSH Dynamic SOCKS
        tunnel_name = "SSH_SOCKS"
        log_info("\n[bold yellow]SSH Dynamic SOCKS Proxy (-D)[/bold yellow]")
        log_info("Create a SOCKS proxy through SSH")
        
        attacker_user = Prompt.ask("Enter your username on pivot/SSH server")
        pivot_host = Prompt.ask("Enter pivot/SSH server IP/hostname")
        if not validate_hostname(pivot_host):
            log_error("Invalid IP/hostname")
            return
        
        socks_port = Prompt.ask("Enter SOCKS proxy port on your machine", default="1080")
        if not validate_port(socks_port):
            log_error("Invalid port number")
            return
        
        commands = [
            ("Attacker", f"ssh -D {socks_port} {attacker_user}@{pivot_host} -N -f"),
            ("Alternative (no background)", f"ssh -D {socks_port} {attacker_user}@{pivot_host}"),
            ("Configure Proxy", f"# Set browser/tools to use SOCKS5 proxy: localhost:{socks_port}"),
            ("ProxyChains", f"# Add to /etc/proxychains.conf: socks5 127.0.0.1 {socks_port}"),
            ("Usage Example", f"proxychains nmap -sT -Pn 10.10.10.0/24")
        ]

    elif choice == '5':
        # Ligolo-ng
        tunnel_name = "Ligolo"
        log_info("\n[bold yellow]Ligolo-ng Setup[/bold yellow]")
        log_info("Modern tunneling with TUN interface")
        
        attacker_ip = Prompt.ask("Enter your attacking machine IP")
        if not validate_hostname(attacker_ip):
            log_error("Invalid IP/hostname")
            return
        
        ligolo_port = Prompt.ask("Enter Ligolo listener port", default="11601")
        if not validate_port(ligolo_port):
            log_error("Invalid port number")
            return
        
        tunnel_ip = Prompt.ask("Enter tunnel network (e.g., 240.0.0.1/24)", default="240.0.0.1/24")
        
        commands = [
            ("Attacker - Setup Interface", f"sudo ip tuntap add user $(whoami) mode tun ligolo"),
            ("Attacker - Bring Up", f"sudo ip link set ligolo up"),
            ("Attacker - Start Proxy", f"./proxy -selfcert -laddr 0.0.0.0:{ligolo_port}"),
            ("Target", f"./agent -connect {attacker_ip}:{ligolo_port} -ignore-cert"),
            ("In Ligolo Console", f"session # Select session"),
            ("In Ligolo Console", f"ifconfig # View target networks"),
            ("Attacker - Add Route", f"sudo ip route add {tunnel_ip} dev ligolo"),
            ("In Ligolo Console", f"start # Start tunnel")
        ]

    elif choice == '6':
        # Socat
        tunnel_name = "Socat"
        log_info("\n[bold yellow]Socat Port Forward[/bold yellow]")
        
        listen_port = Prompt.ask("Enter port to listen on", default="8080")
        if not validate_port(listen_port):
            log_error("Invalid port number")
            return
        
        target_host = Prompt.ask("Enter target host to forward to")
        if not validate_hostname(target_host):
            log_error("Invalid IP/hostname")
            return
        
        target_port = Prompt.ask("Enter target port", default="80")
        if not validate_port(target_port):
            log_error("Invalid port number")
            return
        
        commands = [
            ("Basic Forward", f"socat TCP-LISTEN:{listen_port},fork TCP:{target_host}:{target_port}"),
            ("Background", f"socat TCP-LISTEN:{listen_port},fork TCP:{target_host}:{target_port} &"),
            ("With Reuseaddr", f"socat TCP-LISTEN:{listen_port},fork,reuseaddr TCP:{target_host}:{target_port}"),
            ("Reverse Shell Relay", f"socat TCP-LISTEN:{listen_port} TCP:{target_host}:{target_port}"),
            ("Usage", f"# Connect to localhost:{listen_port} to reach {target_host}:{target_port}")
        ]

    elif choice == '7':
        # Windows Netsh
        tunnel_name = "Netsh"
        log_info("\n[bold yellow]Windows Netsh PortProxy[/bold yellow]")
        log_info("Native Windows port forwarding (requires admin)")
        
        listen_port = Prompt.ask("Enter port to listen on", default="8080")
        if not validate_port(listen_port):
            log_error("Invalid port number")
            return
        
        target_host = Prompt.ask("Enter target host to forward to")
        target_port = Prompt.ask("Enter target port", default="80")
        if not validate_port(target_port):
            log_error("Invalid port number")
            return
        
        listen_addr = Prompt.ask("Enter listen address", default="0.0.0.0")
        
        commands = [
            ("Add Port Forward", f"netsh interface portproxy add v4tov4 listenaddress={listen_addr} listenport={listen_port} connectaddress={target_host} connectport={target_port}"),
            ("List Forwards", f"netsh interface portproxy show all"),
            ("Delete Forward", f"netsh interface portproxy delete v4tov4 listenaddress={listen_addr} listenport={listen_port}"),
            ("Reset All", f"netsh interface portproxy reset"),
            ("Firewall Rule", f"netsh advfirewall firewall add rule name=\"Port Forward {listen_port}\" protocol=TCP dir=in localport={listen_port} action=allow"),
            ("Note", "# Requires Administrator privileges")
        ]

    elif choice == '8':
        # Metasploit Autoroute
        tunnel_name = "Metasploit"
        log_info("\n[bold yellow]Metasploit Autoroute & Port Forward[/bold yellow]")
        
        session_id = Prompt.ask("Enter Meterpreter session ID", default="1")
        target_subnet = Prompt.ask("Enter target subnet to route (e.g., 10.10.10.0/24)")
        local_port = Prompt.ask("Enter local port for port forward", default="8080")
        if not validate_port(local_port):
            log_error("Invalid port number")
            return
        
        target_host = Prompt.ask("Enter target host for port forward (optional)", default="")
        target_port = Prompt.ask("Enter target port for port forward (optional)", default="")
        
        commands = [
            ("Autoroute", f"use post/multi/manage/autoroute"),
            ("Set Session", f"set SESSION {session_id}"),
            ("Set Subnet", f"set SUBNET {target_subnet}"),
            ("Run", f"run"),
            ("Verify Routes", f"route print"),
            ("SOCKS Proxy", f"use auxiliary/server/socks_proxy"),
            ("Set Version", f"set SRVPORT 1080"),
            ("Run Proxy", f"run -j"),
        ]
        
        if target_host and target_port:
            commands.extend([
                ("Port Forward", f"portfwd add -l {local_port} -p {target_port} -r {target_host}"),
                ("List Forwards", f"portfwd list"),
                ("Delete Forward", f"portfwd delete -l {local_port}"),
            ])

    # Display commands
    log_info(f"\n[bold green]=== {tunnel_name} Commands ===[/bold green]")
    for label, cmd in commands:
        log_info(f"\n[cyan]{label}:[/cyan]")
        if not CONFIG['quiet']:
            console.print(f"  {cmd}", style="bold white")
    
    # Save to file
    if Confirm.ask("\n[yellow]Save these commands to a file?[/yellow]"):
        env_name = Prompt.ask("Enter environment/host name (for filename)", default="tunnel")
        safe_name = sanitize_filename(env_name)
        save_file = Path.cwd() / f"{safe_name}-{tunnel_name.lower()}-commands.txt"
        
        if save_file.exists() and not CONFIG['dry_run']:
            if not Confirm.ask(f"[yellow]File {save_file} exists. Overwrite?[/yellow]"):
                log_info("Not saving commands.", "yellow")
                return
        
        if CONFIG['dry_run']:
            log_info(f"[DRY RUN] Would save commands to {save_file}", "yellow")
            return
        
        try:
            with save_file.open('w') as f:
                f.write(f"# {tunnel_name} Tunnel Commands\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Environment: {env_name}\n\n")
                
                for label, cmd in commands:
                    f.write(f"# {label}\n")
                    f.write(f"{cmd}\n\n")
            
            log_success(f"Commands saved to: {save_file}")
        except Exception as e:
            log_error(f"Error saving commands: {e}")

def find_password_files(domain: str, search_path: Path = None) -> List[Path]:
    """
    Search for password files matching the domain name.
    
    Args:
        domain: Domain/environment name to search for
        search_path: Root path to search from (defaults to current directory)
        
    Returns:
        List of matching password file paths
    """
    if search_path is None:
        search_path = Path.cwd()
    
    target_filename = f"{domain}-passwords.txt"
    matches = []
    
    log_verbose(f"Searching for {target_filename} in {search_path}...")
    
    try:
        for path in search_path.rglob(target_filename):
            if path.is_file():
                matches.append(path)
                log_verbose(f"Found: {path}", "green")
    except Exception as e:
        log_verbose(f"Warning during search: {e}", "yellow")
    
    return matches


def generate_hashcat_rules() -> None:
    """Generate hashcat rules from password patterns in environment password file."""
    log_info("\n== Hashcat Rule Generator ==", "bold cyan")

    domain = Prompt.ask("Enter domain/environment name (used in filename)").strip().rstrip('/')
    
    # Search in current directory and subdirectories
    matches = find_password_files(domain)
    
    # If not found locally, ask for custom search path
    if not matches:
        log_info(f"No {domain}-passwords.txt found in current directory.", "yellow")
        if Confirm.ask("Search in a different directory?"):
            custom_path = Prompt.ask("Enter directory path to search")
            try:
                matches = find_password_files(domain, Path(custom_path))
            except Exception as e:
                log_error(f"Error searching custom path: {e}")
                return
    
    if not matches:
        log_error(f"No {domain}-passwords.txt file found.")
        return

    if len(matches) == 1:
        pw_file = matches[0]
    else:
        log_info("Multiple password files found:", "bold yellow")
        for i, path in enumerate(matches):
            log_info(f"{i + 1}. {path}")
        try:
            index = int(Prompt.ask("Select the file to use", choices=[str(i + 1) for i in range(len(matches))])) - 1
            pw_file = matches[index]
        except (ValueError, IndexError):
            log_error("Invalid selection.")
            return

    pw_file = Path(pw_file)
    rule_file = pw_file.parent / "hashcat_generated.rule"
    
    # Check if rule file exists and warn user
    if rule_file.exists() and not CONFIG['dry_run']:
        if not Confirm.ask(f"[yellow]Rule file {rule_file} already exists. Overwrite?[/yellow]"):
            log_info("Operation cancelled.", "yellow")
            return
    
    if CONFIG['dry_run']:
        log_info(f"[DRY RUN] Would generate hashcat rules from {pw_file}", "yellow")
        return

    try:
        passwords = [line.strip() for line in pw_file.read_text(errors='ignore').splitlines() if line.strip()]
    except Exception as e:
        log_error(f"Error reading password file: {e}")
        return

    # Analyze password patterns
    rules_list = []
    pattern_stats = {
        'lowercase': 0,
        'uppercase': 0,
        'capitalize': 0,
        'reverse': 0,
        'digit_append': Counter(),
        'symbol_append': Counter(),
        'digit_prepend': Counter(),
        'symbol_prepend': Counter(),
        'years': Counter(),
        'lengths': Counter(),
        'leetspeak': 0,
        'duplicates': 0
    }
    
    password_set = set(passwords)
    
    for pw in passwords:
        if not pw:
            continue
            
        pattern_stats['lengths'][len(pw)] += 1
        
        # Case transformations
        if pw.islower():
            pattern_stats['lowercase'] += 1
        elif pw.isupper():
            pattern_stats['uppercase'] += 1
            rules_list.append('u')  # uppercase all
        elif pw[0].isupper() and pw[1:].islower():
            pattern_stats['capitalize'] += 1
            rules_list.append('c')  # capitalize first letter
        
        # Reverse
        if pw[::-1] in password_set and pw[::-1] != pw:
            pattern_stats['reverse'] += 1
            rules_list.append('r')  # reverse
        
        # Digit patterns at end
        if len(pw) > 1 and pw[-1].isdigit():
            pattern_stats['digit_append'][pw[-1]] += 1
            rules_list.append(f'${pw[-1]}')  # append digit
            
            # Check for multiple trailing digits
            if len(pw) > 2 and pw[-2:].isdigit():
                for char in pw[-2:]:
                    rules_list.append(f'${char}')
        
        # Digit patterns at start
        if len(pw) > 1 and pw[0].isdigit():
            pattern_stats['digit_prepend'][pw[0]] += 1
            rules_list.append(f'^{pw[0]}')  # prepend digit
        
        # Symbol patterns at end
        if len(pw) > 1 and pw[-1] in "!@#$%^&*()_+-=[]{}|;:,.<>?":
            pattern_stats['symbol_append'][pw[-1]] += 1
            rules_list.append(f'${pw[-1]}')  # append symbol
        
        # Symbol patterns at start
        if len(pw) > 1 and pw[0] in "!@#$%^&*()_+-=[]{}|;:,.<>?":
            pattern_stats['symbol_prepend'][pw[0]] += 1
            rules_list.append(f'^{pw[0]}')  # prepend symbol
        
        # Year detection (1900-2099)
        year_matches = re.findall(r'(19\d{2}|20\d{2})', pw)
        for year in year_matches:
            pattern_stats['years'][year] += 1
            # Add rules to append the year
            for digit in year:
                rules_list.append(f'${digit}')
        
        # Leetspeak detection
        leet_chars = {'@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '5': 's', '7': 't'}
        if any(char in leet_chars for char in pw):
            pattern_stats['leetspeak'] += 1
            for leet, normal in leet_chars.items():
                if leet in pw:
                    rules_list.append(f's{normal}{leet}')  # substitute
        
        # Duplicate detection
        if re.search(r'(.)\1{1,}', pw):
            pattern_stats['duplicates'] += 1
            rules_list.append('d')  # duplicate all characters
    
    # Generate common combination rules
    common_combos = [
        'c $1',           # Capitalize + append 1
        'c $!',           # Capitalize + append !
        'c $1 $2',        # Capitalize + append 12
        'c $2 $0',        # Capitalize + append 20
        'c $1 $9',        # Capitalize + append 19
        'u $1',           # Uppercase + append 1
        'u $!',           # Uppercase + append !
        '$1 $2 $3',       # Append 123
        '$! $@ $#',       # Append !@#
        'c d',            # Capitalize + duplicate
        'c r',            # Capitalize + reverse
    ]
    
    # Add year-based rules for common years found
    if pattern_stats['years']:
        most_common_year = pattern_stats['years'].most_common(1)[0][0]
        for digit in most_common_year:
            common_combos.append(f'c ${digit}')
    
    # Count rule frequency
    rule_counter = Counter(rules_list)
    
    # Get most common individual rules (top 20)
    top_individual_rules = [rule for rule, _ in rule_counter.most_common(20)]
    
    # Combine individual rules and combo rules
    all_rules = top_individual_rules + common_combos
    
    # Remove duplicates while preserving order
    unique_rules = []
    seen = set()
    for rule in all_rules:
        if rule not in seen:
            unique_rules.append(rule)
            seen.add(rule)
    
    # Write rules to file
    try:
        with rule_file.open('w') as rf:
            rf.write("# Hashcat rules generated by Empusa\n")
            rf.write(f"# Generated from {len(passwords)} passwords\n")
            rf.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
            
            for rule in unique_rules:
                rf.write(rule + "\n")
        
        # Display statistics
        log_info("\nPassword Pattern Analysis:", "bold cyan")
        log_info(f"  Total passwords analyzed: {len(passwords)}")
        log_info(f"  Lowercase: {pattern_stats['lowercase']}")
        log_info(f"  Uppercase: {pattern_stats['uppercase']}")
        log_info(f"  Capitalized: {pattern_stats['capitalize']}")
        log_info(f"  Contains leetspeak: {pattern_stats['leetspeak']}")
        log_info(f"  Has duplicates: {pattern_stats['duplicates']}")
        log_info(f"  Reverse pairs found: {pattern_stats['reverse']}")
        
        if pattern_stats['digit_append']:
            top_digits = pattern_stats['digit_append'].most_common(3)
            log_info(f"  Common trailing digits: {', '.join([d for d, _ in top_digits])}")
        
        if pattern_stats['symbol_append']:
            top_symbols = pattern_stats['symbol_append'].most_common(3)
            log_info(f"  Common trailing symbols: {', '.join([s for s, _ in top_symbols])}")
        
        if pattern_stats['years']:
            top_years = pattern_stats['years'].most_common(3)
            log_info(f"  Common years: {', '.join([y for y, _ in top_years])}")
        
        common_lengths = pattern_stats['lengths'].most_common(3)
        log_info(f"  Common lengths: {', '.join([str(l) for l, _ in common_lengths])}")
        
        log_success(f"\n[+] {len(unique_rules)} hashcat rules generated")
        log_success(f"Saved rules to: {rule_file}")
        log_info(f"\nUsage: hashcat -a 0 -m <mode> <hashfile> <wordlist> -r {rule_file}", "yellow")
    except Exception as e:
        log_error(f"Error writing rule file: {e}")


def summarize_command() -> None:
    """Display the main menu options."""
    log_info("==== Environment Automation Tool ====", "bold blue")
    log_info("1. Build New Environment")
    log_info("2. Build Reverse Tunnel")
    log_info("3. Generate Hashcat Rules")
    log_info("4. Search Exploits from Nmap Results")
    log_info("0. Exit")


def main_menu() -> None:
    """Run the interactive main menu loop."""
    print_banner()
    while True:
        summarize_hosts(".")
        console.print("")
        summarize_command()
        choice = Prompt.ask("Select an option")

        if choice == '1':
            env_name = Prompt.ask("Enter environment name")
            ip_input = Prompt.ask("Enter IPs (comma-separated)")
            ips = [ip.strip() for ip in ip_input.split(',') if ip.strip()]
            build_env(env_name, ips)
        elif choice == '2':
            build_reverse_tunnel()
        elif choice == '3':
            generate_hashcat_rules()
        elif choice == '4':
            env_name = Prompt.ask("Enter environment name")
            ip_target = Prompt.ask("Enter target IP or folder format (e.g., 10.10.10.10-Windows)")
            nmap_path = Path(env_name) / ip_target / "nmap" / "full_scan.txt"
            search_exploits_from_nmap(nmap_path)
        elif choice == '0':
            log_info("Exiting.", "bold yellow")
            break
        else:
            log_error("Invalid choice. Try again.")


def main() -> None:
    """Main entry point for the Empusa CLI."""
    from empusa import __version__
    
    parser = argparse.ArgumentParser(
        prog="empusa", 
        description="Empusa – Shape-shifting Recon & Exploitation Automation Framework",
        epilog="Use responsibly and only with explicit authorization."
    )
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (detailed logging)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-essential output"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Maximum number of concurrent scan workers (default: 8)"
    )
    
    args = parser.parse_args()
    
    # Update global configuration
    CONFIG['verbose'] = args.verbose
    CONFIG['quiet'] = args.quiet
    CONFIG['dry_run'] = args.dry_run
    CONFIG['no_color'] = args.no_color
    CONFIG['max_workers'] = max(1, args.workers)
    
    # Configure console based on settings
    global console
    if args.no_color:
        console = Console(no_color=True, force_terminal=False)
    
    if args.verbose and args.quiet:
        log_error("Cannot use --verbose and --quiet together")
        return
    
    if args.dry_run:
        log_info("[DRY RUN MODE] No changes will be made", "bold yellow")
    
    main_menu()

if __name__ == '__main__':
    main()