# Empusa

**Shape-shifting Recon & Exploitation Framework**
Inspired by Empusa - vampire, demon, and sorceress of stealth.

> *"She shifts form… beauty, beast, and death."*

## Features

### Core Toolkit

- **Environment Builder** - Creates per-target folders, runs threaded `nmap` scans, auto-classifies hosts by OS, and writes per-port notes with next-step guidance.
- **Reverse Tunnel Builder** - Interactive wizard for 8 tunneling methods: Chisel, SSH (-R, -L, -D), Ligolo-ng, Socat, Netsh PortProxy, and Metasploit Autoroute.
- **Hashcat Rule Generator** - Analyzes observed password patterns (leetspeak, years, trailing digits, symbols) and emits a compact `.rule` file.
- **Exploit Discovery** - Parses services from nmap output and runs `searchsploit`, saving a markdown report.
- **Loot Tracker** - Interactive credential/hash/flag manager with JSON storage, rich tables, credential reuse detection, cross-host spray suggestions, environment file sync, and markdown export.
- **Report Builder** - Generates a full  penetration test report in Markdown, auto-populated from scan data and loot entries.
- **Module Workshop** - Compile, create, and manage shellcode modules (C, ASM, Nim, Go, Python). Detects available compilers, shows metadata, and batch-compiles the entire modules directory.
- **Privesc Enumeration Generator** - Windows and Linux privilege escalation command generator covering 50+ techniques: SUID/GUID, sudo misconfigs, writable paths, scheduled tasks, token impersonation, service exploits, and more.
- **Hash Identifier + Crack Builder** - Identifies hash type from 27 built-in signatures (MD5, NTLM, SHA-family, bcrypt, Kerberos, etc.) and builds a ready-to-run hashcat command.
- **AD Enumeration Playbook** - Structured Active Directory enumeration guide: BloodHound, PowerView, ldapsearch, impacket (GetNPUsers, GetUserSPNs, secretsdump), and SMB enumeration.

### Session Management

- **Environment Detection** - Auto-discovers previous builds on startup and displays them in a selectable table.
- **Session Persistence** - Remembers your active environment across menu actions.
- **Screen Clearing** - Clean transitions between every menu action.

### Hook / Plugin System

- **Layer 2 — Hooks**: 7 lifecycle events: `on_startup`, `on_shutdown`, `post_build`, `post_scan`, `on_loot_add`, `on_report_generated`, `on_env_select`
- **Drop-in Python scripts** in `empusa/hooks/<event>/` with a `run(context)` function — no manifest required.
- **Layer 3 — Plugins**: Full plugin lifecycle with JSON manifests, declared permissions, dependency graphs, and `ScopedServices` capability gating.
- **Built-in manager** (menu option 8): list hooks, create examples, test-fire events, delete scripts; list/create/enable/disable/uninstall plugins; browse the capability registry.
- **Full context dicts** passed to every hook with event-specific data (IPs, paths, credentials, etc.)

### Graceful Shutdown

- **Process cleanup** - Terminates lingering `nmap`/`searchsploit` child processes with PID reporting.
- **Shell hook removal** - Strips Empusa command logging blocks from `.bashrc`/`.zshrc`/PowerShell profile.
- **Session execution flow** - ASCII art diagram showing every action taken during the session with timestamps.
- **Farewell panel** - Detailed shutdown summary with process/hook cleanup results.

## Installation

### Prerequisites

- **Python 3.9+**
- **External tools** (optional but recommended):
  - `nmap` - for network scanning
  - `searchsploit` (from exploit-db) - for exploit discovery

### Install with pipx (Recommended)

```bash
pipx install git+https://github.com/Icarus4122/empusa.git

# Or from local directory
pipx install .
```

### Install with pip

```bash
pip install git+https://github.com/Icarus4122/empusa.git

# Or from local directory
pip install .
```

### Development Install

```bash
git clone https://github.com/Icarus4122/empusa.git
cd empusa
pip install -e .
```

### Verify

```bash
empusa --version  # Should print 2.1.0
empusa --help
```

## Usage

```bash
empusa              # Launch interactive menu
empusa -v           # Verbose mode
empusa -q           # Quiet mode
empusa --dry-run    # Preview actions without executing
empusa --no-color   # Disable colored output
empusa -w 16        # Set max concurrent scan workers
```

### Main Menu

```
==== Environment Automation Tool ====
1. Build New Environment
2. Build Reverse Tunnel
3. Generate Hashcat Rules
4. Search Exploits from Nmap Results
5. Loot Tracker
6. Report Builder
7. Select / Switch Environment
8. Manage Hooks / Plugins
9. Module Workshop
10. Privesc Enumeration Generator
11. Hash Identifier + Crack Builder
12. AD Enumeration Playbook
0. Exit
```

## Output Layout

```text
<env>/
├-- <ip>-<OS>/
│   ├-- nmap/
│   │   ├-- full_scan.txt
│   │   ├-- ports_grep.txt
│   │   └-- ports/
│   │       ├-- 22-ssh.txt
│   │       ├-- 80-http.txt
│   │       └-- ...
├-- <env>-users.txt
├-- <env>-passwords.txt
├-- commands_ran.txt
├-- loot.json
├-- loot_report.md
└-- <assessment>_report.md
```

## Hooks / Plugins

Empusa auto-creates `empusa/hooks/` with event subdirectories on first launch.

### Creating a Hook

```python
# empusa/hooks/on_loot_add/notify.py
def run(context: dict) -> None:
    print(f"[Hook] New loot on {context['host']}: {context['username']}")
```

### Available Events

| Event | Fires When | Key Context |
|-------|-----------|-------------|
| `on_startup` | Empusa launches | `timestamp`, `session_env` |
| `on_shutdown` | Clean exit or Ctrl+C | `killed_pids`, `cleaned_hooks` |
| `post_build` | After environment build | `env_name`, `env_path`, `ips` |
| `post_scan` | After each host scan | `ip`, `scan_output`, `os_type` |
| `on_loot_add` | After loot entry saved | `host`, `username`, `secret`, `cred_type` |
| `on_report_generated` | After report written | `report_path`, `env_name` |
| `on_env_select` | Environment selected | `env_name` |

Use **menu option 8** to manage hooks interactively (list, create, test-fire, delete).

## Platform Support

| Feature | Linux/macOS | Windows |
|---------|:-----------:|:-------:|
| Nmap scanning | ✔ | ✔ |
| Shell history hooks | bash/zsh | PowerShell |
| Process cleanup | pkill | taskkill |
| File manager open | xdg-open | explorer |
| Tunnel commands | ✔ | ✔ |

## CLI Flags

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Detailed logging output |
| `-q`, `--quiet` | Suppress non-essential output |
| `--dry-run` | Preview actions without executing |
| `--no-color` | Disable colored output |
| `-w N`, `--workers N` | Max concurrent scan workers (default: 8) |
| `--version` | Show version |
| `--help` | Show help |

## Notes

- `nmap` must be installed and on `PATH` for scanning features
- `searchsploit` (exploit-db) must be installed for exploit discovery
- IP addresses are validated before scanning
- All file operations use cross-platform paths via `pathlib`
- Shell history hooks are automatically cleaned up on exit
- no automated exploitation
- **Use responsibly and only where you have explicit authorization**

## Development

```bash
make build    # Build distribution packages
make clean    # Remove build artifacts
python -m empusa  # Dev run
```

## License

[GPL-3.0-or-later](LICENSE)
