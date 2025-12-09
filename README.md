# Empusa

**Shape-shifting Recon & Exploitation Framework**  
Inspired by Empusa — vampire, demon, and sorceress of stealth.

## Features

- **Environment Builder** – creates per-target folders, runs full `nmap -A -p-`, and writes per-port notes with “next steps.”
- **Auto OS Classifier** – parses nmap output and renames host folders to `IP-<Windows|Linux|Unknown>`.
- **Exploit Discovery** – parses services from Nmap and runs `searchsploit` for quick leads, saving a markdown log.
- **Reverse Tunnel Helper** – interactive Chisel/SSH recipes to pivot quickly.
- **Hashcat Rule Generator** – mines observed password patterns to emit a compact `.rule` file.
- **Command History Hook** – appends a small snippet to your shell rc to log commands for reporting.

## Installation

### Prerequisites

- **Python 3.9+**
- **External tools** (optional but recommended):
  - `nmap` - for network scanning
  - `searchsploit` (from exploit-db) - for exploit discovery

### Install Methods

#### Option 1: pipx (Recommended - Isolated Environment)

```bash
# Install pipx if not already installed
pip install pipx
pipx ensurepath

# Install empusa
pipx install git+https://github.com/Icarus4122/empusa.git

# Or from local directory
pipx install .
```

#### Option 2: pip (System/User Install)

```bash
# Install from GitHub
pip install git+https://github.com/Icarus4122/empusa.git

# Or install from local directory
pip install .

# Or install in editable mode for development
pip install -e .
```

#### Option 3: Virtual Environment (Development)

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

### Verify Installation

```bash
empusa --version
empusa --help
```

### Uninstall

**With pipx:**

```bash
pipx uninstall empusa
```

**With pip:**

```bash
pip uninstall empusa
```

## Usage

Launch the interactive menu:

```bash
empusa
```

Or run as a Python module:

```bash
python -m empusa
```

### Main Menu

1. Build New Environment – `env/`, `users.txt`, `passwords.txt`, `commands_ran.txt`, run threaded Nmap, auto-classify.
2. Build Reverse Tunnel – Chisel or SSH guidance.
3. Generate Hashcat Rules – produce `hashcat_generated.rule` from `<env>-passwords.txt`.
4. Search Exploits from Nmap Results – parse services and run `searchsploit`.

## Output Layout

```text
<env>/
├─ <ip>-<OS>/
│  └─ nmap/
│     ├─ full_scan.txt
│     └─ ports/
│        ├─ 22-ssh.txt
│        ├─ 80-http.txt
│        └─ ...
├─ <env>-users.txt
├─ <env>-passwords.txt
└─ commands_ran.txt
```

## Platform Support

Empusa supports **Windows**, **Linux**, and **macOS**:

- **Windows**: PowerShell profile configuration for command logging
- **Linux/macOS**: Bash/Zsh RC file configuration
- **Cross-platform file operations** using Python's pathlib

## Notes

- Command history logging is configured automatically based on your platform:
  - **Windows**: Appends to PowerShell profile (`Microsoft.PowerShell_profile.ps1`)
  - **Linux/macOS**: Appends to `~/.bashrc` or `~/.zshrc`
  - Review changes before sourcing/restarting shell
- `nmap` must be installed and on `PATH` for scanning features
- `searchsploit` (exploit-db) must be installed for exploit discovery features
- IP addresses are validated before scanning
- All file operations use cross-platform paths
- **Use responsibly and only where you have explicit authorization**

## Development

```bash
make lint   # if you add a linter
python -m empusa  # dev run
```

## License

MIT
