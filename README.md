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

## Install

```bash
# Option A: local dev
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Option B: install from source without editing
pip install .
```

> Requires **Python 3.9+** and external tools you call during ops (e.g., `nmap`, `searchsploit`).

## Usage

Launch the interactive menu:

```bash
empusa
```

or via python:

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

## Notes

- `set_shell_history_hooks()` appends to `~/.bashrc` or `~/.zshrc`. Review diffs before sourcing.
- `searchsploit` and `nmap` must be installed and on `PATH`.
- Use responsibly and only where you have explicit authorization.


## Development

```bash
make lint   # if you add a linter
python -m empusa  # dev run
```

## License

MIT
