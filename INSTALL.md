# Installing Empusa

## Requirements

| Requirement | Minimum | Recommended |
| ------------- | --------- | ------------- |
| Python | 3.9 | 3.12+ |
| pip / pipx | latest | latest |
| nmap | any | 7.94+ |
| searchsploit | any | latest |

> `nmap` and `searchsploit` are optional but required for scanning and exploit
> discovery features.

## Option 1 - pipx (Recommended)

`pipx` installs Empusa in an isolated virtual environment with the `empusa`
command available globally.

```bash
# From GitHub
pipx install git+https://github.com/Icarus4122/empusa.git

# From a local clone
git clone https://github.com/Icarus4122/empusa.git
cd empusa
pipx install .
```

### Upgrading with pipx

```bash
pipx upgrade empusa

# Or force reinstall from local source
pipx uninstall empusa && pipx install .
```

## Option 2 - pip

```bash
pip install git+https://github.com/Icarus4122/empusa.git

# Or from local clone
pip install .
```

### Editable / Development Install

```bash
pip install -e .
```

## Option 3 - Docker

```bash
docker build -t empusa .
docker run -it --rm empusa
```

The Dockerfile installs `nmap` and `exploitdb` automatically.

## Post-Install Setup

### Verify the installation

```bash
empusa --version   # Should print 2.2.0
empusa --help      # Show CLI flags
```

### Hook directories

On first launch Empusa auto-creates `empusa/hooks/` with subdirectories
for every lifecycle event:

```text
empusa/hooks/
├── on_startup/
├── on_shutdown/
├── pre_build/
├── post_build/
├── pre_scan_host/
├── post_scan/
├── on_loot_add/
├── on_report_generated/
├── pre_report_write/
├── on_env_select/
├── pre_command/
├── post_command/
└── post_compile/
```

You can also create example hooks via **menu option 8 -> Create example hook**.

### Kali Linux Notes

Kali ships with a system Python that is externally managed. Use `pipx`:

```bash
sudo apt install pipx
pipx ensurepath
pipx install .
```

If you previously installed an older version:

```bash
pipx uninstall empusa && pipx install .
```

### External Tools

| Tool | Install (Kali/Debian) | Used By |
| ------ | ---------------------- | --------- |
| nmap | `sudo apt install nmap` | Environment Builder |
| searchsploit | `sudo apt install exploitdb` | Exploit Discovery |
| chisel | manual download | Reverse Tunnels |
| ligolo-ng | manual download | Reverse Tunnels |

## Uninstall

```bash
# pipx
pipx uninstall empusa

# pip
pip uninstall empusa

# Clean up hook directory (optional - only if you added custom hooks)
# Hooks live inside the empusa/ package directory and are removed with uninstall
```

## Troubleshooting

| Problem | Solution |
| --------- | ---------- |
| `command not found: empusa` | Run `pipx ensurepath` and restart your shell |
| `externally-managed-environment` | Use `pipx` instead of `pip` |
| `ModuleNotFoundError: rich` | Reinstall: `pipx uninstall empusa && pipx install .` |
| Nmap scans fail | Ensure `nmap` is on `PATH` (`which nmap`) |
| Hooks not firing | Check file has `def run(context):` and is `.py` |
