# Empusa

![Python] ![License] ![Version] ![Stars]

## **Shape-shifting Recon & Exploitation Framework**

> *"She shifts form… beauty, beast, and death."*

Empusa is a modular offensive security framework designed for **structured engagements**, combining:

* Event-driven execution
* Plugin-based extensibility
* Environment-scoped workflows
* Automated reporting and data tracking

---

## 🧠 Framework Overview

Empusa is built as a layered system:

* CLI-driven operator workflows
* Lifecycle-based event system
* Hook and plugin extension layers
* Scoped service execution model

Each action in the system emits events:

```text
Action → Event → Hooks → Plugins → Services → Output
```

This allows functionality to be extended without modifying core logic.

---

## 🧱 Core System

### 🔄 Event System

Empusa emits lifecycle events such as:

* `on_startup`
* `post_build`
* `post_scan`
* `on_loot_add`
* `on_report_generated`

These events drive both hooks and plugins.

---

### 🧩 Extension Layers

#### Hooks (Lightweight)

* Drop-in Python scripts
* No configuration required
* Located in `empusa/hooks/<event>/`

#### Plugins (Structured)

* JSON manifests
* Declared permissions
* Dependency resolution + cycle detection
* Scoped access via `ScopedServices`

---

### 🔐 Scoped Services

Plugins operate through controlled services:

| Service    | Description                    |
| ---------- | ------------------------------ |
| Filesystem | Environment-scoped file access |
| Subprocess | Controlled command execution   |
| Loot       | Credential + data management   |
| Registry   | Capability registration        |

---

## 🧰 Capabilities

### 🏗️ Environment & Recon

* Threaded `nmap` scanning
* OS classification
* Service extraction
* Per-port notes with guidance

---

### 🔍 Exploitation Support

* Exploit discovery via `searchsploit`
* Reverse tunnel command generation
* Privilege escalation command generators
* Active Directory enumeration playbooks

---

### 🔐 Credential Operations

* Loot tracking (credentials, hashes, flags)
* Credential reuse detection
* Cross-host spraying suggestions
* Hash identification + cracking command builder
* Hashcat rule generation

---

### 📊 Reporting

* Auto-generated Markdown reports
* Built from scan + loot data
* Plugin-injected sections supported

---

### 🧪 Module System

* Compile and manage payload modules
* Supports C, C++, C#, Go, Rust, Perl, Make
* 22 built-in modules (reverse shells, bind shells, privesc, enumeration)
* Detects available compilers
* Batch compilation support

---

## 🗂️ Output Structure

```text
<env>/
├── <ip>-<OS>/
│   ├── nmap/
│   └── ports/
├── loot.json
├── loot_report.md
├── commands_ran.txt
└── <assessment>_report.md
```

---

## 🚀 Quickstart

```bash
git clone https://github.com/Icarus4122/empusa.git
cd empusa
pip install -e .
empusa
```

---

## ⚙️ CLI Overview

```text
1. Build Environment
2. Reverse Tunnel
3. Hashcat Rules
4. Exploit Search
5. Loot Tracker
6. Report Builder
7. Environment Switch
8. Hooks / Plugins
9. Module Workshop
10. Privesc Generator
11. Hash Identifier
12. AD Playbook
```

---

## 🧩 Hooks

Example:

```python
def run(context: dict) -> None:
    print(f"New loot: {context['username']}")
```

### Events

| Event               | Description          |
| ------------------- | -------------------- |
| on_startup          | framework launch     |
| on_shutdown         | shutdown cleanup     |
| post_build          | environment creation |
| post_scan           | scan completion      |
| on_loot_add         | credential added     |
| on_report_generated | report created       |

---

## 🔌 Plugin Development

Structure:

```text
empusa/plugins/<plugin>/
├── manifest.json
├── plugin.py
└── config.json
```

Example:

```python
def activate(services, registry, bus):
    services.logger.info("Plugin loaded")

def on_post_scan(event):
    services.logger.info(f"{event.ip}")
```

---

### Permissions

| Permission | Description           |
| ---------- | --------------------- |
| filesystem | file access           |
| subprocess | command execution     |
| loot_read  | read loot             |
| loot_write | write loot            |
| registry   | register capabilities |
| network    | advisory only         |

---

## 🖥️ Platform Support

| Feature           | Linux/macOS | Windows    |
| ----------------- | ----------- | ---------- |
| Scanning          | ✔           | ✔          |
| Cleanup           | ✔           | ✔          |
| Shell integration | bash/zsh    | PowerShell |

---

## ⚙️ CLI Flags

| Flag         | Description        |
| ------------ | ------------------ |
| `-v`         | verbose            |
| `-q`         | quiet              |
| `--dry-run`  | simulate execution |
| `--no-color` | disable colors     |
| `-w N`       | worker threads     |

---

## 🛠️ Development

```bash
make build
make clean
python -m empusa
```

---

## ✅ Status

* [x] Event-driven architecture
* [x] Plugin system with dependency validation
* [x] Scoped service enforcement
* [x] Environment-based workflow
* [x] Reporting system

---

## 🎯 Future Work

* [ ] Additional analyzers (plugin-based)
* [ ] Enhanced reporting templates
* [ ] Network traffic simulation support
* [ ] Detection engineering integrations

---

## ⚠️ Disclaimer

For authorized security testing and research only.

---

## 👤 Contributors

* [@AmosSParker](https://github.com/AmosSParker)

---

## 📜 License

GPL-3.0-or-later

[Python](https://img.shields.io/badge/python-3.9%2B-blue)
[License](https://img.shields.io/badge/license-GPL--3.0-green)
[Version](https://img.shields.io/github/v/release/Icarus4122/empusa)
[Stars](https://img.shields.io/github/stars/Icarus4122/empusa?style=social)
