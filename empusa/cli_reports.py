"""
Empusa - Report Builder (cli_reports)

Generates OSCP-style penetration test reports with auto-population
from environment host/loot data and plugin-contributed sections.

Public API consumed by *cli.py*:

- **report_builder(…)** - interactive report wizard
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    cast,
)

from rich.prompt import Confirm, Prompt

from empusa.cli_common import (
    load_loot,
    log_error,
    log_info,
    log_success,
    render_group_heading,
    render_screen,
    sanitize_filename,
)

if TYPE_CHECKING:
    from empusa.registry import CapabilityRegistry


# ── Public API aliases (used by non-interactive CLI subcommands) ────


def gather_env_host_data(env_path: Path) -> list[dict[str, Any]]:
    """Public wrapper for ``_gather_env_host_data``."""
    return _gather_env_host_data(env_path)


def build_host_md(
    host: dict[str, Any],
    section: int,
    idx: int,
    category: str,
) -> list[str]:
    """Public wrapper for ``_build_host_md``."""
    return _build_host_md(host, section, idx, category)


# ── Data gathering ─────────────────────────────────────────────────


def _gather_env_host_data(env_path: Path) -> list[dict[str, Any]]:
    """Scan environment directory for host data from nmap scans and loot."""
    hosts: list[dict[str, Any]] = []
    nmap_port_re = re.compile(r"(\d+)/(tcp|udp)\s+open\s+([\w\-\._]+)\s*(.*)")

    try:
        for entry in sorted(env_path.iterdir()):
            if not entry.is_dir() or "-" not in entry.name:
                continue
            parts = entry.name.rsplit("-", 1)
            ip_part = parts[0]
            os_part = parts[1] if len(parts) > 1 else "Unknown"

            host_data: dict[str, Any] = {
                "ip": ip_part,
                "os": os_part,
                "ports": [],
                "loot": [],
            }

            nmap_file = entry / "nmap" / "full_scan.txt"
            if nmap_file.exists():
                try:
                    for scan_line in nmap_file.read_text(errors="ignore").splitlines():
                        port_match = nmap_port_re.search(scan_line)
                        if port_match:
                            host_data["ports"].append(
                                {
                                    "port": port_match.group(1),
                                    "proto": port_match.group(2),
                                    "service": port_match.group(3),
                                    "version": port_match.group(4).strip(),
                                }
                            )
                except Exception:
                    pass

            hosts.append(host_data)
    except Exception:
        pass

    loot_file = env_path / "loot.json"
    if loot_file.exists():
        all_loot = load_loot(loot_file)
        for loot_entry in all_loot:
            loot_host = loot_entry.get("host", "")
            for host in hosts:
                if loot_host and loot_host == host["ip"]:
                    host["loot"].append(loot_entry)
                    break

    return hosts


# ── Markdown helpers ───────────────────────────────────────────────


def _build_host_md(
    host: dict[str, Any],
    section: int,
    idx: int,
    category: str,
) -> list[str]:
    """Generate report markdown lines for a single host section."""
    lines: list[str] = []
    ip_str = host["ip"] if host["ip"] else f"<!-- {category} {idx} IP -->"
    os_str = f" ({host['os']})" if host.get("os") else ""
    s = section
    i = idx

    lines.append(f"## {s}.{i} {category} - {ip_str}{os_str}")
    lines.append("")

    # Reconnaissance & Enumeration
    lines.append(f"### {s}.{i}.1 Reconnaissance & Enumeration")
    lines.append("")
    lines.append("**Tools Used**:")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"#### {s}.{i}.1.1 Network & Service Discovery")
    lines.append("")
    target = host["ip"] if host["ip"] else "<TARGET_IP>"
    lines.append("```bash")
    lines.append(f"nmap -sC -sV -p- {target}")
    lines.append("```")
    lines.append("")
    lines.append("**Open Ports Identified**:")
    lines.append("")
    lines.append("| Port | Service | Service Version |")
    lines.append("|------|---------|-----------------|")
    if host.get("ports"):
        for p in host["ports"]:
            lines.append(f"| {p['port']}/{p['proto']} | {p['service']} | {p['version']} |")
    else:
        lines.append("| <!-- port --> | <!-- service --> | <!-- version --> |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"#### {s}.{i}.1.2 Key Findings")
    lines.append("")
    lines.append("<!-- Document key findings -->")
    lines.append("")
    lines.append("**Visual Evidence:**")
    lines.append("")
    lines.append("<!-- Add screenshots -->")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Initial Access
    lines.append(f"### {s}.{i}.2 Initial Access")
    lines.append("")
    lines.append("**Attack Vector:**")
    lines.append("")
    lines.append("<!-- Describe the attack vector -->")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"#### {s}.{i}.2.1 Steps Taken")
    lines.append("")
    lines.append("<!-- Document exploitation steps -->")
    lines.append("")
    lines.append("**Visual Evidence:**")
    lines.append("")
    lines.append("<!-- Add screenshots -->")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Privilege Escalation
    lines.append(f"### {s}.{i}.3 Privilege Escalation")
    lines.append("")
    lines.append("**Attack Vector:**")
    lines.append("")
    lines.append("<!-- Describe privilege escalation method -->")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"#### {s}.{i}.3.1 Steps Taken")
    lines.append("")
    lines.append("<!-- Document privilege escalation steps -->")
    lines.append("")
    lines.append("**Visual Evidence:**")
    lines.append("")
    lines.append("<!-- Add screenshots -->")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Post-Exploitation & Proof
    lines.append(f"### {s}.{i}.4 Post-Exploitation & Proof")
    lines.append("")
    host_loot = host.get("loot", [])
    flags = [le for le in host_loot if le.get("cred_type") == "flag"]
    creds = [le for le in host_loot if le.get("cred_type") not in ("flag", "username")]

    if flags:
        for flag_e in flags:
            lines.append(f"**Proof:** `{flag_e.get('secret', '')}`")
            src = flag_e.get("source", "")
            if src:
                lines.append(f"**Source:** {src}")
        lines.append("")

    if creds:
        lines.append("**Credentials Obtained:**")
        lines.append("")
        lines.append("| Type | Username | Secret | Source |")
        lines.append("|------|----------|--------|--------|")
        for cred in creds:
            lines.append(
                f"| {cred.get('cred_type', '')} "
                f"| {cred.get('username', '')} "
                f"| {cred.get('secret', '')} "
                f"| {cred.get('source', '')} |"
            )
        lines.append("")

    if not flags and not creds:
        lines.append("<!-- Document post-exploitation findings and proof -->")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Cleanup
    lines.append(f"### {s}.{i}.5 Cleanup")
    lines.append("")
    lines.append("<!-- Document cleanup actions for this host -->")
    lines.append("")
    lines.append("---")
    lines.append("")

    return lines


# ── Report builder (main entry) ───────────────────────────────────


def report_builder(
    *,
    registry: CapabilityRegistry | None = None,
    run_hooks_fn: Callable[..., Any] | None = None,
    ask_env_fn: Callable[..., str] | None = None,
) -> None:
    """Interactive penetration test report builder with auto-population from environment data."""
    render_screen("Penetration Test Report Builder", "Auto-populated from environment host/loot data.")

    env_name = ask_env_fn() if ask_env_fn is not None else Prompt.ask("Enter environment name").strip()

    env_path = Path(env_name).absolute()

    if not env_path.exists():
        log_error(f"Environment '{env_name}' not found.")
        return

    hosts = _gather_env_host_data(env_path)

    if hosts:
        log_info(f"\nFound {len(hosts)} host(s) in environment:", "green")
        for i, h in enumerate(hosts, 1):
            p_cnt = len(h.get("ports", []))
            l_cnt = len(h.get("loot", []))
            log_info(f"  {i}. {h['ip']} ({h['os']}) - {p_cnt} ports, {l_cnt} loot entries")
    else:
        log_info("No host data found. Report will use placeholders.", "yellow")

    render_group_heading("Report Metadata", "bold yellow")
    assessment_name = Prompt.ask("Assessment name", default="Internal Penetration Test")
    tester_name = Prompt.ask("Tester name")
    client_name = Prompt.ask("Client/Organization name", default="Client")
    target_domain = Prompt.ask("Target domain (blank if N/A)", default="")
    start_date = Prompt.ask("Start date", default=datetime.now().strftime("%B %d, %Y"))
    end_date = Prompt.ask("End date (blank if ongoing)", default="")

    standalone: list[dict[str, Any]] = []
    ad_set: list[dict[str, Any]] = []

    if hosts:
        render_group_heading("Categorize Hosts", "bold yellow")
        log_info("Mark each as [s]tandalone target or [a]ctive Directory set.")
        for h in hosts:
            cat = Prompt.ask(f"  {h['ip']} ({h['os']})", choices=["s", "a"], default="s")
            if cat == "a":
                ad_set.append(h)
            else:
                standalone.append(h)
    else:
        try:
            n_s = int(Prompt.ask("Number of standalone targets", default="3"))
        except ValueError:
            n_s = 3
        try:
            n_a = int(Prompt.ask("Number of AD targets (0 if none)", default="0"))
        except ValueError:
            n_a = 0
        for _ in range(n_s):
            standalone.append({"ip": "", "os": "", "ports": [], "loot": []})
        for _ in range(n_a):
            ad_set.append({"ip": "", "os": "", "ports": [], "loot": []})

    all_targets = standalone + ad_set
    md: list[str] = []

    # --- Frontmatter ---
    slug = sanitize_filename(assessment_name).lower().replace(" ", "-")
    md.extend(
        [
            "---",
            f"title: {assessment_name} Report",
            "tags:",
            "  - penetration-test",
            f"  - {slug}",
            "  - report",
            f"created: {datetime.now().strftime('%Y-%m-%d')}",
        ]
    )
    if start_date:
        md.append(f"start: {start_date}")
    if end_date:
        md.append(f"end: {end_date}")
    md.extend(["---", ""])

    # --- Section 1: Introduction ---
    md.extend(
        [
            f"# 1. {assessment_name} Report",
            "",
            "## 1.1 Introduction",
            "",
            f"This report documents all efforts conducted during the {assessment_name} "
            f"engagement against {client_name}. It contains the full methodology, technical "
            f"findings, and supporting evidence gathered throughout the assessment. The purpose "
            f"of this report is to demonstrate a thorough understanding of penetration testing "
            f"methodologies and provide actionable intelligence for remediation.",
            "",
            "## 1.2 Objective",
            "",
        ]
    )
    domain_clause = f" targeting the **{target_domain}** domain" if target_domain else ""
    md.extend(
        [
            f"The objective of this assessment is to perform an internal penetration test "
            f"against {client_name}'s network{domain_clause}. {tester_name} is tasked with "
            f"following a methodical approach to obtaining access to the objective goals. "
            f"This test simulates an actual penetration test from beginning to end, including "
            f"reconnaissance, exploitation, post-exploitation, and comprehensive reporting.",
            "",
            "## 1.3 Requirements",
            "",
            "- High-level summary and non-technical recommendations",
            "- Detailed walkthrough of methodology",
            "- Technical findings with evidence (screenshots, commands, proof)",
            "- Post-exploitation clean-up procedures",
            "",
            "---",
            "",
        ]
    )

    # --- Section 2: High-Level Summary ---
    domain_ref = f"**{target_domain}** domain" if target_domain else "network"
    md.extend(
        [
            "# 2. High-Level Summary",
            "",
            f"{tester_name} was tasked with performing an **internal penetration test** "
            f"against {client_name}. This assessment simulates a dedicated attacker with "
            f"internal network access targeting the organization's systems and resources.",
            "",
            f"The primary objective was to evaluate the security posture of the internal {domain_ref} by:",
            "- Enumerating all accessible hosts and services across the target network.",
            "- Identifying vulnerabilities, weak credentials, and misconfigurations.",
            "- Exploiting flaws to demonstrate potential risk and lateral movement paths.",
            f"- Providing actionable recommendations to strengthen {client_name}'s defenses.",
            "",
            "### Key Accomplishments",
            "",
            "<!-- Document key accomplishments here -->",
            "",
            "### Overall Impact",
            "",
            "<!-- Describe overall impact of the assessment findings -->",
            "",
            "## 2.1 Recommendations",
            "",
            "Based on the findings from this assessment, the following actions are recommended:",
            "",
            "<!-- Add recommendations here -->",
            "",
            "---",
            "",
        ]
    )

    # Summary table
    md.extend(
        [
            "| IP Address | Initial Access Vector | Privilege Escalation Method | Proof Hash |",
            "|------------|----------------------|---------------------------|------------|",
        ]
    )
    for h in all_targets:
        ip_cell = h["ip"] if h["ip"] else "<!-- IP -->"
        proof_cell = ""
        for le in h.get("loot", []):
            if le.get("cred_type") == "flag":
                proof_cell = le.get("secret", "")
                break
        md.append(
            f"| {ip_cell} | <!-- vector --> | <!-- method --> | {proof_cell if proof_cell else '<!-- proof -->'} |"
        )
    md.extend(["", ""])

    # --- Section 3: Methodologies ---
    md.extend(
        [
            "# 3. Methodologies",
            "",
            "## 3.1 Information Gathering",
            "",
            "The information gathering phase focuses on identifying scope, target assets, "
            "and collecting intelligence before actively engaging with systems.",
            "",
            "During this engagement, the following activities were performed:",
            "- **Scope Confirmation & Asset Identification:** "
            "Confirmed all in-scope IP ranges and documented testing boundaries.",
            "- **Active & Passive Intelligence Gathering:** "
            "Leveraged passive reconnaissance and active scanning (Nmap, banner grabbing) to map the network.",
            "- **Network Mapping & Service Discovery:** "
            "Determined available services and attack surfaces on each host.",
            "",
            "The following IP addresses were in-scope:",
            "```txt",
        ]
    )
    ips_found = [h["ip"] for h in all_targets if h["ip"]]
    md.extend(ips_found if ips_found else ["<!-- Add in-scope IPs here -->"])
    md.extend(
        [
            "```",
            "",
            "### 3.1.1 Key Observations During Information Gathering",
            "",
            "<!-- Document key observations -->",
            "",
            "## 3.2 Service Enumeration",
            "",
            "The service enumeration phase focused on fingerprinting all active services on the discovered hosts.",
            "",
            "### 3.2.1 Tools & Techniques Utilized",
            "",
            "<!-- List tools and techniques -->",
            "",
            "### 3.2.2 Purpose & Objectives",
            "",
            "<!-- Describe purpose -->",
            "",
            "### 3.2.3 Key Findings During Enumeration",
            "",
            "<!-- Document key findings -->",
            "",
            "## 3.3 Penetration",
            "",
            "The penetration phase focused on exploiting identified attack vectors to gain "
            "footholds, escalate privileges, and pivot through the network.",
            "",
            "### 3.3.1 Approach",
            "",
            "<!-- Describe approach -->",
            "",
            "### 3.3.2 Examples of Successful Exploits",
            "",
            "<!-- Document exploits -->",
            "",
            "### 3.3.3 Outcomes",
            "",
            "<!-- Document outcomes -->",
            "",
            "## 3.4 Maintaining Access",
            "",
            "Short-lived and controlled persistence mechanisms were established to ensure "
            "continued access during the assessment.",
            "",
            "### 3.4.1 Approach",
            "",
            "<!-- Describe persistence approach -->",
            "",
            "### 3.4.2 Examples",
            "",
            "<!-- Document persistence examples -->",
            "",
            "## 3.5 House Cleaning",
            "",
            "The house cleaning phase ensured that **no residual artifacts**, user accounts, "
            "or configurations were left on any compromised hosts.",
            "",
            "### 3.5.1 Actions Taken",
            "",
            "<!-- Document cleanup actions -->",
            "",
            "### 3.5.2 Final Confirmation",
            "",
            "After capturing all proof files and completing documentation, a final "
            "verification sweep was conducted across all in-scope systems.",
            "",
        ]
    )

    # --- Dynamic host sections ---
    next_sec = 4

    if standalone:
        md.extend([f"# {next_sec}. Independent Challenges", ""])
        for idx_s, host_s in enumerate(standalone, 1):
            md.extend(_build_host_md(host_s, next_sec, idx_s, "Target"))
        next_sec += 1

    if ad_set:
        md.extend([f"# {next_sec}. Active Directory Set", ""])
        for idx_a, host_a in enumerate(ad_set, 1):
            md.extend(_build_host_md(host_a, next_sec, idx_a, "Active Directory"))
        next_sec += 1

    # --- Conclusion ---
    n_hosts = len(all_targets)
    scope_desc = (
        " both isolated hosts and an integrated Active Directory environment" if ad_set else " all target systems"
    )
    md.extend(
        [
            f"# {next_sec}. Conclusion",
            "",
            f"*The {assessment_name} demanded a rigorous, methodical penetration test across"
            f"{scope_desc}. Through systematic reconnaissance, enumeration, exploitation, "
            f"and privilege escalation techniques, {n_hosts} "
            f"system{'s were' if n_hosts != 1 else ' was'} assessed. All actions were "
            f"thoroughly documented, and a comprehensive cleanup was performed to ensure "
            f"no residual artifacts remained on any target system.*",
            "",
            "Respectfully submitted,",
            f"**{tester_name}**",
            f"*{datetime.now().strftime('%B %d, %Y')}*",
            "",
        ]
    )

    # --- Plugin-contributed report sections (Layer 4 - Registry) ---
    if registry is not None:
        plugin_sections = registry.get("report_section")
        if plugin_sections:
            md.extend(["", f"# {next_sec}. Plugin-Contributed Sections", ""])
            for entry in plugin_sections:
                try:
                    section_result: Any = entry.handler(
                        {
                            "env_name": env_name,
                            "env_path": str(env_path),
                            "hosts": all_targets,
                            "standalone": standalone,
                            "ad_set": ad_set,
                        }
                    )
                    if isinstance(section_result, list):
                        md.extend(cast(list[str], section_result))
                    elif isinstance(section_result, str):
                        md.append(section_result)
                except Exception as exc:
                    log_error(f"Plugin report section '{entry.name}' failed: {exc}")
            next_sec += 1

    if run_hooks_fn is not None:
        run_hooks_fn(
            "pre_report_write",
            {
                "env_name": env_name,
                "env_path": str(env_path),
                "standalone_count": len(standalone),
                "ad_count": len(ad_set),
            },
        )

    # --- Write report file ---
    report_text = "\n".join(md)
    file_slug = sanitize_filename(assessment_name).lower().replace(" ", "_")
    report_path = env_path / f"{file_slug}_report.md"

    if report_path.exists() and not Confirm.ask(f"[yellow]{report_path.name} already exists. Overwrite?[/yellow]"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = env_path / f"{file_slug}_report_{ts}.md"

    try:
        report_path.write_text(report_text, encoding="utf-8")
        log_success(f"[+] Report generated: {report_path}")
        log_info(f"  Standalone targets: {len(standalone)}", "cyan")
        log_info(f"  AD targets: {len(ad_set)}", "cyan")
        filled_ports = sum(1 for h in all_targets if h.get("ports"))
        filled_loot = sum(1 for h in all_targets if h.get("loot"))
        if filled_ports:
            log_info(f"  Auto-filled port data for {filled_ports} host(s)", "green")
        if filled_loot:
            log_info(f"  Auto-filled loot/proof data for {filled_loot} host(s)", "green")
        log_info("\n  Fill in <!-- comment --> placeholders with your findings.", "yellow")
        if run_hooks_fn is not None:
            run_hooks_fn(
                "on_report_generated",
                {
                    "report_path": str(report_path),
                    "env_name": env_name,
                    "env_path": str(env_path),
                    "standalone_count": len(standalone),
                    "ad_count": len(ad_set),
                },
            )
    except Exception as e:
        log_error(f"Error writing report: {e}")
