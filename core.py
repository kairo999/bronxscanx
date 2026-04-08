#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BRONX Multi-Scanner v8.0 - ULTRA GOD LEVEL
Author: @BRONX_ULTRA (Telegram)
Features: Host/IP Scanner, CIDR, Subdomain, Domain Scanner, CDN, Tunable, Auto-Update
"""

import os
import sys
import socket
import threading
import httpx
import urllib3
import asyncio
import ipaddress
import signal
import ssl
from queue import Queue
from datetime import datetime
from collections import Counter

from rich.console import Console
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
shutdown = False
VERSION = "8.0.0"
REPO_URL = "https://raw.githubusercontent.com/kairo999/bronxscan/main/bronxscan/core.py"

def handle_exit(sig, frame):
    global shutdown
    shutdown = True
    console.print("\n[red]🛑 Stopping scan...[/red]")

signal.signal(signal.SIGINT, handle_exit)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    console.print("""
[bold red]
██████╗ ██████╗  ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔══██╗██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝██████╔╝██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══██╗██║   ██║██║╚██╗██║ ██╔██╗ 
██████╔╝██║  ██║╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
[/bold red]
[bold yellow]BRONX MULTI-SCANNER v{}[/bold yellow]
[dim]Telegram: @BRONX_ULTRA | God Level | Auto-Update[/dim]
    """.format(VERSION))

def main_menu():
    console.print(Panel.fit(
        "⚡ BRONX v8.0 - ULTRA GOD LEVEL\n"
        "[1] Host/IP Scanner    [2] CIDR Scanner    [3] Domain File Scanner\n"
        "[4] Subdomain Finder   [5] CDN Detector    [6] Tunable Checker\n"
        "[7] Result Viewer      [8] Host Inspector  [9] Update Tool\n"
        "[0] Exit",
        style="bold red", title="MAIN MENU"
    ))
    return console.input("[bold cyan]➤ Choose: [/bold cyan]").strip()

# ================= HOST/IP SCANNER =================
class HostScanner:
    def __init__(self):
        self.ports = [80, 443, 8080, 8443]
        self.threads = 200
        self.timeout = 2
        self.q = Queue()
        self.lock = threading.Lock()

    def tcp_scan(self, ip, port):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((ip, port))
            s.close()
            return True
        except:
            return False

    def http_check(self, ip, port):
        try:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{ip}:{port}"
            with httpx.Client(verify=False, timeout=self.timeout) as client:
                r = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                server = r.headers.get("Server", "Unknown")
                return r.status_code, server
        except:
            return None, None

    def scan_host(self, ip, outfile, progress, task):
        for port in self.ports:
            if shutdown: break
            if self.tcp_scan(ip, port):
                code, server = self.http_check(ip, port)
                if code:
                    with self.lock:
                        result = f"{code} | {ip} | {server} | {ip}:{port}"
                        console.print(f"[green]{code}[/green] │ [cyan]{ip}[/cyan] │ [magenta]{server}[/magenta] │ [yellow]{ip}:{port}[/yellow]")
                        outfile.write(result + "\n")
                        outfile.flush()
                    break
        progress.update(task, advance=1)

    def worker(self, outfile, progress, task):
        while True:
            ip = self.q.get()
            if ip is None: break
            self.scan_host(ip, outfile, progress, task)
            self.q.task_done()

    def run(self):
        clear()
        console.print(Panel.fit("[bold green]HOST / IP SCANNER[/bold green]\n[dim]Single IP or IP list file[/dim]", style="green"))
        target = input("[?] IP or file path: ").strip()
        if not target: return
        if os.path.isfile(target):
            with open(target) as f:
                ips = [line.strip() for line in f if line.strip()]
        else:
            ips = [target]
        output = "host_results.txt"
        total = len(ips)
        with open(output, "w") as f:
            f.write("# Host Scanner Results\n")
        with open(output, "a") as outfile:
            with Progress(TextColumn("[cyan]SCANNING HOSTS"), BarColumn(), MofNCompleteColumn(), TimeRemainingColumn(), console=console) as progress:
                task = progress.add_task("scan", total=total)
                threads = []
                for _ in range(self.threads):
                    t = threading.Thread(target=self.worker, args=(outfile, progress, task), daemon=True)
                    t.start()
                    threads.append(t)
                for ip in ips:
                    self.q.put(ip)
                self.q.join()
                for _ in range(self.threads):
                    self.q.put(None)
                for t in threads:
                    t.join()
        console.print(f"\n[green]✓ Results saved to {output}[/green]")
        input("\nPress Enter...")

# ================= CIDR SCANNER =================
class CIDRScanner:
    def __init__(self):
        self.ports = [80, 443]
        self.threads = 300
        self.timeout = 2

    async def scan_cidr(self):
        cidr = console.input("[cyan]CIDR (e.g., 192.168.1.0/24): [/cyan]").strip()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except:
            console.print("[red]Invalid CIDR[/red]")
            return
        total = net.num_addresses
        console.print(f"[yellow]Scanning {total} IPs...[/yellow]")
        found = 0
        with Progress(TextColumn("[cyan]CIDR SCAN"), BarColumn(), MofNCompleteColumn(), console=console) as progress:
            task = progress.add_task(f"[cyan]{cidr}", total=total)
            sem = asyncio.Semaphore(self.threads)
            async def scan_one(ip):
                nonlocal found
                async with sem:
                    for port in self.ports:
                        try:
                            reader, writer = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout=self.timeout)
                            writer.close()
                            await writer.wait_closed()
                            code = await self.http_head(str(ip), port)
                            if code:
                                console.print(f"[green]✓[/green] {ip}:{port} [{code}]")
                                with open("cidr_results.txt", "a") as f:
                                    f.write(f"{ip}:{port} [{code}]\n")
                                found += 1
                                break
                        except:
                            pass
                    progress.update(task, advance=1)
            tasks = [scan_one(ip) for ip in net]
            await asyncio.gather(*tasks)
        console.print(f"[green]Found {found} open ports[/green]")
        input("Press Enter...")

    async def http_head(self, ip, port):
        try:
            ssl_ctx = ssl.create_default_context() if port==443 else None
            if ssl_ctx:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=2)
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            if b"200" in data or b"301" in data or b"302" in data:
                return "200"
            return None
        except:
            return None

    def run(self):
        clear()
        banner()
        asyncio.run(self.scan_cidr())

# ================= DOMAIN FILE SCANNER =================
class DomainScanner:
    def __init__(self):
        self.THREADS = 180
        self.TIMEOUT = 2
        self.q = Queue()
        self.lock = threading.Lock()

    def resolve_ip(self, host):
        try: return socket.gethostbyname(host)
        except: return "-"

    def scan(self, host, ports, outfile, client):
        ip = self.resolve_ip(host)
        for port in ports:
            url = f"http{'s' if port==443 else ''}://{host}:{port}"
            try:
                r = client.get(url, timeout=self.TIMEOUT, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 302: return
                server = r.headers.get("Server", "Unknown")
                result = f"{r.status_code} | {ip} | {server} | {host}:{port}"
                with self.lock:
                    console.print(f"[green]{r.status_code:<5}[/green] │ [cyan]{ip:<15}[/cyan] │ [magenta]{server:<22}[/magenta] │ [yellow]{host}:{port}[/yellow]")
                    outfile.write(result + "\n")
                    outfile.flush()
            except: pass

    def worker(self, ports, outfile, progress, task):
        with httpx.Client(verify=False, timeout=self.TIMEOUT, http2=True) as client:
            while True:
                host = self.q.get()
                if host is None: break
                self.scan(host, ports, outfile, client)
                progress.update(task, advance=1)
                self.q.task_done()

    def run(self):
        clear()
        console.print(Panel.fit("[bold green]DOMAIN FILE SCANNER[/bold green]", style="green"))
        domain_file = input("Domain file: ").strip()
        if not os.path.isfile(domain_file):
            console.print("[red]File not found[/red]")
            input("Press Enter...")
            return
        ports_input = input("Ports (default 443): ").strip()
        ports = [443] if ports_input == "" else [int(x) for x in ports_input.split(",")]
        output = "results.txt"
        with open(domain_file) as f:
            domains = [line.strip() for line in f if line.strip()]
        total = len(domains)
        console.print("\n[bold]Code │ IP │ Server │ Host[/bold]\n")
        with open(output, "a") as outfile:
            with Progress(TextColumn("[cyan]SCANNING DOMAINS"), BarColumn(), MofNCompleteColumn(), TimeRemainingColumn(), console=console) as progress:
                task = progress.add_task("scan", total=total)
                threads = []
                for _ in range(self.THREADS):
                    t = threading.Thread(target=self.worker, args=(ports, outfile, progress, task), daemon=True)
                    t.start()
                    threads.append(t)
                for d in domains:
                    self.q.put(d)
                self.q.join()
                for _ in range(self.THREADS):
                    self.q.put(None)
                for t in threads:
                    t.join()
        console.print(f"\n[green]✓ Saved to {output}[/green]")
        input("Press Enter...")

# ================= SUBDOMAIN FINDER =================
class SubdomainFinder:
    def run(self):
        clear()
        console.print(Panel.fit("[bold cyan]SUBDOMAIN FINDER[/bold cyan]", style="cyan"))
        domain = input("Target domain: ").strip()
        wordlist = input("Wordlist file: ").strip()
        if not os.path.isfile(wordlist):
            console.print("[red]Wordlist not found[/red]")
            input("Press Enter...")
            return
        with open(wordlist) as f:
            subs = [line.strip() for line in f if line.strip()]
        output = f"subdomains_{domain}.txt"
        found = []
        console.print(f"\n[green]Scanning {len(subs)} subdomains...[/green]\n")
        for sub in subs:
            if shutdown: break
            full = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full)
                console.print(f"[green]✓[/green] {full} -> {ip}")
                found.append(f"{full} -> {ip}")
            except:
                pass
        with open(output, "w") as f:
            f.write("\n".join(found))
        console.print(f"\n[green]Found {len(found)} subdomains, saved to {output}[/green]")
        input("Press Enter...")

# ================= CDN DETECTOR =================
class CDNFinder:
    def run(self):
        clear()
        banner()
        domain = input("Domain: ").strip()
        for scheme in ("https","http"):
            try:
                with httpx.Client(verify=False, timeout=10) as client:
                    r = client.get(f"{scheme}://{domain}", headers={"User-Agent":"Mozilla/5.0"})
                    console.print(f"[bold]Status:[/bold] {r.status_code}")
                    table = Table(show_header=True)
                    table.add_column("Header", style="cyan")
                    table.add_column("Value", style="white")
                    for k,v in r.headers.items():
                        table.add_row(k,v)
                    console.print(table)
                    headers_str = str(r.headers).lower()
                    if "cf-ray" in headers_str:
                        console.print("[green]CDN: Cloudflare[/green]")
                    elif "x-amz-cf" in headers_str:
                        console.print("[green]CDN: CloudFront[/green]")
                    elif "google" in headers_str:
                        console.print("[green]CDN: Google[/green]")
                    else:
                        console.print("[yellow]CDN: Unknown[/yellow]")
                    break
            except Exception as e:
                console.print(f"[red]{scheme} failed: {e}[/red]")
        input("Press Enter...")

# ================= TUNNABLE CHECKER =================
class TunableChecker:
    def run(self):
        clear()
        banner()
        domain = input("Domain: ").strip()
        try:
            ip = socket.gethostbyname(domain)
            console.print(f"[green]IP: {ip}[/green]")
            if ip.startswith(("23.","49.","184.")):
                console.print("[red]✗ NON-TUNNABLE (IP blocked)[/red]")
            else:
                console.print("[green]✓ TUNNABLE - Good for SSH tunneling[/green]")
                console.print(Panel(f"CONNECT {domain}:443 HTTP/1.1\nHost: {domain}\nUser-Agent: Mozilla/5.0", title="Payload Example", border_style="green"))
        except:
            console.print("[red]Resolution failed[/red]")
        input("Press Enter...")

# ================= RESULT VIEWER =================
class ResultViewer:
    def run(self):
        clear()
        banner()
        if not os.path.exists("results.txt"):
            console.print("[red]No results.txt found (run Domain Scanner first)[/red]")
            input("Press Enter...")
            return
        with open("results.txt") as f:
            lines = [l.strip() for l in f if l.strip()]
        if not lines:
            console.print("[yellow]Empty[/yellow]")
        else:
            table = Table(title="Hosts from results.txt")
            table.add_column("Status", style="green")
            table.add_column("IP", style="cyan")
            table.add_column("Server", style="magenta")
            table.add_column("Host:Port", style="yellow")
            for line in lines[:100]:
                parts = line.split("|")
                if len(parts)>=4:
                    table.add_row(parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip())
            console.print(table)
        input("Press Enter...")

# ================= HOST INSPECTOR =================
class HostInspector:
    def run(self):
        clear()
        banner()
        target = input("host:port (e.g., example.com:443): ").strip()
        if ":" not in target:
            console.print("[red]Need port[/red]")
            input("Press Enter...")
            return
        host, port = target.rsplit(":",1)
        port = int(port)
        scheme = "https" if port==443 else "http"
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                r = client.get(f"{scheme}://{host}:{port}", headers={"User-Agent":"Mozilla/5.0"})
                console.print(f"[bold]Status:[/bold] {r.status_code}")
                for k,v in r.headers.items():
                    console.print(f"[cyan]{k}[/cyan]: {v}")
                if r.text:
                    console.print("\n[bold]Body preview:[/bold]")
                    console.print(r.text[:500] + ("..." if len(r.text)>500 else ""))
        except Exception as e:
            console.print(f"[red]{e}[/red]")
        input("Press Enter...")

# ================= AUTO-UPDATE =================
def update_tool():
    console.print("[yellow]Checking for updates...[/yellow]")
    try:
        try:
            import requests
            r = requests.get(REPO_URL, timeout=10)
            content = r.text
        except ImportError:
            import urllib.request
            with urllib.request.urlopen(REPO_URL, timeout=10) as response:
                content = response.read().decode('utf-8')
        import re
        match = re.search(r'VERSION\s*=\s*"([^"]+)"', content)
        new_ver = match.group(1) if match else "unknown"
        if new_ver != VERSION:
            console.print(f"[green]New version {new_ver} available. Updating...[/green]")
            with open(__file__, 'w') as f:
                f.write(content)
            console.print("[green]Update complete! Please restart the tool.[/green]")
            sys.exit(0)
        else:
            console.print("[green]Already up to date.[/green]")
    except Exception as e:
        console.print(f"[red]Update error: {e}[/red]")
    input("Press Enter...")

# ================= MAIN =================
def main():
    while True:
        clear()
        banner()
        choice = main_menu()
        if choice == "1":
            HostScanner().run()
        elif choice == "2":
            CIDRScanner().run()
        elif choice == "3":
            DomainScanner().run()
        elif choice == "4":
            SubdomainFinder().run()
        elif choice == "5":
            CDNFinder().run()
        elif choice == "6":
            TunableChecker().run()
        elif choice == "7":
            ResultViewer().run()
        elif choice == "8":
            HostInspector().run()
        elif choice == "9":
            update_tool()
        elif choice == "0":
            clear()
            console.print("[red]Goodbye from BRONX![/red]")
            break
        else:
            console.print("[red]Invalid option[/red]")
            input("Press Enter...")

if __name__ == "__main__":
    main()
