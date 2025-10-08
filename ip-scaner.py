#!/usr/bin/env python3
"""
net_menu.py
Interactive one-by-one network scanner menu with colored UI + skull banner.

Features:
 - Colored skull banner + MR.XHACKER title
 - Discover hosts on a network (ping sweep)
 - Port scan single/multiple hosts
 - Quick scan common ports
 - Save/Show last results

Use responsibly: scan only networks/devices you own or have permission to scan.
"""

import ipaddress, platform, subprocess, socket, time, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- Colors ----------------
RESET = '\033[0m'
BOLD  = '\033[1m'
RED   = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW= '\033[1;33m'
BLUE  = '\033[1;34m'
MAG   = '\033[1;35m'
CYAN  = '\033[1;36m'
WHITE = '\033[1;37m'

# ---------------- Config ----------------
DEFAULT_PORTS = [22, 80, 443, 8080]
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 200

# ---------------- Helpers ----------------
def clear():
    if platform.system().lower().startswith("win"):
        subprocess.call("cls", shell=True)
    else:
        subprocess.call("clear", shell=True)

def center_text(s):
    cols = shutil.get_terminal_size((80, 20)).columns
    lines = s.splitlines()
    out = []
    for ln in lines:
        ln_stripped = ln.rstrip("\n")
        pad = max(0, (cols - len(strip_ansi(ln_stripped))) // 2)
        out.append(" " * pad + ln_stripped)
    return "\n".join(out)

def strip_ansi(s):
    # remove simple ANSI sequences for width calc
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

# ---------------- Skull Banner ----------------
def skull_banner():
    skull = r"""
       .-''''-.
      /  .--.  \
     /  /    \  \
    |  |  ()  |  |
    |  |      |  |
     \  \    /  /
      '._'--'_. '
    """
    title = f"{CYAN}{BOLD}       === MR.XHACKER ==={RESET}"
    art = f"{MAG}{skull}{RESET}\n{center_text(title)}\n"
    print(center_text(art))

# ---------------- Network utilities ----------------
def ping_host(ip, timeout=1.0):
    """Return True if host responds to ping, False otherwise."""
    system = platform.system().lower()
    if system.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout*1000)), str(ip)]
    else:
        # Linux: -c 1 (count), -W timeout (seconds)
        if platform.system().lower() == "darwin":
            cmd = ["ping", "-c", "1", str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), str(ip)]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
        return r.returncode == 0
    except Exception:
        return False

def tcp_scan_port(ip, port, timeout=0.8):
    """Try TCP connect to ip:port. Return True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), int(port)))
            return True
    except Exception:
        return False

def expand_ports(port_str):
    """Parse strings like '22,80,8000-8010' into sorted list."""
    out = set()
    parts = [p.strip() for p in port_str.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            a,b = part.split("-",1)
            out.update(range(int(a), int(b)+1))
        else:
            out.add(int(part))
    return sorted([p for p in out if 1 <= p <= 65535])

# ---------------- High level functions ----------------
def discover_hosts(network_cidr, timeout=DEFAULT_TIMEOUT, workers=MAX_WORKERS):
    """Ping sweep the provided CIDR and return list of alive IPs."""
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except Exception as e:
        print(f"{RED}Invalid network:{RESET} {e}")
        return []
    ips = [str(ip) for ip in net.hosts()]
    alive = []
    print(f"{YELLOW}[*]{RESET} Starting ping sweep of {BLUE}{net}{RESET} ({len(ips)} hosts) ...")
    start = time.time()
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as exe:
        futures = {exe.submit(ping_host, ip, timeout): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
                    print(f"  {GREEN}[+]{RESET} {ip} is alive")
            except Exception:
                pass
    elapsed = time.time() - start
    print(f"{YELLOW}[*]{RESET} Discovery complete: found {GREEN}{len(alive)}{RESET} hosts (elapsed {elapsed:.1f}s)")
    return sorted(alive)

def scan_ports_on_host(ip, ports, timeout=DEFAULT_TIMEOUT, workers=200):
    """Scan the list of ports on the given host in parallel. Return dict port->True/False"""
    results = {}
    print(f"{CYAN}[*]{RESET} Scanning {MAG}{ip}{RESET} ports: {ports} ...")
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as exe:
        futures = {exe.submit(tcp_scan_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                ok = fut.result()
                results[p] = ok
                if ok:
                    print(f"  {GREEN}[open]{RESET} {p}")
            except Exception:
                results[p] = False
    open_ports = [p for p,v in results.items() if v]
    print(f"{YELLOW}[*]{RESET} Result for {BLUE}{ip}{RESET}: open ports = {GREEN if open_ports else RED}{open_ports if open_ports else 'None'}{RESET}")
    return results

def scan_multiple_hosts(ips, ports, timeout=DEFAULT_TIMEOUT, workers=200):
    """Scan given ports on multiple hosts, returns dict host->port results"""
    all_results = {}
    for ip in ips:
        res = scan_ports_on_host(ip, ports, timeout=timeout, workers=workers)
        all_results[ip] = res
    return all_results

# ---------------- Storage for last results ----------------
LAST_RESULTS = {
    "hosts": [],
    "scan": {}
}

def save_results(path):
    try:
        with open(path, "a") as f:
            f.write(time.asctime() + "\n")
            f.write("Discovered hosts:\n")
            for h in LAST_RESULTS["hosts"]:
                f.write(f"  {h}\n")
            f.write("Port scan results:\n")
            for host, ports in LAST_RESULTS["scan"].items():
                openp = [p for p,v in ports.items() if v]
                f.write(f"  {host} -> open: {openp}\n")
            f.write("\n")
        print(f"{GREEN}Results appended to{RESET} {path}")
    except Exception as e:
        print(f"{RED}Could not save results:{RESET} {e}")

# ---------------- Interactive menu helpers ----------------
def read_cidr_prompt():
    while True:
        net = input(f"{MAG}Enter network in CIDR (e.g. 192.168.1.0/24) or 'back': {RESET}").strip()
        if net.lower() == "back":
            return None
        try:
            _ = ipaddress.ip_network(net, strict=False)
            return net
        except Exception as e:
            print(f"{RED}Invalid CIDR:{RESET} {e}")

def read_ip_prompt(prompt="Enter IP (or 'back'): "):
    while True:
        ip = input(f"{MAG}{prompt}{RESET}").strip()
        if ip.lower() == "back":
            return None
        try:
            _ = ipaddress.ip_address(ip)
            return ip
        except Exception as e:
            print(f"{RED}Invalid IP:{RESET} {e}")

def read_ports_prompt(default=None):
    default_str = ",".join(str(p) for p in default) if default else "22,80,443"
    s = input(f"{MAG}Enter ports (e.g. 22,80,8000-8010) [default: {default_str}]: {RESET}").strip()
    if not s:
        s = default_str
    try:
        ports = expand_ports(s)
        return ports
    except Exception as e:
        print(f"{RED}Invalid ports:{RESET} {e}")
        return []

# ---------------- Main menu ----------------
def main_menu():
    global LAST_RESULTS
    while True:
        clear()
        skull_banner()
        print(f"{BOLD}{CYAN}=== MR.XHACKER — Network Scanner Menu ==={RESET}")
        print(f"{YELLOW}1){RESET} Discover hosts on a network (ping sweep)")
        print(f"{YELLOW}2){RESET} Port scan a single host")
        print(f"{YELLOW}3){RESET} Port scan multiple hosts (from discovery or manual list)")
        print(f"{YELLOW}4){RESET} Quick scan common ports on a network (ping then scan open hosts)")
        print(f"{YELLOW}5){RESET} Save last results to file")
        print(f"{YELLOW}6){RESET} Show last results summary")
        print(f"{YELLOW}7){RESET} Exit")
        choice = input(f"\n{MAG}Choose an option [1-7]: {RESET}").strip()
        if choice == "1":
            net = read_cidr_prompt()
            if not net: continue
            alive = discover_hosts(net, timeout=DEFAULT_TIMEOUT, workers=MAX_WORKERS)
            LAST_RESULTS["hosts"] = alive
            LAST_RESULTS["scan"] = {}
            input(f"\n{BLUE}Press Enter to continue...{RESET}")
        elif choice == "2":
            ip = read_ip_prompt()
            if not ip: continue
            ports = read_ports_prompt(default=DEFAULT_PORTS)
            res = scan_ports_on_host(ip, ports, timeout=DEFAULT_TIMEOUT, workers=MAX_WORKERS)
            LAST_RESULTS["hosts"] = [ip]
            LAST_RESULTS["scan"] = {ip: res}
            input(f"\n{BLUE}Press Enter to continue...{RESET}")
        elif choice == "3":
            mode = input(f"{MAG}Use discovered hosts? (y) or manual list (m): {RESET}").strip().lower()
            if mode == "y":
                ips = LAST_RESULTS.get("hosts", [])
                if not ips:
                    print(f"{RED}No discovered hosts available — run option 1 first or choose manual.{RESET}")
                    input(f"\n{BLUE}Press Enter to continue...{RESET}")
                    continue
            else:
                manual = input(f"{MAG}Enter IPs space-separated: {RESET}").strip()
                ips = manual.split()
            if not ips:
                print(f"{RED}No hosts provided.{RESET}")
                input(f"\n{BLUE}Press Enter to continue...{RESET}")
                continue
            ports = read_ports_prompt(default=DEFAULT_PORTS)
            allres = scan_multiple_hosts(ips, ports, timeout=DEFAULT_TIMEOUT, workers=MAX_WORKERS)
            LAST_RESULTS["hosts"] = ips
            LAST_RESULTS["scan"] = allres
            input(f"\n{BLUE}Press Enter to continue...{RESET}")
        elif choice == "4":
            net = read_cidr_prompt()
            if not net: continue
            alive = discover_hosts(net, timeout=DEFAULT_TIMEOUT, workers=MAX_WORKERS)
            LAST_RESULTS["hosts"] = alive
            if not alive:
                print(f"{RED}No hosts found by discovery.{RESET}")
                input(f"\n{BLUE}Press Enter to continue...{RESET}")
                continue
            ports = DEFAULT_PORTS
            print(f"{YELLOW}Scanning discovered hosts on common ports:{RESET} {ports}")
            allres = scan_multiple_hosts(alive, ports, timeout=DEFAULT_TIMEOUT, workers=MAX_WORKERS)
            LAST_RESULTS["scan"] = allres
            input(f"\n{BLUE}Press Enter to continue...{RESET}")
        elif choice == "5":
            path = input(f"{MAG}Enter file to append results (e.g. ~/scan_log.txt): {RESET}").strip()
            if not path:
                print(f"{RED}No path entered.{RESET}")
                input(f"\n{BLUE}Press Enter to continue...{RESET}")
                continue
            save_results(path)
            input(f"\n{BLUE}Press Enter to continue...{RESET}")
        elif choice == "6":
            print(f"\n{CYAN}--- Last Results Summary ---{RESET}")
            hosts = LAST_RESULTS.get("hosts", [])
            print("Discovered hosts:", hosts if hosts else "None")
            for h, ports in LAST_RESULTS.get("scan", {}).items():
                openp = [p for p,v in ports.items() if v]
                print(f"  {h} -> open: {openp if openp else 'None'}")
            input(f"\n{BLUE}Press Enter to continue...{RESET}")
        elif choice == "7":
            print(f"{GREEN}Bye 👋{RESET}"); break
        else:
            print(f"{RED}Invalid choice — try again.{RESET}")
            time.sleep(0.8)

if __name__ == "__main__":
    main_menu()
