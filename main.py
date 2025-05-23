from ipaddress import ip_address
from colorama import Fore, Style
import nmap
import os
import sys
import time
import threading
import itertools
import pyfiglet

SCAN_DIR = "scans"
ASCII_FILE = "ascii/haunter.txt"
DEFAULT_NET = "192.168.1.0/24"

os.makedirs(SCAN_DIR, exist_ok=True)
os.system("clear")

def show_banner():
    banner = pyfiglet.figlet_format("GHost Hunter", font="slant")
    print(banner.rstrip())
    try:
        with open(ASCII_FILE, "r") as f:
            print(Fore.MAGENTA + f.read() + Style.RESET_ALL)
    except FileNotFoundError:
        print(f"{Fore.RED}ASCII file not found: {ASCII_FILE}{Style.RESET_ALL}")

def loading_animation(stop_event):
    for frame in itertools.cycle(["|", "/", "-", "\\"]):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\033[36m\rScan in progress... {frame}\033[0m")
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write("\r" + " " * 40 + "\r")

def load_previous_scan(file_name):
    previous_devices = set()
    previous_hosts = []
    path = os.path.join(SCAN_DIR, file_name)
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f.readlines()[2:]:
                parts = line.split()
                if parts:
                    previous_devices.add(parts[0])
                    previous_hosts.append(tuple(parts))
    return previous_devices, previous_hosts

def perform_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sn")
    hosts = []
    for host in nm.all_hosts():
        full_hostname = nm[host].hostname() or "N/A"
        mac = nm[host]['addresses'].get('mac', "N/A")
        hostname, router = (full_hostname.split(".", 1) + ["N/A"])[:2]
        hosts.append((host, hostname, router, mac))
    return sorted(hosts, key=lambda x: ip_address(x[0]))

def save_scan_results(file_path, hosts):
    col_widths = [18, 25, 15, 20]
    with open(file_path, "w") as f:
        header = f"{'IP Address'.ljust(col_widths[0])}{'Hostname'.ljust(col_widths[1])}" \
                 f"{'Router'.ljust(col_widths[2])}{'MAC Address'.ljust(col_widths[3])}\n"
        f.write(header)
        f.write("=" * sum(col_widths) + "\n")
        for ip, hostname, router, mac in hosts:
            row = f"{ip.ljust(col_widths[0])}{hostname.ljust(col_widths[1])}" \
                  f"{router.ljust(col_widths[2])}{mac.ljust(col_widths[3])}\n"
            f.write(row)

def scan_network(target):
    print(f"\033[33mStarting scan on {target}...\033[0m")
    stop_event = threading.Event()
    loader_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loader_thread.start()

    active_hosts = perform_nmap_scan(target)

    stop_event.set()
    loader_thread.join()
    print(f"\n\033[32mScan completed!\033[0m\n")

    scan_file = f"network_scan_{target.replace('/', '_')}.txt"
    previous_devices, previous_hosts = load_previous_scan(scan_file)
    current_devices = {host[0] for host in active_hosts}
    new_devices = current_devices - previous_devices

    if new_devices:
        print("\n\033[35mNew devices detected:\033[0m")
        for host in active_hosts:
            if host[0] in new_devices:
                ip, hostname, router, mac = host
                print(f"\033[32m[!] {ip} - {hostname} ({router}) - {mac}\033[0m")

    updated_hosts = previous_hosts + [host for host in active_hosts if host[0] in new_devices]
    updated_hosts = sorted(updated_hosts, key=lambda x: ip_address(x[0]))
    save_path = os.path.join(SCAN_DIR, scan_file)
    save_scan_results(save_path, updated_hosts)

    print(f"\n\033[32mScan updated! Results saved to {save_path}\033[0m")

def main():
    show_banner()
    target = input(f"\033[36mEnter the network to scan (default: {DEFAULT_NET}): \033[0m").strip()
    if not target:
        target = DEFAULT_NET
    scan_network(target)

if __name__ == "__main__":
    main()
