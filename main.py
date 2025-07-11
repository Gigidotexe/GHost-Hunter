#!/usr/bin/env python3
import os
import sys
import logging
import socket
from ipaddress import ip_address, IPv4Network
from colorama import Fore, Style
import pyfiglet
from scapy.all import ARP, Ether, srp, IP, ICMP, sr
from concurrent.futures import ThreadPoolExecutor, as_completed

# =============== CONFIGURATION
SCAN_DIR = "scans"
BANNER_FILE = "haunter.txt"
DEFAULT_NET = "192.168.1.0/24"
COMMON_PORTS = [22, 80, 443, 445, 3389]
THREADS_ARP = 20
THREADS_ICMP = 20
THREADS_TCP = 50

# =============== SAFETY CHECK
if os.geteuid() != 0:
    print(f"{Fore.RED}[!] You must run this script as root{Style.RESET_ALL}")
    sys.exit(1)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
os.makedirs(SCAN_DIR, exist_ok=True)

# =============== BANNER
def show_banner():
    banner = pyfiglet.figlet_format("GHost Hunter", font="slant")
    print(banner.rstrip())
    try:
        with open(BANNER_FILE) as f:
            print(Fore.MAGENTA + f.read() + Style.RESET_ALL)
    except FileNotFoundError:
        print(f"{Fore.RED}Missing BANNER file: {BANNER_FILE}{Style.RESET_ALL}")

# =============== HOSTNAME RESOLUTION
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"

# =============== ARP SCAN
def arp_worker(ip_list, results):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_list)
    ans, _ = srp(pkt, timeout=2, retry=1, inter=0, verbose=0, filter="arp")
    for _, r in ans:
        ip, mac = r.psrc, r.hwsrc
        if ip not in results:
            hostname = resolve_hostname(ip)
            results[ip] = {"method": "ARP", "hostname": hostname, "mac": mac}
            print(f"{Fore.GREEN}[ARP] {ip} ({hostname}) - MAC {mac}{Style.RESET_ALL}")

def scan_arp(all_ips):
    results = {}
    print(f"{Fore.YELLOW}[*] Starting ARP scan on {len(all_ips)} IPs with {THREADS_ARP} threads...{Style.RESET_ALL}")
    chunk_size = max(1, len(all_ips) // THREADS_ARP)
    chunks = [all_ips[i:i+chunk_size] for i in range(0, len(all_ips), chunk_size)]
    with ThreadPoolExecutor(max_workers=THREADS_ARP) as executor:
        futures = [executor.submit(arp_worker, chunk, results) for chunk in chunks]
        for _ in as_completed(futures):
            pass
    print(f"{Fore.GREEN}ARP scan completed.{Style.RESET_ALL}")
    return results

# =============== ICMP SCAN
def icmp_worker(ip_list, results):
    pkt = [IP(dst=ip)/ICMP() for ip in ip_list]
    ans, _ = sr(pkt, timeout=1.5, retry=1, verbose=0, filter="icmp")
    for _, r in ans:
        ip = r.src
        if ip not in results:
            hostname = resolve_hostname(ip)
            icmp_type = r.getlayer(ICMP).type
            icmp_code = r.getlayer(ICMP).code
            if icmp_type == 0:
                results[ip] = {"method": "ICMP", "hostname": hostname, "mac": "N/A"}
                print(f"{Fore.CYAN}[ICMP] {ip} ({hostname}) responded{Style.RESET_ALL}")
            elif icmp_type == 3 and icmp_code == 3:
                results[ip] = {"method": "ICMP Port Unreachable", "hostname": hostname, "mac": "N/A"}
                print(f"{Fore.BLUE}[ICMP] {ip} ({hostname}) is UP but port unreachable{Style.RESET_ALL}")

def scan_icmp(all_ips):
    results = {}
    print(f"{Fore.YELLOW}[*] Starting ICMP scan on {len(all_ips)} IPs with {THREADS_ICMP} threads...{Style.RESET_ALL}")
    chunk_size = max(1, len(all_ips) // THREADS_ICMP)
    chunks = [all_ips[i:i+chunk_size] for i in range(0, len(all_ips), chunk_size)]
    with ThreadPoolExecutor(max_workers=THREADS_ICMP) as executor:
        futures = [executor.submit(icmp_worker, chunk, results) for chunk in chunks]
        for _ in as_completed(futures):
            pass
    print(f"{Fore.GREEN}ICMP scan completed.{Style.RESET_ALL}")
    return results

# =============== TCP SCAN
def tcp_connect(ip):
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, port))
            s.close()
            return ip, port
        except:
            continue
    return ip, None

def scan_tcp(all_ips):
    results = {}
    print(f"{Fore.YELLOW}[*] Starting TCP scan on {len(all_ips)} IPs with {THREADS_TCP} threads...{Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=THREADS_TCP) as executor:
        futures = {executor.submit(tcp_connect, ip): ip for ip in all_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            port = fut.result()[1]
            if port:
                hostname = resolve_hostname(ip)
                results[ip] = {"method": f"TCP port {port}", "hostname": hostname, "mac": "N/A"}
                print(f"{Fore.MAGENTA}[TCP] {ip} ({hostname}) port {port} open{Style.RESET_ALL}")
    print(f"{Fore.GREEN}TCP scan completed.{Style.RESET_ALL}")
    return results

# =============== AGGREGATION & SORTING
def perform_scan(target):
    all_ips = [str(ip) for ip in IPv4Network(target).hosts()]
    discovered = {}
    discovered.update(scan_arp(all_ips))
    discovered.update(scan_icmp(all_ips))
    discovered.update(scan_tcp(all_ips))
    sorted_results = sorted(discovered.items(), key=lambda x: ip_address(x[0]))
    return [(ip, data["method"], data["hostname"], data["mac"]) for ip, data in sorted_results]

# =============== SAVE RESULTS
def save_txt(path, hosts):
    max_ip_len = max([len("IP")] + [len(h[0]) for h in hosts]) + 2
    max_method_len = max([len("Method")] + [len(h[1]) for h in hosts]) + 2
    max_host_len = max([len("Hostname")] + [len(h[2]) for h in hosts]) + 2
    max_mac_len = max([len("MAC")] + [len(h[3]) for h in hosts]) + 2

    with open(path, "w") as f:
        f.write(f"{' IP'.ljust(max_ip_len)}{' Method'.ljust(max_method_len)}"
                f"{' Hostname'.ljust(max_host_len)}{' MAC'.ljust(max_mac_len)}\n")
        f.write("=" * (max_ip_len + max_method_len + max_host_len + max_mac_len) + "\n")
        for ip, meth, hostname, mac in hosts:
            f.write(f" {ip.ljust(max_ip_len-1)}{meth.ljust(max_method_len)}"
                    f"{hostname.ljust(max_host_len)}{mac.ljust(max_mac_len)}\n")

# =============== MAIN
def main():
    show_banner()
    target = input(f"{Fore.CYAN}Network to scan (default {DEFAULT_NET}): {Style.RESET_ALL}").strip() or DEFAULT_NET
    try:
        hosts = perform_scan(target)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan manually interrupted{Style.RESET_ALL}")
        sys.exit(1)

    txt_path = os.path.join(SCAN_DIR, f"scan_{target.replace('/','_')}.txt")
    save_txt(txt_path, hosts)

    print(f"\n{Fore.GREEN}TXT -> {txt_path}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
