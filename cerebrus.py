#!/usr/bin/env python3
"""
Cerebrus v1.0 - Python Network Analysis Tool
Similar to Nmap functionality

DISCLAIMER: For EDUCATIONAL and AUTHORIZED testing only.
Unauthorized scanning of networks is illegal.
"""

import socket
import threading
import time
import sys
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common port to service mapping
COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080]

BANNER = """
+------------------------------------------+
|            Cerebrus v1.0                 |
|   Python Network Analysis Tool           |
|   For Educational Use Only               |
+------------------------------------------+
"""


class Cerebrus:
    """Network scanner with port scanning, host discovery, and service detection."""
    
    def __init__(self, target, timeout=1.0, threads=100, verbose=False):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.lock = threading.Lock()
    
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def get_hostname(self, ip):
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    def get_targets(self):
        """Parse target and return list of IPs."""
        targets = []
        
        if '/' in self.target:
            try:
                network = ipaddress.ip_network(self.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            except ValueError as e:
                print(f"[!] Invalid CIDR: {e}")
                return []
        elif '-' in self.target:
            try:
                base_ip, end = self.target.rsplit('.', 1)
                if '-' in end:
                    start, stop = end.split('-')
                    for i in range(int(start), int(stop) + 1):
                        targets.append(f"{base_ip}.{i}")
            except Exception as e:
                print(f"[!] Invalid IP range: {e}")
                return []
        else:
            ip = self.resolve_hostname(self.target) if not self._is_valid_ip(self.target) else self.target
            if ip:
                targets.append(ip)
            else:
                print(f"[!] Could not resolve: {self.target}")
                return []
        
        return targets
    
    def _is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def tcp_connect_scan(self, ip, port):
        """TCP connect scan on a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                banner = self.grab_banner(sock, port)
                sock.close()
                return (port, 'open', banner)
            else:
                sock.close()
                return (port, 'closed', None)
        except socket.timeout:
            return (port, 'filtered', None)
        except Exception as e:
            return (port, 'error', str(e))
    
    def grab_banner(self, sock, port):
        """Grab service banner."""
        try:
            if port in [80, 8080, 443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else None
        except:
            return None
    
    def scan_port_range(self, ip, ports):
        """Scan ports on target IP."""
        results = {'ip': ip, 'hostname': self.get_hostname(ip), 'open': [], 'closed': [], 'filtered': []}
        
        print(f"\n[*] Scanning {ip} - {len(ports)} ports")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.tcp_connect_scan, ip, port): port for port in ports}
            
            for future in as_completed(futures):
                port, status, banner = future.result()
                
                if status == 'open':
                    service = COMMON_PORTS.get(port, 'unknown')
                    results['open'].append({'port': port, 'service': service, 'banner': banner})
                    print(f"  [+] {port}/tcp open - {service}")
                elif status == 'filtered':
                    results['filtered'].append(port)
        
        return results
    
    def ping_host(self, ip):
        """Check if host is alive."""
        probe_ports = [80, 443, 22, 21, 25, 3389, 445]
        start_time = time.time()
        
        for port in probe_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return (ip, True, (time.time() - start_time) * 1000)
            except:
                continue
        
        return (ip, False, 0)
    
    def discover_hosts(self):
        """Discover live hosts."""
        targets = self.get_targets()
        if not targets:
            return []
        
        print(f"\n[*] Discovering hosts ({len(targets)} targets)...")
        live_hosts = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.ping_host, ip): ip for ip in targets}
            
            for future in as_completed(futures):
                ip, is_alive, response_time = future.result()
                if is_alive:
                    hostname = self.get_hostname(ip)
                    live_hosts.append({'ip': ip, 'hostname': hostname, 'response_time': response_time})
                    hn = f" ({hostname})" if hostname else ""
                    print(f"  [+] {ip}{hn} is up ({response_time:.2f}ms)")
        
        print(f"\n[*] Found {len(live_hosts)} live hosts")
        return live_hosts
    
    def detect_service(self, ip, port):
        """Detect service version."""
        result = {'port': port, 'service': COMMON_PORTS.get(port, 'unknown'), 'version': None}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            if port == 22:
                result['version'] = sock.recv(256).decode('utf-8', errors='ignore').strip()
            elif port == 21:
                result['version'] = sock.recv(256).decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080]:
                sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                for line in response.split('\n'):
                    if line.lower().startswith('server:'):
                        result['version'] = line.split(':', 1)[1].strip()
                        break
            
            sock.close()
        except:
            pass
        
        return result


def format_results(results):
    """Display scan results."""
    ip = results.get('ip', 'Unknown')
    hostname = results.get('hostname', '')
    open_ports = results.get('open', [])
    
    hn = f" ({hostname})" if hostname else ""
    
    print(f"\n{'='*60}")
    print(f"Results for {ip}{hn}")
    print('='*60)
    
    if open_ports:
        print(f"\n{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
        print('-'*60)
        for p in sorted(open_ports, key=lambda x: x['port']):
            banner = (p.get('banner') or '')[:30].replace('\n', ' ')
            print(f"{p['port']:<10} {'open':<10} {p['service']:<15} {banner}")
    else:
        print("\nNo open ports found.")
    print()


def save_results(results, filename):
    """Save results to file."""
    with open(filename, 'w') as f:
        f.write(f"Cerebrus Report - {datetime.now()}\n")
        f.write("="*50 + "\n\n")
        
        for r in results:
            f.write(f"Target: {r['ip']}\n")
            for p in r.get('open', []):
                f.write(f"  {p['port']}/tcp open {p['service']}\n")
            f.write("\n")
    
    print(f"[+] Results saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Cerebrus - Python Network Analysis Tool',
        epilog='Example: python cerebrus.py 192.168.1.1 -p 1-1000'
    )
    
    parser.add_argument('target', help='Target IP, hostname, or CIDR range')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 22,80 or 1-1000)')
    parser.add_argument('-d', '--discover', action='store_true', help='Host discovery only')
    parser.add_argument('-sV', '--version', action='store_true', help='Version detection')
    parser.add_argument('--top-ports', type=int, help='Scan top N ports')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Threads (default=100)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Save to file')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print(BANNER)
    
    scanner = Cerebrus(args.target, args.timeout, args.threads, args.verbose)
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    start_time = time.time()
    all_results = []
    
    if args.discover:
        scanner.discover_hosts()
    else:
        ports = []
        if args.all_ports:
            ports = list(range(1, 65536))
        elif args.top_ports:
            ports = TOP_PORTS[:args.top_ports]
        elif args.ports:
            for part in args.ports.split(','):
                if '-' in part:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        else:
            ports = TOP_PORTS
        
        ports = sorted(set(ports))
        print(f"[*] Scanning {len(ports)} ports")
        
        for ip in scanner.get_targets():
            results = scanner.scan_port_range(ip, ports)
            
            if args.version and results['open']:
                print("\n[*] Detecting service versions...")
                for i, p in enumerate(results['open']):
                    info = scanner.detect_service(ip, p['port'])
                    if info['version']:
                        results['open'][i]['banner'] = info['version']
                        print(f"  [+] {p['port']}: {info['version'][:50]}")
            
            all_results.append(results)
            format_results(results)
    
    elapsed = time.time() - start_time
    
    if args.output and all_results:
        save_results(all_results, args.output)
    
    print(f"[*] Completed in {elapsed:.2f} seconds")
    
    if all_results:
        total = sum(len(r.get('open', [])) for r in all_results)
        print(f"[*] Total open ports: {total}")


if __name__ == '__main__':
    main()
