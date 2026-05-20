

import socket
import threading
import sys
import time
import argparse
from datetime import datetime
from queue import Queue

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ███████╗███╗   ███╗ █████╗ ██████╗ ████████╗███████╗ █████╗ ███╗   ██╗      ║
║  ██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗  ██║      ║
║  ███████╗██╔████╔██║███████║██████╔╝   ██║   █████╗  ███████║██╔██╗ ██║      ║
║  ╚════██║██║╚██╔╝██║██╔══██║██╔══██╗   ██║   ██╔══╝  ██╔══██║██║╚██╗██║      ║
║  ███████║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║      ║
║  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝      ║
║                                                                              ║
║                         Advanced Port Scanner                                ║
║                              by Prasad                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)

# Common ports and their services
COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

# Service signatures for banner grabbing
SERVICE_SIGNATURES = {
    "SSH": ["SSH", "OpenSSH"],
    "FTP": ["FTP", "vsFTPd", "FileZilla"],
    "HTTP": ["HTTP", "Apache", "nginx", "IIS", "Express"],
    "MySQL": ["MySQL", "mariadb"],
    "PostgreSQL": ["PostgreSQL", "postgres"],
    "RDP": ["RDP", "Microsoft Terminal Services"],
    "SMB": ["SMB", "Windows", "Samba"],
    "VNC": ["VNC", "RFB"],
}

def get_service_name(port):
    """Return service name for common ports"""
    return COMMON_PORTS.get(port, "Unknown")

def grab_banner(sock, port):
    """Try to grab service banner"""
    try:
        sock.settimeout(2)
        # Send common probe based on port
        probes = {
            80: "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            443: "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            21: "HELP\r\n",
            22: "",
            25: "HELP\r\n",
            110: "USER test\r\n",
            220: "HELP\r\n",
        }
        
        probe = probes.get(port, "\r\n")
        if probe:
            sock.send(probe.encode())
        
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        
        # Detect service from banner
        detected_service = None
        for service, signatures in SERVICE_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in banner.lower():
                    detected_service = service
                    break
            if detected_service:
                break
        
        if banner:
            return banner[:150], detected_service
        return None, None
    except:
        return None, None

def scan_port(target, port, timeout=1):
    """Scan a single port and return result with banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            service = get_service_name(port)
            banner, detected = grab_banner(sock, port)
            sock.close()
            return True, port, service, banner, detected
        sock.close()
        return False, port, None, None, None
    except:
        return False, port, None, None, None

def scan_worker(target, queue, results, timeout, verbose):
    """Worker thread for scanning ports"""
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except:
            break
        
        is_open, port, service, banner, detected = scan_port(target, port, timeout)
        
        if is_open:
            results.append((port, service, banner, detected))
            if verbose:
                status = f"{Colors.GREEN}[+] PORT {port} OPEN{Colors.RESET}"
                if service != "Unknown":
                    status += f" [{Colors.YELLOW}{service}{Colors.RESET}]"
                if detected:
                    status += f" → {Colors.CYAN}{detected}{Colors.RESET}"
                print(status)
                if banner:
                    print(f"    Banner: {Colors.MAGENTA}{banner[:100]}{Colors.RESET}")
        elif verbose:
            print(f"{Colors.RED}[-] PORT {port} CLOSED{Colors.RESET}")
        
        queue.task_done()

def os_detection(target):
    """Attempt OS detection using TTL"""
    try:
        ping_cmd = None
        import subprocess
        import platform
        
        system = platform.system().lower()
        if system == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", "1000", target]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", "1", target]
        
        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        
        # Look for TTL in output
        output = result.stdout.lower()
        if "ttl=" in output:
            ttl_part = output.split("ttl=")[1].split()[0]
            ttl = int(ttl_part)
            
            if ttl <= 64:
                return "Linux / Unix"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Cisco / Solaris"
        return "Unknown"
    except:
        return "Unknown"

def quick_scan(target, ports=[22, 80, 443, 3389, 3306, 8080]):
    """Quick scan of common ports"""
    print(f"{Colors.CYAN}[*] Quick scanning common ports on {target}...{Colors.RESET}\n")
    results = []
    for port in ports:
        is_open, port, service, banner, detected = scan_port(target, port)
        if is_open:
            results.append((port, service, banner, detected))
            status = f"{Colors.GREEN}[+] PORT {port} OPEN{Colors.RESET}"
            if service != "Unknown":
                status += f" [{Colors.YELLOW}{service}{Colors.RESET}]"
            print(status)
        time.sleep(0.05)
    return results

def full_scan(target, start_port, end_port, threads=100, timeout=1, verbose=False):
    """Full port scan with threading"""
    print(f"{Colors.CYAN}[*] Starting full scan on {target}{Colors.RESET}")
    print(f"[*] Port range: {start_port}-{end_port}")
    print(f"[*] Threads: {threads} | Timeout: {timeout}s\n")
    
    queue = Queue()
    results = []
    
    # Fill queue with ports
    for port in range(start_port, end_port + 1):
        queue.put(port)
    
    # Create and start threads
    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=scan_worker, args=(target, queue, results, timeout, verbose))
        thread.start()
        thread_list.append(thread)
    
    # Wait for all threads to complete
    for thread in thread_list:
        thread.join()
    
    return results

def main():
    parser = argparse.ArgumentParser(description="SmartScan - Advanced Python Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000 or 22,80,443)")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick scan of common ports")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-to", "--timeout", type=float, default=1, help="Connection timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show closed ports")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--os", action="store_true", help="Attempt OS detection")
    
    args = parser.parse_args()
    
    print_banner()
    
    target = args.target
    # Remove protocol if present
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    start_time = time.time()
    
    # OS Detection
    if args.os:
        print(f"{Colors.CYAN}[*] Attempting OS detection...{Colors.RESET}")
        os_guess = os_detection(target)
        print(f"{Colors.GREEN}[+] OS Guess: {os_guess}{Colors.RESET}\n")
    
    # Port scan
    if args.quick:
        results = quick_scan(target)
    elif args.ports:
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
            results = full_scan(target, start, end, args.threads, args.timeout, args.verbose)
        else:
            ports = [int(p) for p in args.ports.split(",")]
            results = []
            for port in ports:
                is_open, port, service, banner, detected = scan_port(target, port, args.timeout)
                if is_open:
                    results.append((port, service, banner, detected))
                    print(f"{Colors.GREEN}[+] PORT {port} OPEN{Colors.RESET}")
    else:
        # Default: scan top 20 ports
        top_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
        results = []
        for port in top_ports:
            is_open, port, service, banner, detected = scan_port(target, port, args.timeout)
            if is_open:
                results.append((port, service, banner, detected))
                status = f"{Colors.GREEN}[+] PORT {port} OPEN{Colors.RESET}"
                if service != "Unknown":
                    status += f" [{Colors.YELLOW}{service}{Colors.RESET}]"
                print(status)
    
    # Summary
    elapsed = time.time() - start_time
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] Scan Complete{Colors.RESET}")
    print(f"[*] Target: {target}")
    print(f"[*] Open ports found: {len(results)}")
    print(f"[*] Time taken: {elapsed:.2f} seconds")
    
    if results:
        print(f"\n{Colors.GREEN}[+] Open Ports Summary:{Colors.RESET}")
        for port, service, banner, detected in sorted(results):
            info = f"  {port:5} | {service:15}"
            if detected:
                info += f" | {detected}"
            print(info)
    
    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"SmartScan Results - {target}\n")
            f.write(f"Scan completed: {datetime.now()}\n")
            f.write(f"Open ports: {len(results)}\n\n")
            for port, service, banner, detected in sorted(results):
                f.write(f"Port {port}: {service}\n")
                if detected:
                    f.write(f"  Service: {detected}\n")
                if banner:
                    f.write(f"  Banner: {banner}\n")
        print(f"\n{Colors.GREEN}[+] Results saved to {args.output}{Colors.RESET}")
    
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)
