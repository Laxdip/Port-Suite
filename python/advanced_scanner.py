#!/usr/bin/env python3
# =============================================================================
#   ██████╗  ██████╗ ██████╗ ████████╗    ███████╗██╗   ██╗██╗████████╗███████╗
#   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
#   ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║   ██║██║   ██║   █████╗
#   ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║   ██║██║   ██║   ██╔══╝
#   ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╔╝██║   ██║   ███████╗
#   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
# =============================================================================
#   Advanced Port Scanner v2.0  |  Author: Prasad  |  github.com/Laxdip
#   Features: Multithreaded....Banner Grabbing...OS Fingerprint....CVE Hints
#             Service Detection....Stealth Mode....JSON/CSV Export...CIDR Support
# =============================================================================

import socket
import threading
import argparse
import sys
import json
import csv
import time
import struct
import ipaddress
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue

# ──────────────────────────────────────────────────────────────────────────────
#  ANSI COLOR CODES
# ──────────────────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def disable():
        for attr in ['RED','GREEN','YELLOW','BLUE','MAGENTA','CYAN','WHITE','BOLD','DIM','RESET']:
            setattr(C, attr, '')

# ──────────────────────────────────────────────────────────────────────────────
#  SERVICE DATABASE  (port → service name, protocol hint, known vuln hint)
# ──────────────────────────────────────────────────────────────────────────────
SERVICE_DB = {
    20:   ("FTP-DATA",    "ftp",   "Anonymous FTP data channel"),
    21:   ("FTP",         "ftp",   "Check: anonymous login, CVE-2011-2523 (vsftpd backdoor)"),
    22:   ("SSH",         "ssh",   "Check: weak ciphers, CVE-2023-38408 (OpenSSH RCE)"),
    23:   ("TELNET",      "telnet","CLEARTEXT – Credentials sniffable. Disable immediately."),
    25:   ("SMTP",        "smtp",  "Check: open relay, VRFY/EXPN enumeration"),
    53:   ("DNS",         "dns",   "Check: zone transfer (AXFR), CVE-2008-1447 (Kaminsky)"),
    67:   ("DHCP",        "dhcp",  "DHCP server – rogue DHCP risk"),
    69:   ("TFTP",        "tftp",  "No auth – file read/write possible"),
    80:   ("HTTP",        "http",  "Check: directory traversal, open redirects"),
    110:  ("POP3",        "pop3",  "CLEARTEXT – Use POP3S (995)"),
    111:  ("RPCBIND",     "rpc",   "NFS enumeration vector"),
    119:  ("NNTP",        "nntp",  "Legacy – check for auth bypass"),
    123:  ("NTP",         "ntp",   "Check: monlist amplification (CVE-2013-5211)"),
    135:  ("MSRPC",       "rpc",   "Windows RPC – lateral movement vector"),
    137:  ("NETBIOS-NS",  "smb",   "NetBIOS name enumeration"),
    138:  ("NETBIOS-DGM", "smb",   "NetBIOS datagram – often unneeded"),
    139:  ("NETBIOS-SSN", "smb",   "SMB over NetBIOS – EternalBlue path"),
    143:  ("IMAP",        "imap",  "CLEARTEXT – Use IMAPS (993)"),
    161:  ("SNMP",        "snmp",  "Check: community string 'public', CVE-2017-6736"),
    179:  ("BGP",         "bgp",   "BGP hijacking risk if exposed"),
    389:  ("LDAP",        "ldap",  "Check: anonymous bind, LDAP injection"),
    443:  ("HTTPS",       "https", "Check: TLS version, expired cert, POODLE/BEAST"),
    445:  ("SMB",         "smb",   "EternalBlue (CVE-2017-0144) – patch immediately"),
    465:  ("SMTPS",       "smtp",  "Secure SMTP – verify TLS config"),
    500:  ("ISAKMP",      "ipsec", "IKE – check for aggressive mode"),
    512:  ("REXEC",       "rsh",   "CLEARTEXT remote exec – legacy, disable"),
    513:  ("RLOGIN",      "rsh",   "CLEARTEXT remote login – legacy, disable"),
    514:  ("SYSLOG",      "syslog","Check: log injection, unencrypted transport"),
    554:  ("RTSP",        "rtsp",  "Camera/media stream – check auth"),
    587:  ("SMTP-ALT",    "smtp",  "Mail submission – check TLS/auth"),
    631:  ("IPP",         "ipp",   "CUPS – check: CVE-2024-47176 (RCE)"),
    636:  ("LDAPS",       "ldap",  "Secure LDAP – verify cert"),
    873:  ("RSYNC",       "rsync", "Check: anonymous access, CVE-2007-6200"),
    993:  ("IMAPS",       "imap",  "Secure IMAP – verify TLS"),
    995:  ("POP3S",       "pop3",  "Secure POP3 – verify TLS"),
    1080: ("SOCKS",       "proxy", "SOCKS proxy – check open relay"),
    1194: ("OpenVPN",     "vpn",   "VPN endpoint – check cipher suite"),
    1433: ("MSSQL",       "sql",   "Check: SA account, CVE-2020-0618 (RCE)"),
    1521: ("Oracle-DB",   "sql",   "Check: default credentials TNS"),
    2049: ("NFS",         "nfs",   "Check: world-readable exports"),
    2181: ("ZooKeeper",   "zk",    "No auth by default – CVE-2019-0201"),
    2375: ("Docker",      "docker","UNENCRYPTED Docker API – critical exposure"),
    2376: ("Docker-TLS",  "docker","Docker API with TLS – verify cert"),
    3000: ("DEV-HTTP",    "http",  "Dev server – likely no auth"),
    3306: ("MySQL",       "sql",   "Check: root with no password, CVE-2012-2122"),
    3389: ("RDP",         "rdp",   "Check: BlueKeep (CVE-2019-0708), NLA enforcement"),
    3690: ("SVN",         "svn",   "Check: anonymous access to repos"),
    4444: ("METERPRETER", "shell", "Common Metasploit/reverse-shell port – investigate"),
    4848: ("GlassFish",   "http",  "Check: default admin credentials"),
    5000: ("DEV-HTTP",    "http",  "Flask/dev server – often no auth"),
    5432: ("PostgreSQL",  "sql",   "Check: trust auth, CVE-2019-9193"),
    5900: ("VNC",         "vnc",   "Check: no auth, CVE-2006-2369"),
    5985: ("WinRM-HTTP",  "winrm", "Windows Remote Mgmt – lateral movement"),
    5986: ("WinRM-HTTPS", "winrm", "Windows Remote Mgmt TLS"),
    6379: ("Redis",       "redis", "NO AUTH by default – CVE-2022-0543 (RCE)"),
    6443: ("K8s-API",     "k8s",   "Kubernetes API – check RBAC"),
    7001: ("WebLogic",    "java",  "Check: CVE-2020-14882 (RCE), deserialization"),
    8080: ("HTTP-ALT",    "http",  "Common proxy/app port – check auth"),
    8443: ("HTTPS-ALT",   "https", "Alt HTTPS – check TLS config"),
    8888: ("Jupyter",     "http",  "Jupyter Notebook – often no auth"),
    9200: ("Elasticsearch","http", "NO AUTH by default – CVE-2015-1427 (Groovy RCE)"),
    9300: ("ES-Cluster",  "http",  "Elasticsearch cluster comms"),
    10250:("Kubelet",     "k8s",   "Kubelet API – check: anonymous auth"),
    27017:("MongoDB",     "nosql", "NO AUTH by default – exposed to internet risk"),
    50000:("DB2",         "sql",   "Check: default credentials"),
}

# ──────────────────────────────────────────────────────────────────────────────
#  OS FINGERPRINT HINTS  (TTL-based approximation from banner/ping)
# ──────────────────────────────────────────────────────────────────────────────
OS_TTL_HINTS = {
    (1,   64):  "Linux / Android / macOS",
    (65,  128): "Windows",
    (129, 255): "Cisco / Solaris / FreeBSD",
}

BANNER_OS_PATTERNS = [
    (r"(?i)ubuntu|debian|kali|centos|fedora|rhel|arch",  "Linux"),
    (r"(?i)windows|microsoft|win32|iis",                  "Windows"),
    (r"(?i)freebsd|openbsd|netbsd",                       "BSD"),
    (r"(?i)cisco|junos",                                  "Network Device"),
    (r"(?i)darwin|macos|mac os x",                        "macOS"),
    (r"(?i)android",                                      "Android"),
]

# ──────────────────────────────────────────────────────────────────────────────
#  BANNER PROBES  (what to send to elicit a response per service)
# ──────────────────────────────────────────────────────────────────────────────
PROBES = {
    "http":  b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "https": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "smtp":  b"EHLO portscanner\r\n",
    "ftp":   b"",          # FTP sends banner on connect
    "ssh":   b"",          # SSH sends banner on connect
    "imap":  b"",
    "pop3":  b"",
    "mysql": b"\x0e\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "redis": b"*1\r\n$4\r\nPING\r\n",
}

# ──────────────────────────────────────────────────────────────────────────────
#  SCAN RESULT  (dataclass-style)
# ──────────────────────────────────────────────────────────────────────────────
class ScanResult:
    def __init__(self, port, state, service, banner, response_ms, vuln_hint):
        self.port        = port
        self.state       = state          # "open" | "closed" | "filtered"
        self.service     = service
        self.banner      = banner
        self.response_ms = response_ms
        self.vuln_hint   = vuln_hint
        self.timestamp   = datetime.now().isoformat()

# ──────────────────────────────────────────────────────────────────────────────
#  CORE SCANNER CLASS
# ──────────────────────────────────────────────────────────────────────────────
class AdvancedPortScanner:

    def __init__(self, target, ports, timeout=1.5, threads=300,
                 grab_banners=True, stealth=False, verbose=False):
        self.target       = target
        self.ports        = ports
        self.timeout      = timeout
        self.threads      = threads
        self.grab_banners = grab_banners
        self.stealth      = stealth
        self.verbose      = verbose
        self.results      = []
        self.lock         = threading.Lock()
        self.scanned      = 0
        self.start_time   = None
        self.resolved_ip  = None
        self.os_guess     = "Unknown"
        self._resolve()

    # ── resolve hostname ──────────────────────────────────────────────────────
    def _resolve(self):
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            print(f"{C.RED}[!] Cannot resolve '{self.target}': {e}{C.RESET}")
            sys.exit(1)

    # ── grab banner from open port ────────────────────────────────────────────
    def _grab_banner(self, port, proto_hint):
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.resolved_ip, port))

            probe = PROBES.get(proto_hint, b"")
            if probe:
                probe = probe.replace(b"{host}", self.target.encode())
                s.sendall(probe)

            raw = s.recv(1024)
            banner = raw.decode("utf-8", errors="replace").strip()
            banner = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", banner)
            banner = banner[:200]
            s.close()
        except Exception:
            pass
        return banner

    # ── probe a single port ───────────────────────────────────────────────────
    def _scan_port(self, port):
        t0 = time.time()
        state = "closed"
        banner = ""
        service_name = "unknown"
        proto_hint   = ""
        vuln_hint    = ""

        if port in SERVICE_DB:
            service_name, proto_hint, vuln_hint = SERVICE_DB[port]
        else:
            try:
                service_name = socket.getservbyport(port, "tcp")
            except Exception:
                service_name = "unknown"

        # stealth: SYN-like (connect with quick abort) vs full connect
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            code = s.connect_ex((self.resolved_ip, port))
            elapsed_ms = (time.time() - t0) * 1000

            if code == 0:
                state = "open"
                s.close()
                if self.grab_banners:
                    banner = self._grab_banner(port, proto_hint)
            else:
                s.close()
                state = "closed"
                elapsed_ms = (time.time() - t0) * 1000

        except socket.timeout:
            state = "filtered"
            elapsed_ms = self.timeout * 1000
        except Exception:
            state = "filtered"
            elapsed_ms = (time.time() - t0) * 1000

        result = ScanResult(port, state, service_name, banner, elapsed_ms, vuln_hint)

        with self.lock:
            self.scanned += 1
            self.results.append(result)
            if state == "open":
                self._print_open(result)
            elif self.verbose and state == "filtered":
                self._print_filtered(result)

        return result

    # ── pretty print open port ────────────────────────────────────────────────
    def _print_open(self, r):
        hint_str = ""
        if r.vuln_hint:
            hint_str = f"\n        {C.YELLOW}⚠  {r.vuln_hint}{C.RESET}"
        banner_str = ""
        if r.banner:
            short = r.banner.split('\n')[0][:80]
            banner_str = f"\n        {C.DIM}↳  {short}{C.RESET}"
        print(
            f"  {C.GREEN}[OPEN]{C.RESET}  "
            f"{C.BOLD}{r.port:<6}{C.RESET}  "
            f"{C.CYAN}{r.service:<18}{C.RESET}  "
            f"{C.DIM}{r.response_ms:>7.1f} ms{C.RESET}"
            f"{hint_str}{banner_str}"
        )

    def _print_filtered(self, r):
        print(
            f"  {C.YELLOW}[FILT]{C.RESET}  "
            f"{r.port:<6}  {C.DIM}{r.service}{C.RESET}"
        )

    # ── OS fingerprint from banners ───────────────────────────────────────────
    def _fingerprint_os(self):
        all_banners = " ".join(r.banner for r in self.results if r.banner)
        for pattern, name in BANNER_OS_PATTERNS:
            if re.search(pattern, all_banners):
                self.os_guess = name
                return
        # secondary: check SSH banner version string patterns
        for r in self.results:
            if r.port == 22 and "OpenSSH" in r.banner:
                if "Ubuntu" in r.banner:
                    self.os_guess = "Linux (Ubuntu)"
                elif "Debian" in r.banner:
                    self.os_guess = "Linux (Debian)"
                else:
                    self.os_guess = "Linux"
                return

    # ── print progress bar ────────────────────────────────────────────────────
    def _progress(self, done, total):
        pct   = done / total
        width = 35
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)
        elapsed = time.time() - self.start_time
        rate    = done / elapsed if elapsed > 0 else 0
        eta     = (total - done) / rate if rate > 0 else 0
        print(
            f"\r  {C.CYAN}[{bar}]{C.RESET} "
            f"{pct*100:5.1f}%  "
            f"{done}/{total} ports  "
            f"{rate:.0f}/s  "
            f"ETA {eta:.0f}s   ",
            end="", flush=True
        )

    # ── main scan entry point ─────────────────────────────────────────────────
    def scan(self):
        self.start_time = time.time()
        total = len(self.ports)

        print(f"\n  {C.DIM}{'─'*65}{C.RESET}")
        print(f"  {C.BOLD}{C.CYAN}TARGET{C.RESET}   {self.target}  ({self.resolved_ip})")
        print(f"  {C.BOLD}PORTS{C.RESET}    {total:,} ports  |  "
              f"THREADS {self.threads}  |  "
              f"TIMEOUT {self.timeout}s  |  "
              f"BANNERS {'ON' if self.grab_banners else 'OFF'}")
        print(f"  {C.BOLD}STARTED{C.RESET}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {C.DIM}{'─'*65}{C.RESET}\n")

        completed = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for _ in as_completed(futures):
                completed += 1
                self.scanned = completed
                self._progress(completed, total)

        print()  # newline after progress

        elapsed = time.time() - self.start_time
        self._fingerprint_os()
        self._print_summary(elapsed)

    # ── summary ───────────────────────────────────────────────────────────────
    def _print_summary(self, elapsed):
        open_ports     = [r for r in self.results if r.state == "open"]
        filtered_ports = [r for r in self.results if r.state == "filtered"]
        closed_ports   = [r for r in self.results if r.state == "closed"]

        print(f"\n  {C.DIM}{'─'*65}{C.RESET}")
        print(f"  {C.BOLD}SCAN COMPLETE{C.RESET}  in {elapsed:.2f}s  "
              f"({len(self.ports)/elapsed:.0f} ports/sec)")
        print(f"\n  {C.GREEN}OPEN     : {len(open_ports)}{C.RESET}   "
              f"{C.YELLOW}FILTERED : {len(filtered_ports)}{C.RESET}   "
              f"{C.DIM}CLOSED   : {len(closed_ports)}{C.RESET}")
        print(f"  {C.MAGENTA}OS GUESS : {self.os_guess}{C.RESET}")
        print(f"  {C.DIM}{'─'*65}{C.RESET}")

        if open_ports:
            print(f"\n  {C.BOLD}OPEN PORTS SUMMARY{C.RESET}")
            print(f"  {'PORT':<8}{'SERVICE':<20}{'RESPONSE':<12}{'BANNER (first line)'}")
            print(f"  {C.DIM}{'─'*65}{C.RESET}")
            for r in sorted(open_ports, key=lambda x: x.port):
                banner_preview = r.banner.split('\n')[0][:35] if r.banner else "—"
                print(f"  {C.GREEN}{r.port:<8}{C.RESET}"
                      f"{C.CYAN}{r.service:<20}{C.RESET}"
                      f"{r.response_ms:<12.1f}"
                      f"{C.DIM}{banner_preview}{C.RESET}")

        # risk heatmap
        if open_ports:
            print(f"\n  {C.BOLD}RISK HIGHLIGHTS{C.RESET}")
            for r in sorted(open_ports, key=lambda x: x.port):
                if r.vuln_hint:
                    print(f"  {C.RED}✖{C.RESET}  Port {C.BOLD}{r.port}{C.RESET}"
                          f" ({r.service}) — {C.YELLOW}{r.vuln_hint}{C.RESET}")

        print()

    # ── export ────────────────────────────────────────────────────────────────
    def export_json(self, filepath):
        data = {
            "meta": {
                "target":      self.target,
                "resolved_ip": self.resolved_ip,
                "os_guess":    self.os_guess,
                "scanned_at":  datetime.now().isoformat(),
                "total_ports": len(self.ports),
            },
            "results": [
                {
                    "port":        r.port,
                    "state":       r.state,
                    "service":     r.service,
                    "banner":      r.banner,
                    "response_ms": round(r.response_ms, 2),
                    "vuln_hint":   r.vuln_hint,
                }
                for r in sorted(self.results, key=lambda x: x.port)
                if r.state == "open"
            ]
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  {C.GREEN}[✓] JSON saved → {filepath}{C.RESET}")

    def export_csv(self, filepath):
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["port","state","service","response_ms","banner","vuln_hint"])
            for r in sorted(self.results, key=lambda x: x.port):
                if r.state == "open":
                    w.writerow([r.port, r.state, r.service,
                                 round(r.response_ms,2), r.banner, r.vuln_hint])
        print(f"  {C.GREEN}[✓] CSV saved  → {filepath}{C.RESET}")

    def export_txt(self, filepath):
        with open(filepath, "w") as f:
            f.write(f"Port-Suite Advanced Scanner  |  Author: Prasad\n")
            f.write(f"Target : {self.target} ({self.resolved_ip})\n")
            f.write(f"OS Hint: {self.os_guess}\n")
            f.write(f"Scanned: {datetime.now().isoformat()}\n")
            f.write("="*60 + "\n\n")
            for r in sorted(self.results, key=lambda x: x.port):
                if r.state == "open":
                    f.write(f"[OPEN]  {r.port:<6}  {r.service:<20}  {r.response_ms:.1f}ms\n")
                    if r.banner:
                        f.write(f"        Banner: {r.banner[:100]}\n")
                    if r.vuln_hint:
                        f.write(f"        Risk  : {r.vuln_hint}\n")
                    f.write("\n")
        print(f"  {C.GREEN}[✓] TXT saved  → {filepath}{C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
#  PORT RANGE PARSER
# ──────────────────────────────────────────────────────────────────────────────
def parse_ports(port_str):
    """Parse port expressions like: 80,443,8080-8090,top1000,all"""
    TOP_1000 = [
        1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,
        70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,
        135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,
        280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,
        464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,
        563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,
        705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,
        888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,
        1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,
        1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,
        1041,1044,1045,1049,1050,1053,1054,1058,1059,1064,1065,1066,1069,
        1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1900,2000,
        2001,2049,2100,2181,2222,2375,2376,2379,2380,3000,3128,3268,3306,
        3389,3690,4000,4369,4444,4848,5000,5432,5900,5985,5986,6000,6379,
        6443,7001,7077,7474,8000,8080,8081,8443,8888,9000,9200,9300,10250,
        27017,50000,
    ]
    if port_str.lower() == "all":
        return list(range(1, 65536))
    if port_str.lower() in ("top1000", "common"):
        return sorted(set(TOP_1000))

    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)


# ──────────────────────────────────────────────────────────────────────────────
#  ASCII BANNER
# ──────────────────────────────────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗██╗   ██╗██╗████████╗███████╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║   ██║██║   ██║   █████╗
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║   ██║██║   ██║   ██╔══╝
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╔╝██║   ██║   ███████╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
{C.RESET}{C.DIM}
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Advanced Port Scanner v3.0        Author: Prasad  (github.com/Laxdip)  │
  │  Multithreaded • OS Detection • CVE Hints • Export                      │
  └─────────────────────────────────────────────────────────────────────────┘
{C.RESET}"""


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Port-Suite Advanced Scanner  |  Author: Prasad",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES
  python advanced_scanner.py -t scanme.nmap.org -p top1000
  python advanced_scanner.py -t 192.168.1.1 -p 1-65535 -T 500 --timeout 0.5
  python advanced_scanner.py -t example.com -p 80,443,8080-8090 --json out.json
  python advanced_scanner.py -t 10.0.0.1 -p common --no-banner --stealth
  python advanced_scanner.py -t scanme.nmap.org -p top1000 --csv results.csv

PORT EXPRESSIONS
  top1000    Most common 1000 ports (default)
  common     Same as top1000
  all        All 65535 ports
  1-1024     Port range
  80,443     Specific ports
  22,80-90   Mixed
        """
    )
    p.add_argument("-t",  "--target",   required=True, help="Target hostname or IP")
    p.add_argument("-p",  "--ports",    default="top1000",
                   help="Port spec (default: top1000)")
    p.add_argument("-T",  "--threads",  type=int, default=300,
                   help="Thread count (default: 300)")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Per-port timeout in seconds (default: 1.5)")
    p.add_argument("--no-banner", action="store_true",
                   help="Skip banner grabbing (faster)")
    p.add_argument("--stealth",   action="store_true",
                   help="Stealth mode — no probe data sent")
    p.add_argument("--verbose",   action="store_true",
                   help="Show filtered ports too")
    p.add_argument("--no-color",  action="store_true",
                   help="Disable ANSI colors")
    p.add_argument("--json",      metavar="FILE",
                   help="Export results to JSON file")
    p.add_argument("--csv",       metavar="FILE",
                   help="Export results to CSV file")
    p.add_argument("--txt",       metavar="FILE",
                   help="Export results to TXT file")
    return p.parse_args()


def main():
    args = parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    print(BANNER)

    ports = parse_ports(args.ports)
    print(f"  {C.DIM}Loaded {len(ports):,} ports to scan...{C.RESET}")

    scanner = AdvancedPortScanner(
        target       = args.target,
        ports        = ports,
        timeout      = args.timeout,
        threads      = args.threads,
        grab_banners = not args.no_banner,
        stealth      = args.stealth,
        verbose      = args.verbose,
    )

    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Scan interrupted by user.{C.RESET}")

    # exports
    if args.json:
        scanner.export_json(args.json)
    if args.csv:
        scanner.export_csv(args.csv)
    if args.txt:
        scanner.export_txt(args.txt)

    print(f"\n  {C.DIM}⚠  Use only on systems you own or have permission to test.{C.RESET}\n")


if __name__ == "__main__":
    main()
