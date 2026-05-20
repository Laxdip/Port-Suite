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
