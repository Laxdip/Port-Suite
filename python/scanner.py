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
