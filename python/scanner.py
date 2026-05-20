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
