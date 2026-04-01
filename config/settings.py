#!/usr/bin/env python3
"""
Configuration settings for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
WORDLIST_DIR = CONFIG_DIR / "wordlists"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"

# Create directories if not exist
REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# Network settings
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 100
MAX_THREADS = 500
DEFAULT_PORT_RANGE = (1, 1024)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
]

# HTTP settings
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DEFAULT_REQUEST_TIMEOUT = 10

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_FILE = LOG_DIR / "eht.log"

# Report settings
REPORT_FORMATS = ["txt", "json", "html"]
DEFAULT_REPORT_FORMAT = "txt"

# Wordlist paths (defaults)
COMMON_PASSWORDS = WORDLIST_DIR / "common_passwords.txt"
COMMON_DIRECTORIES = WORDLIST_DIR / "directories.txt"
COMMON_SUBDOMAINS = WORDLIST_DIR / "subdomains.txt"

# Rate limiting
RATE_LIMIT = 100
RATE_LIMIT_ENABLED = True

# Scapy settings
SCAPY_USE_IPV6 = False

# Adaptive threading
ADAPTIVE_THREADING = True
MAX_THREADS_LIMIT = 500

# Environment variable override for max threads
if os.environ.get("EHT_MAX_THREADS"):
    MAX_THREADS_LIMIT = int(os.environ.get("EHT_MAX_THREADS"))

# Disable adaptive threading via environment variable
if os.environ.get("EHT_DISABLE_ADAPTIVE"):
    ADAPTIVE_THREADING = False

# Author info
AUTHOR = "Jet"
GITHUB = "https://github.com/JettRnh"
TIKTOK = "@jettinibos_"
