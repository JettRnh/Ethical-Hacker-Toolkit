# Ethical Hacker Toolkit

Professional security testing framework for authorized penetration testing and vulnerability assessment.

## Author

- **Jet**
- GitHub: https://github.com/JettRnh
- TikTok: @jettinibos_

---

## ⚠️ Important Notice

This toolkit is strictly for:
- Authorized penetration testing
- Security research in controlled environments
- Educational purposes

**Do NOT use this tool on systems without explicit permission.**

---

## Features

### Network Security
- Port scanning with service detection
- Banner grabbing and version identification
- Ping sweep for network discovery
- Traceroute with hop timing

### Web Application Testing
- Directory and file brute-force
- Subdomain enumeration
- HTTP headers security analysis
- SQL injection detection (basic)

### Reconnaissance
- WHOIS lookup for domains and IPs
- DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
- Zone transfer attempts
- Email harvesting from websites

### Cryptography
- Hash cracking (MD5, SHA1, SHA256, SHA512, NTLM)
- Dictionary and brute-force methods
- Encoding utilities (Base64, Hex, URL, ROT13, Caesar, Fernet)
- Hash generation

### Reporting
- Output formats: TXT, JSON, HTML
- Logging system
- Report merging utility
- Log cleanup

---

## Installation

```bash
git clone https://github.com/JettRnh/Ethical-Hacker-Toolkit.git
cd Ethical-Hacker-Toolkit
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh
source venv/bin/activate
```

---

## Quick Start

```bash
# Port scan
eht scan 192.168.1.1 -p 1-1000 --banner

# Network discovery
eht ping 192.168.1.0/24

# Traceroute
eht trace google.com

# Directory brute-force
eht dir http://example.com -w config/wordlists/directories.txt

# Subdomain enumeration
eht subdomain example.com -w config/wordlists/subdomains.txt

# HTTP headers analysis
eht headers https://example.com

# SQL test
eht sql "http://example.com/page?id=1"

# WHOIS lookup
eht whois example.com

# DNS enumeration
eht dns example.com --transfer

# Email harvesting
eht email example.com -u http://example.com

# Hash cracking
eht crack <hash> md5 -w config/wordlists/common_passwords.txt

# Encoding
eht encode "Hello World" --base64 --hex --rot13

# Full scan
eht all example.com -o html
```

---

## Command Overview

### Network
- `scan` → Port scanning  
- `ping` → Network discovery  
- `trace` → Traceroute  

### Web
- `dir` → Directory brute-force  
- `subdomain` → Subdomain scan  
- `headers` → Header analysis  
- `sql` → SQL testing  

### Recon
- `whois` → WHOIS lookup  
- `dns` → DNS enumeration  
- `email` → Email scraping  

### Crypto
- `crack` → Hash cracking  
- `encode` → Encoding tools  

### Full
- `all` → Run all modules  

---

## Options

| Option | Description |
|--------|------------|
| -o     | Output format (txt/json/html) |
| -t     | Threads |
| -w     | Wordlist |
| -p     | Ports |
| --banner | Banner grabbing |
| -e     | File extensions |
| -r     | Recursive scan |
| -a     | Aggressive mode |
| --transfer | DNS zone transfer |

---

## Project Structure

```
Ethical-Hacker-Toolkit/
├── config/
├── core/
├── modules/
│   ├── network/
│   ├── web/
│   ├── recon/
│   └── crypto/
├── reports/
├── logs/
├── scripts/
├── tests/
└── eht.py
```

---

## Logging

Logs stored in:
```
logs/eht.log
```

Levels:
- INFO
- SUCCESS
- WARNING
- ERROR
- DEBUG

View logs:
```bash
./scripts/view_logs.sh
```

---

## Reports

Saved in:
```
reports/
```

Formats:
- TXT
- JSON
- HTML

Merge reports:
```bash
python scripts/report_merger.py
```

---

## Requirements

- Python 3.8+
- Linux / macOS / Windows (WSL recommended)
- Root privileges for some features

---

## Dependencies

- requests  
- dnspython  
- colorama  
- whois  
- cryptography  

---

## Legal Disclaimer

This toolkit is for **educational and authorized testing only**.

You may ONLY use this tool on:
- Systems you own
- Systems you have explicit permission to test

Unauthorized usage is illegal and may result in criminal charges.

The author is not responsible for misuse.

---

## License

MIT License

---

## Support

- GitHub Issues: https://github.com/JettRnh/Ethical-Hacker-Toolkit/issues
- TikTok: @jettinibos_

---

## Version

1.0.0
