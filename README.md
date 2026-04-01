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
# Show system info
eht info

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

# Encoding utilities
eht encode "Hello World" --base64 --hex --rot13

# Full assessment
eht all example.com -o html
```

---

## Commands Reference

### Info
| Command | Description |
|--------|------------|
| eht info | Show system information |

### Network
| Command | Description | Example |
|--------|------------|--------|
| scan | Port scan | eht scan 192.168.1.1 -p 1-1000 |
| ping | Network discovery | eht ping 192.168.1.0/24 |
| trace | Traceroute | eht trace google.com |

### Web
| Command | Description | Example |
|--------|------------|--------|
| dir | Directory brute-force | eht dir http://example.com |
| subdomain | Subdomain scan | eht subdomain example.com |
| headers | Header analysis | eht headers https://example.com |
| sql | SQL testing | eht sql "http://example.com?id=1" |

### Recon
| Command | Description |
|--------|------------|
| whois | WHOIS lookup |
| dns | DNS enumeration |
| email | Email harvesting |

### Crypto
| Command | Description |
|--------|------------|
| crack | Hash cracking |
| encode | Encoding tools |

### Full
| Command | Description |
|--------|------------|
| all | Run all modules |

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

## Adaptive Threading

The toolkit automatically adjusts threads based on system capability:

- Mobile / Termux → up to 200 threads  
- Desktop / Server → up to 1000 threads  

### Override

```bash
export EHT_DISABLE_ADAPTIVE=1
export EHT_MAX_THREADS=200
```

---

## Logging

Logs:
```
logs/eht.log
```

Levels:
- INFO
- SUCCESS
- WARNING
- ERROR
- DEBUG

View:
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

Merge:
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
- Systems you have explicit permission

Unauthorized use is illegal.

The author is not responsible for misuse.

---

## License

MIT License

---

## Support

- Issues: https://github.com/JettRnh/Ethical-Hacker-Toolkit/issues
- TikTok: @jettinibos_

---

## Version

1.0.0
