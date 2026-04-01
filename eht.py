#!/usr/bin/env python3
"""
Ethical Hacker Toolkit - Main Entry Point
Professional Security Testing Framework

Author: Jet
GitHub: https://github.com/JettRnh
TikTok: @jettinibos_
"""

import argparse
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.logger import log
from core.reporter import Reporter
from modules.network import PortScanner, PingSweep, Traceroute
from modules.web import DirBruteforce, SubdomainEnum, HeadersAnalyzer, SQLInjection
from modules.recon import WhoisLookup, DNSEnumerator, EmailHarvester
from modules.crypto import HashCracker, Encryption
from config.settings import WORDLIST_DIR, AUTHOR, GITHUB, TIKTOK


def print_banner():
    """Print toolkit banner"""
    print()
    print("Ethical Hacker Toolkit v1.0")
    print("Security Testing Framework")
    print(f"Author: {AUTHOR}")
    print(f"GitHub: {GITHUB}")
    print(f"TikTok: {TIKTOK}")
    print()


def setup_argparse():
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Ethical Hacker Toolkit - Professional Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  eht scan 192.168.1.1 -p 1-1000 --banner
  eht ping 192.168.1.0/24
  eht trace google.com
  eht dir http://example.com -w wordlist.txt
  eht subdomain example.com -w subdomains.txt
  eht headers https://example.com
  eht sql http://example.com/page?id=1
  eht whois example.com
  eht dns example.com
  eht email example.com -u https://example.com
  eht crack 5f4dcc3b5aa765d61d8327deb882cf99 md5 -w wordlist.txt
  eht encode "Hello World" --base64
  eht all example.com -o html
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Network commands
    scan_parser = subparsers.add_parser("scan", help="Port scan target")
    scan_parser.add_argument("target", help="Target IP or hostname")
    scan_parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1000 or 80,443,8080)")
    scan_parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    scan_parser.add_argument("--banner", action="store_true", help="Grab service banners")
    scan_parser.add_argument("-o", "--output", choices=["txt", "json", "html"], default="txt", help="Output format")
    
    ping_parser = subparsers.add_parser("ping", help="Ping sweep network")
    ping_parser.add_argument("network", help="Network (e.g., 192.168.1.0/24)")
    ping_parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    ping_parser.add_argument("--arp", action="store_true", help="Use ARP ping (Linux only)")
    
    trace_parser = subparsers.add_parser("trace", help="Traceroute to target")
    trace_parser.add_argument("target", help="Target IP or hostname")
    trace_parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum hops")
    
    # Web commands
    dir_parser = subparsers.add_parser("dir", help="Directory brute-force")
    dir_parser.add_argument("url", help="Target URL")
    dir_parser.add_argument("-w", "--wordlist", default=str(WORDLIST_DIR / "directories.txt"), help="Wordlist path")
    dir_parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    dir_parser.add_argument("-e", "--extensions", help="File extensions (comma separated)")
    dir_parser.add_argument("-r", "--recursive", action="store_true", help="Recursive scan")
    
    subdomain_parser = subparsers.add_parser("subdomain", help="Subdomain enumeration")
    subdomain_parser.add_argument("domain", help="Target domain")
    subdomain_parser.add_argument("-w", "--wordlist", default=str(WORDLIST_DIR / "subdomains.txt"), help="Wordlist path")
    subdomain_parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    subdomain_parser.add_argument("-a", "--aggressive", action="store_true", help="Aggressive mode")
    
    headers_parser = subparsers.add_parser("headers", help="Analyze HTTP headers")
    headers_parser.add_argument("url", help="Target URL")
    
    sql_parser = subparsers.add_parser("sql", help="SQL injection scan")
    sql_parser.add_argument("url", help="Target URL with parameters")
    sql_parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET", help="Request method")
    sql_parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    
    # Recon commands
    whois_parser = subparsers.add_parser("whois", help="WHOIS lookup")
    whois_parser.add_argument("target", help="Domain or IP address")
    
    dns_parser = subparsers.add_parser("dns", help="DNS enumeration")
    dns_parser.add_argument("domain", help="Target domain")
    dns_parser.add_argument("--transfer", action="store_true", help="Attempt zone transfer")
    
    email_parser = subparsers.add_parser("email", help="Email harvester")
    email_parser.add_argument("domain", help="Target domain")
    email_parser.add_argument("-u", "--url", help="URL to scrape")
    email_parser.add_argument("-f", "--file", help="Local file to parse")
    email_parser.add_argument("-c", "--crawl", action="store_true", help="Crawl website")
    email_parser.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl")
    
    # Crypto commands
    crack_parser = subparsers.add_parser("crack", help="Hash cracker")
    crack_parser.add_argument("hash", help="Target hash")
    crack_parser.add_argument("type", choices=["md5", "md4", "sha1", "sha256", "sha512", "ntlm"], help="Hash type")
    crack_parser.add_argument("-w", "--wordlist", help="Wordlist path")
    crack_parser.add_argument("-r", "--rules", action="store_true", help="Use rule-based attack")
    crack_parser.add_argument("-b", "--bruteforce", action="store_true", help="Use brute-force attack")
    crack_parser.add_argument("--max-length", type=int, default=4, help="Max length for brute-force")
    crack_parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    
    encode_parser = subparsers.add_parser("encode", help="Encoding utilities")
    encode_parser.add_argument("text", help="Text to encode")
    encode_parser.add_argument("--base64", action="store_true", help="Base64 encode")
    encode_parser.add_argument("--hex", action="store_true", help="Hex encode")
    encode_parser.add_argument("--url", action="store_true", help="URL encode")
    encode_parser.add_argument("--rot13", action="store_true", help="ROT13 cipher")
    encode_parser.add_argument("--caesar", type=int, help="Caesar cipher shift")
    encode_parser.add_argument("--hash", choices=["md5", "sha1", "sha256", "sha512"], help="Hash text")
    
    # Full scan command
    all_parser = subparsers.add_parser("all", help="Run all tests against target")
    all_parser.add_argument("target", help="Target IP or domain")
    all_parser.add_argument("-o", "--output", choices=["txt", "json", "html"], default="txt", help="Output format")
    
    return parser


def handle_network_commands(args, reporter):
    """Handle network-related commands"""
    if args.command == "scan":
        scanner = PortScanner(args.target, threads=args.threads)
        
        if "--" in args.ports or "-" in args.ports:
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
                if args.banner:
                    results = scanner.scan_with_banner(start, end)
                else:
                    results = scanner.scan_range(start, end)
            else:
                ports = [int(p) for p in args.ports.split(",")]
                results = []
                for port in ports:
                    result = scanner.scan_single_port(port)
                    if result:
                        results.append(result)
                        scanner.add_result(result)
        else:
            if args.banner:
                results = scanner.scan_common_with_banner()
            else:
                results = scanner.scan_common_ports()
        
        report = scanner.full_report() if args.banner else str(scanner.get_summary())
        reporter.add_result(report)
        
        if args.output:
            filepath = reporter.save(args.output)
            log.success(f"Report saved to {filepath}")
        else:
            print(report)
    
    elif args.command == "ping":
        sweeper = PingSweep(args.network, threads=args.threads)
        results = sweeper.scan()
        report = sweeper.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "trace":
        tracer = Traceroute(args.target, max_hops=args.max_hops)
        results = tracer.trace()
        report = tracer.get_report()
        reporter.add_result(report)
        print(report)


def handle_web_commands(args, reporter):
    """Handle web-related commands"""
    if args.command == "dir":
        extensions = None
        if args.extensions:
            extensions = [ext.strip() for ext in args.extensions.split(",")]
        
        bruteforcer = DirBruteforce(
            args.url, args.wordlist, args.threads, 
            extensions, args.recursive
        )
        results = bruteforcer.run()
        report = bruteforcer.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "subdomain":
        enumerator = SubdomainEnum(args.domain, args.wordlist, args.threads)
        results = enumerator.run(aggressive=args.aggressive)
        report = enumerator.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "headers":
        analyzer = HeadersAnalyzer(args.url)
        results = analyzer.analyze()
        report = analyzer.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "sql":
        injector = SQLInjection(args.url, method=args.method, threads=args.threads)
        results = injector.scan()
        report = injector.get_report()
        reporter.add_result(report)
        print(report)


def handle_recon_commands(args, reporter):
    """Handle reconnaissance commands"""
    if args.command == "whois":
        lookup = WhoisLookup(args.target)
        results = lookup.lookup()
        report = lookup.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "dns":
        enumerator = DNSEnumerator(args.domain)
        results = enumerator.enumerate_all()
        
        if args.transfer:
            zone = enumerator.attempt_zone_transfer()
            if zone:
                reporter.add_result(f"Zone transfer results: {len(zone)} records")
        
        report = enumerator.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "email":
        harvester = EmailHarvester(args.domain)
        
        if args.url:
            results = harvester.harvest_from_url(args.url)
        elif args.file:
            results = harvester.harvest_from_file(args.file)
        elif args.crawl:
            results = harvester.crawl_website(f"http://{args.domain}", max_pages=args.max_pages)
        else:
            results = harvester.harvest_from_url(f"http://{args.domain}")
        
        report = harvester.get_report()
        reporter.add_result(report)
        print(report)


def handle_crypto_commands(args, reporter):
    """Handle crypto commands"""
    if args.command == "crack":
        cracker = HashCracker(args.hash, args.type, args.wordlist, threads=args.threads)
        
        if args.bruteforce:
            result = cracker.brute_force_attack(max_length=args.max_length)
        elif args.rules or args.wordlist:
            if args.rules and args.wordlist:
                result = cracker.rule_based_attack()
            else:
                result = cracker.dictionary_attack()
        else:
            log.error("Need wordlist or rules for cracking")
            return
        
        report = cracker.get_report()
        reporter.add_result(report)
        print(report)
    
    elif args.command == "encode":
        crypto = Encryption()
        
        if args.base64:
            result = crypto.base64_encode(args.text)
            print(f"Base64: {result}")
            reporter.add_result(f"Base64: {result}")
        
        if args.hex:
            result = crypto.hex_encode(args.text)
            print(f"Hex: {result}")
            reporter.add_result(f"Hex: {result}")
        
        if args.url:
            result = crypto.url_encode(args.text)
            print(f"URL Encoded: {result}")
            reporter.add_result(f"URL Encoded: {result}")
        
        if args.rot13:
            result = crypto.rot13(args.text)
            print(f"ROT13: {result}")
            reporter.add_result(f"ROT13: {result}")
        
        if args.caesar:
            result = crypto.caesar_cipher(args.text, args.caesar)
            print(f"Caesar (shift {args.caesar}): {result}")
            reporter.add_result(f"Caesar (shift {args.caesar}): {result}")
        
        if args.hash:
            if args.hash == "md5":
                result = crypto.hash_md5(args.text)
            elif args.hash == "sha1":
                result = crypto.hash_sha1(args.text)
            elif args.hash == "sha256":
                result = crypto.hash_sha256(args.text)
            elif args.hash == "sha512":
                result = crypto.hash_sha512(args.text)
            print(f"{args.hash.upper()}: {result}")
            reporter.add_result(f"{args.hash.upper()}: {result}")


def handle_full_scan(args, reporter):
    """Run full security assessment"""
    target = args.target
    log.status(f"Starting full security assessment on {target}")
    
    # DNS enumeration
    log.progress("[1/5] DNS enumeration")
    try:
        dns_enum = DNSEnumerator(target)
        dns_results = dns_enum.enumerate_all()
        reporter.add_result(dns_enum.get_report())
        log.success("DNS enumeration completed")
    except Exception as e:
        log.error(f"DNS enumeration failed: {e}")
    
    # WHOIS lookup
    log.progress("[2/5] WHOIS lookup")
    try:
        whois_lookup = WhoisLookup(target)
        whois_results = whois_lookup.lookup()
        reporter.add_result(whois_lookup.get_report())
        log.success("WHOIS lookup completed")
    except Exception as e:
        log.error(f"WHOIS lookup failed: {e}")
    
    # Port scan
    log.progress("[3/5] Port scan")
    try:
        scanner = PortScanner(target)
        scan_results = scanner.scan_common_ports()
        reporter.add_result(scanner.get_summary())
        log.success(f"Port scan completed, found {len(scan_results)} open ports")
    except Exception as e:
        log.error(f"Port scan failed: {e}")
    
    # Web scan if HTTP ports open
    http_ports = [80, 443, 8080, 8443]
    has_http = any(r.get('port') in http_ports for r in scan_results) if scan_results else False
    
    if has_http:
        log.progress("[4/5] Web analysis")
        url = f"http://{target}"
        if 443 in [r.get('port') for r in scan_results]:
            url = f"https://{target}"
        
        try:
            headers_analyzer = HeadersAnalyzer(url)
            headers_analyzer.analyze()
            reporter.add_result(headers_analyzer.get_report())
            
            wordlist = WORDLIST_DIR / "directories.txt"
            if wordlist.exists():
                bruteforcer = DirBruteforce(url, str(wordlist), threads=30)
                dir_results = bruteforcer.run()
                reporter.add_result(f"Directory scan found {len(dir_results)} items")
            
            log.success("Web analysis completed")
        except Exception as e:
            log.error(f"Web analysis failed: {e}")
    else:
        log.info("No HTTP services detected, skipping web analysis")
    
    # Email harvesting
    log.progress("[5/5] Email harvesting")
    try:
        harvester = EmailHarvester(target)
        email_results = harvester.harvest_from_url(f"http://{target}")
        reporter.add_result(harvester.get_report())
        log.success(f"Email harvesting completed, found {len(email_results)} emails")
    except Exception as e:
        log.error(f"Email harvesting failed: {e}")
    
    # Save report
    filepath = reporter.save(args.output)
    log.success(f"Full assessment report saved to {filepath}")


def main():
    """Main entry point"""
    print_banner()
    
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    reporter = Reporter(args.command, getattr(args, 'output', 'txt'))
    
    try:
        if args.command in ['scan', 'ping', 'trace']:
            handle_network_commands(args, reporter)
        
        elif args.command in ['dir', 'subdomain', 'headers', 'sql']:
            handle_web_commands(args, reporter)
        
        elif args.command in ['whois', 'dns', 'email']:
            handle_recon_commands(args, reporter)
        
        elif args.command in ['crack', 'encode']:
            handle_crypto_commands(args, reporter)
        
        elif args.command == 'all':
            handle_full_scan(args, reporter)
        
        else:
            log.error(f"Unknown command: {args.command}")
            parser.print_help()
            sys.exit(1)
    
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        log.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
