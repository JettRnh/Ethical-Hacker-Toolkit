#!/usr/bin/env python3
"""
Ethical Hacker Toolkit - Main Entry Point
Author: Jet
GitHub: https://github.com/JettRnh
TikTok: @jettinibos_
"""

import argparse
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.logger import log
from core.reporter import Reporter
from modules.network import PortScanner, PingSweep, Traceroute
from modules.web import DirBruteforce, SubdomainEnum, HeadersAnalyzer, SQLInjection
from modules.recon import WhoisLookup, DNSEnumerator, EmailHarvester
from modules.crypto import HashCracker, Encryption
from config.settings import WORDLIST_DIR, AUTHOR, GITHUB, TIKTOK

def print_banner():
    print()
    print("Ethical Hacker Toolkit v1.0")
    print(f"Author: {AUTHOR}")
    print(f"GitHub: {GITHUB}")
    print(f"TikTok: {TIKTOK}")
    print()

def show_system_info():
    """Show system information and threading capabilities"""
    from core.adaptive import get_system_info, get_max_safe_threads, get_recommended_threads
    
    info = get_system_info()
    print("\nSystem Information")
    print("=" * 40)
    print(f"CPU Cores: {info['cpu_count']}")
    print(f"System: {info['system']}")
    print(f"Machine: {info['machine']}")
    print(f"Limited Environment: {info['is_limited']}")
    print(f"Max Safe Threads: {get_max_safe_threads()}")
    print()
    print("Recommended Threads by Task:")
    print(f"  Network: {get_recommended_threads('network')}")
    print(f"  Web: {get_recommended_threads('web')}")
    print(f"  Crypto: {get_recommended_threads('crypto')}")
    print()

def setup_argparse():
    parser = argparse.ArgumentParser(
        description="Ethical Hacker Toolkit - Professional Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show system information")
    
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
    if args.command == "scan":
        scanner = PortScanner(args.target, threads=args.threads)
        
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
            if args.banner:
                scanner.scan_with_banner(start, end)
            else:
                scanner.scan_range(start, end)
        else:
            ports = [int(p) for p in args.ports.split(",")]
            for port in ports:
                scanner.scan_single_port(port)
        
        print(scanner.full_report() if args.banner else scanner.get_summary())
    
    elif args.command == "ping":
        sweeper = PingSweep(args.network, threads=args.threads)
        sweeper.scan()
        print(sweeper.get_report())
    
    elif args.command == "trace":
        tracer = Traceroute(args.target, max_hops=args.max_hops)
        tracer.trace()
        print(tracer.get_report())

def handle_web_commands(args, reporter):
    if args.command == "dir":
        extensions = args.extensions.split(",") if args.extensions else None
        bruteforcer = DirBruteforce(args.url, args.wordlist, args.threads, extensions, args.recursive)
        bruteforcer.run()
        print(bruteforcer.get_report())
    
    elif args.command == "subdomain":
        enumerator = SubdomainEnum(args.domain, args.wordlist, args.threads)
        enumerator.run(aggressive=args.aggressive)
        print(enumerator.get_report())
    
    elif args.command == "headers":
        analyzer = HeadersAnalyzer(args.url)
        analyzer.analyze()
        print(analyzer.get_report())
    
    elif args.command == "sql":
        injector = SQLInjection(args.url, method=args.method, threads=args.threads)
        injector.scan()
        print(injector.get_report())

def handle_recon_commands(args, reporter):
    if args.command == "whois":
        lookup = WhoisLookup(args.target)
        lookup.lookup()
        print(lookup.get_report())
    
    elif args.command == "dns":
        dns = DNSEnumerator(args.domain)
        dns.enumerate_all()
        if args.transfer:
            zone = dns.attempt_zone_transfer()
            print(f"Zone transfer: {len(zone)} records")
        print(dns.get_report())
    
    elif args.command == "email":
        harvester = EmailHarvester(args.domain)
        if args.url:
            harvester.harvest_from_url(args.url)
        elif args.file:
            harvester.harvest_from_file(args.file)
        elif args.crawl:
            harvester.crawl_website(f"http://{args.domain}", max_pages=args.max_pages)
        else:
            harvester.harvest_from_url(f"http://{args.domain}")
        print(harvester.get_report())

def handle_crypto_commands(args, reporter):
    if args.command == "crack":
        cracker = HashCracker(args.hash, args.type, args.wordlist, threads=args.threads)
        
        if args.bruteforce:
            cracker.brute_force_attack(max_length=args.max_length)
        elif args.rules or args.wordlist:
            if args.rules and args.wordlist:
                cracker.rule_based_attack()
            else:
                cracker.dictionary_attack()
        else:
            log.error("Need wordlist or rules for cracking")
            return
        
        print(cracker.get_report())
    
    elif args.command == "encode":
        crypto = Encryption()
        
        if args.base64:
            print(f"Base64: {crypto.base64_encode(args.text)}")
        if args.hex:
            print(f"Hex: {crypto.hex_encode(args.text)}")
        if args.url:
            print(f"URL Encoded: {crypto.url_encode(args.text)}")
        if args.rot13:
            print(f"ROT13: {crypto.rot13(args.text)}")
        if args.caesar:
            print(f"Caesar (shift {args.caesar}): {crypto.caesar_cipher(args.text, args.caesar)}")
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

def handle_full_scan(args, reporter):
    from core.orchestrator import ReconPipeline
    
    log.status(f"Starting full security assessment on {args.target}")
    pipeline = ReconPipeline(args.target, output_format=args.output)
    pipeline.run()
    pipeline.generate_report()

def main():
    print_banner()
    
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Handle info command
    if args.command == "info":
        show_system_info()
        return
    
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
