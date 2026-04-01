#!/usr/bin/env python3
"""
Ethical Hacker Toolkit - CLI Pro
Author: Jet
GitHub: https://github.com/JettRnh
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.logger import log
from core.orchestrator import ReconPipeline
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

def create_parser():
    parser = argparse.ArgumentParser(description="Ethical Hacker Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Auto mode (orchestrator)
    auto_parser = subparsers.add_parser("auto", help="Run full automated assessment")
    auto_parser.add_argument("target", help="Target IP or domain")
    auto_parser.add_argument("-o", "--output", choices=["txt", "json", "html"], default="txt")
    auto_parser.add_argument("--skip", help="Comma-separated modules to skip (dns,whois,port,web,email)")

    # Network commands
    scan_parser = subparsers.add_parser("scan", help="Port scan")
    scan_parser.add_argument("target")
    scan_parser.add_argument("-p", "--ports", default="1-1024")
    scan_parser.add_argument("-t", "--threads", type=int, default=100)
    scan_parser.add_argument("--banner", action="store_true")
    scan_parser.add_argument("-o", "--output", choices=["txt", "json", "html"], default="txt")

    ping_parser = subparsers.add_parser("ping", help="Ping sweep")
    ping_parser.add_argument("network")
    ping_parser.add_argument("-t", "--threads", type=int, default=100)

    trace_parser = subparsers.add_parser("trace", help="Traceroute")
    trace_parser.add_argument("target")
    trace_parser.add_argument("-m", "--max-hops", type=int, default=30)

    # Web commands
    dir_parser = subparsers.add_parser("dir", help="Directory brute-force")
    dir_parser.add_argument("url")
    dir_parser.add_argument("-w", "--wordlist", default=str(WORDLIST_DIR / "directories.txt"))
    dir_parser.add_argument("-t", "--threads", type=int, default=50)
    dir_parser.add_argument("-e", "--extensions", help="Comma-separated extensions")

    subdomain_parser = subparsers.add_parser("subdomain", help="Subdomain enumeration")
    subdomain_parser.add_argument("domain")
    subdomain_parser.add_argument("-w", "--wordlist", default=str(WORDLIST_DIR / "subdomains.txt"))
    subdomain_parser.add_argument("-t", "--threads", type=int, default=50)

    headers_parser = subparsers.add_parser("headers", help="Analyze HTTP headers")
    headers_parser.add_argument("url")

    sql_parser = subparsers.add_parser("sql", help="SQL injection scan")
    sql_parser.add_argument("url")
    sql_parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET")

    # Recon commands
    whois_parser = subparsers.add_parser("whois", help="WHOIS lookup")
    whois_parser.add_argument("target")

    dns_parser = subparsers.add_parser("dns", help="DNS enumeration")
    dns_parser.add_argument("domain")
    dns_parser.add_argument("--transfer", action="store_true")

    email_parser = subparsers.add_parser("email", help="Email harvester")
    email_parser.add_argument("domain")
    email_parser.add_argument("-u", "--url", help="URL to scrape")
    email_parser.add_argument("-f", "--file", help="Local file to parse")

    # Crypto commands
    crack_parser = subparsers.add_parser("crack", help="Hash cracker")
    crack_parser.add_argument("hash")
    crack_parser.add_argument("type", choices=["md5", "sha1", "sha256", "sha512", "ntlm"])
    crack_parser.add_argument("-w", "--wordlist", required=True)
    crack_parser.add_argument("-t", "--threads", type=int, default=50)

    encode_parser = subparsers.add_parser("encode", help="Encoding utilities")
    encode_parser.add_argument("text")
    encode_parser.add_argument("--base64", action="store_true")
    encode_parser.add_argument("--hex", action="store_true")
    encode_parser.add_argument("--rot13", action="store_true")

    return parser

def main():
    print_banner()
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "auto":
            skip = args.skip.split(",") if args.skip else []
            modules = [m for m in ["dns", "whois", "port", "web", "email"] if m not in skip]
            pipeline = ReconPipeline(args.target, output_format=args.output)
            pipeline.run(modules=modules)
            pipeline.generate_report()

        elif args.command == "scan":
            scanner = PortScanner(args.target, threads=args.threads)
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
                scanner.scan_range(start, end)
            else:
                ports = [int(p) for p in args.ports.split(",")]
                for port in ports:
                    scanner.scan_single_port(port)
            if args.banner:
                scanner.scan_with_banner()
            print(scanner.full_report())

        elif args.command == "ping":
            sweeper = PingSweep(args.network, threads=args.threads)
            sweeper.scan()
            print(sweeper.get_report())

        elif args.command == "trace":
            tracer = Traceroute(args.target, max_hops=args.max_hops)
            tracer.trace()
            print(tracer.get_report())

        elif args.command == "dir":
            extensions = args.extensions.split(",") if args.extensions else None
            bruteforcer = DirBruteforce(args.url, args.wordlist, args.threads, extensions)
            bruteforcer.run()
            print(bruteforcer.get_report())

        elif args.command == "subdomain":
            enumerator = SubdomainEnum(args.domain, args.wordlist, args.threads)
            enumerator.run()
            print(enumerator.get_report())

        elif args.command == "headers":
            analyzer = HeadersAnalyzer(args.url)
            analyzer.analyze()
            print(analyzer.get_report())

        elif args.command == "sql":
            injector = SQLInjection(args.url, method=args.method)
            injector.scan()
            print(injector.get_report())

        elif args.command == "whois":
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
            else:
                harvester.harvest_from_url(f"http://{args.domain}")
            print(harvester.get_report())

        elif args.command == "crack":
            cracker = HashCracker(args.hash, args.type, args.wordlist, threads=args.threads)
            cracker.dictionary_attack()
            print(cracker.get_report())

        elif args.command == "encode":
            crypto = Encryption()
            if args.base64:
                print(f"Base64: {crypto.base64_encode(args.text)}")
            if args.hex:
                print(f"Hex: {crypto.hex_encode(args.text)}")
            if args.rot13:
                print(f"ROT13: {crypto.rot13(args.text)}")

    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        log.error(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
