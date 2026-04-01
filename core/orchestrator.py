#!/usr/bin/env python3
"""
Orchestrator - Central pipeline for security assessments
Author: Jet
"""

import time
from datetime import datetime
from core.logger import log
from core.reporter import Reporter
from modules.network import PortScanner
from modules.recon import DNSEnumerator, WhoisLookup, EmailHarvester
from modules.web import HeadersAnalyzer, DirBruteforce
from config.settings import WORDLIST_DIR

class ReconPipeline:
    """Orchestrates multiple reconnaissance modules into a single workflow"""

    def __init__(self, target, output_format="txt"):
        self.target = target
        self.output_format = output_format
        self.results = {}
        self.start_time = None
        self.end_time = None

    def run(self, modules=None):
        """Run selected modules (or all by default)"""
        if modules is None:
            modules = ["dns", "whois", "port", "web", "email"]

        self.start_time = datetime.now()
        log.status(f"Starting orchestrated assessment on {self.target}")
        log.info(f"Modules: {', '.join(modules)}")

        # DNS enumeration
        if "dns" in modules:
            self._run_dns()

        # WHOIS lookup
        if "whois" in modules:
            self._run_whois()

        # Port scan
        if "port" in modules:
            self._run_port_scan()

        # Web analysis (if HTTP ports found)
        if "web" in modules:
            self._run_web_analysis()

        # Email harvesting
        if "email" in modules:
            self._run_email()

        self.end_time = datetime.now()
        log.success(f"Assessment completed in {(self.end_time - self.start_time).total_seconds():.2f}s")

        return self.results

    def _run_dns(self):
        log.progress("Running DNS enumeration...")
        dns = DNSEnumerator(self.target)
        self.results["dns"] = dns.enumerate_all()
        log.success("DNS enumeration done")

    def _run_whois(self):
        log.progress("Running WHOIS lookup...")
        whois = WhoisLookup(self.target)
        self.results["whois"] = whois.lookup()
        log.success("WHOIS lookup done")

    def _run_port_scan(self):
        log.progress("Running port scan...")
        scanner = PortScanner(self.target)
        self.results["ports"] = scanner.scan_common_ports()
        log.success(f"Port scan done: {len(self.results['ports'])} open ports")

    def _run_web_analysis(self):
        # Determine if web ports are open
        web_ports = [80, 443, 8080, 8443]
        open_ports = [p['port'] for p in self.results.get("ports", [])]
        http_port = None
        for port in web_ports:
            if port in open_ports:
                http_port = port
                break

        if not http_port:
            log.info("No web services detected, skipping web analysis")
            return

        url = f"http://{self.target}" if http_port != 443 else f"https://{self.target}"
        if http_port not in [80, 443]:
            url += f":{http_port}"

        log.progress(f"Running web analysis on {url}")

        # Headers analysis
        headers = HeadersAnalyzer(url)
        self.results["headers"] = headers.analyze()

        # Directory brute-force (optional, can be heavy)
        wordlist = WORDLIST_DIR / "directories.txt"
        if wordlist.exists():
            dir_scan = DirBruteforce(url, str(wordlist), threads=30)
            self.results["directories"] = dir_scan.run()

        log.success("Web analysis done")

    def _run_email(self):
        log.progress("Harvesting emails...")
        harvester = EmailHarvester(self.target)
        self.results["emails"] = harvester.harvest_from_url(f"http://{self.target}")
        log.success(f"Email harvest done: {len(self.results['emails'])} found")

    def generate_report(self):
        """Create a unified report from all results"""
        reporter = Reporter("orchestrated", self.output_format)

        # Build a human-readable summary
        summary = []
        summary.append("=" * 70)
        summary.append(f"TARGET: {self.target}")
        summary.append(f"START: {self.start_time}")
        summary.append(f"END: {self.end_time}")
        summary.append("=" * 70)

        # DNS summary
        if "dns" in self.results:
            dns = self.results["dns"]
            summary.append("\n[DNS]")
            if dns.get("A"):
                summary.append(f"  A records: {len(dns['A'])}")
            if dns.get("NS"):
                summary.append(f"  NS records: {len(dns['NS'])}")
            if dns.get("MX"):
                summary.append(f"  MX records: {len(dns['MX'])}")

        # Port scan summary
        if "ports" in self.results:
            ports = self.results["ports"]
            summary.append(f"\n[PORTS] {len(ports)} open ports")
            for p in ports[:10]:  # Show first 10
                summary.append(f"  {p['port']}/{p['service']}")

        # Headers summary
        if "headers" in self.results:
            issues = self.results["headers"].get("issues", [])
            if issues:
                summary.append(f"\n[WEB SECURITY] {len(issues)} issues found")
                for issue in issues[:5]:
                    summary.append(f"  - {issue['message']}")

        # Emails
        if "emails" in self.results:
            emails = self.results["emails"]
            summary.append(f"\n[EMAILS] {len(emails)} found")
            for email in emails[:10]:
                summary.append(f"  {email}")

        reporter.add_result("\n".join(summary))

        # Also add detailed results from each module (optional)
        # Here you could append full JSON dumps, etc.

        filepath = reporter.save()
        log.success(f"Report saved to {filepath}")
        return filepath
