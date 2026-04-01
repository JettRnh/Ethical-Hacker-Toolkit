#!/usr/bin/env python3
"""
DNS enumeration module for comprehensive DNS record discovery
Author: Jet
GitHub: https://github.com/JettRnh
"""

import dns.resolver
import dns.query
import dns.zone
import dns.reversename
import socket
import threading
from core.logger import log
from core.utils import ThreadPool

class DNSEnumerator:
    """Comprehensive DNS record enumerator"""
    
    def __init__(self, domain, nameservers=None):
        self.domain = domain
        self.nameservers = nameservers or ['8.8.8.8', '1.1.1.1']
        self.results = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': [],
            'PTR': []
        }
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.nameservers
        
        log.status(f"DNSEnumerator initialized for {domain}")
        log.info(f"Using nameservers: {self.nameservers}")
    
    def get_a_records(self):
        """Get A records (IPv4)"""
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            self.results['A'] = [str(r) for r in answers]
            log.success(f"Found {len(self.results['A'])} A records")
        except dns.resolver.NXDOMAIN:
            log.warning("Domain does not exist")
        except dns.resolver.NoAnswer:
            log.info("No A records found")
        except Exception as e:
            log.debug(f"A record error: {e}")
    
    def get_aaaa_records(self):
        """Get AAAA records (IPv6)"""
        try:
            answers = self.resolver.resolve(self.domain, 'AAAA')
            self.results['AAAA'] = [str(r) for r in answers]
            log.success(f"Found {len(self.results['AAAA'])} AAAA records")
        except:
            log.info("No AAAA records found")
    
    def get_mx_records(self):
        """Get MX records (mail exchanges)"""
        try:
            answers = self.resolver.resolve(self.domain, 'MX')
            self.results['MX'] = [(r.preference, str(r.exchange)) for r in answers]
            self.results['MX'].sort(key=lambda x: x[0])
            log.success(f"Found {len(self.results['MX'])} MX records")
        except:
            log.info("No MX records found")
    
    def get_ns_records(self):
        """Get NS records (name servers)"""
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            self.results['NS'] = [str(r) for r in answers]
            log.success(f"Found {len(self.results['NS'])} NS records")
        except:
            log.info("No NS records found")
    
    def get_txt_records(self):
        """Get TXT records (text, SPF, DKIM, etc.)"""
        try:
            answers = self.resolver.resolve(self.domain, 'TXT')
            self.results['TXT'] = [str(r) for r in answers]
            log.success(f"Found {len(self.results['TXT'])} TXT records")
        except:
            log.info("No TXT records found")
    
    def get_cname_records(self):
        """Get CNAME records (canonical name)"""
        try:
            answers = self.resolver.resolve(self.domain, 'CNAME')
            self.results['CNAME'] = [str(r) for r in answers]
            log.success(f"Found {len(self.results['CNAME'])} CNAME records")
        except:
            log.info("No CNAME records found")
    
    def get_soa_records(self):
        """Get SOA record (start of authority)"""
        try:
            answers = self.resolver.resolve(self.domain, 'SOA')
            for r in answers:
                self.results['SOA'] = {
                    'mname': str(r.mname),
                    'rname': str(r.rname),
                    'serial': r.serial,
                    'refresh': r.refresh,
                    'retry': r.retry,
                    'expire': r.expire,
                    'minimum': r.minimum
                }
            log.success("SOA record found")
        except:
            log.info("No SOA records found")
    
    def get_ptr_records(self):
        """Get PTR records (reverse DNS) - for IPs"""
        try:
            # Check if domain is actually an IP
            socket.inet_aton(self.domain)
            reverse_name = dns.reversename.from_address(self.domain)
            answers = self.resolver.resolve(reverse_name, 'PTR')
            self.results['PTR'] = [str(r) for r in answers]
            log.success(f"Found {len(self.results['PTR'])} PTR records")
        except socket.error:
            pass  # Not an IP
        except:
            pass
    
    def attempt_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)"""
        log.progress("Attempting zone transfer...")
        
        ns_servers = self.results.get('NS', [])
        if not ns_servers:
            self.get_ns_records()
            ns_servers = self.results.get('NS', [])
        
        zone_records = []
        
        for ns in ns_servers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                for name, node in zone.nodes.items():
                    for rdtype, rdataset in node.rdatasets.items():
                        for rdata in rdataset:
                            zone_records.append({
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdtype),
                                'data': str(rdata)
                            })
                
                if zone_records:
                    log.success(f"Zone transfer successful from {ns}")
                    break
                    
            except dns.exception.TransferError:
                log.debug(f"Zone transfer refused by {ns}")
            except Exception as e:
                log.debug(f"Zone transfer error from {ns}: {e}")
        
        return zone_records
    
    def enumerate_all(self):
        """Enumerate all DNS record types"""
        log.progress(f"Enumerating DNS records for {self.domain}")
        
        self.get_a_records()
        self.get_aaaa_records()
        self.get_mx_records()
        self.get_ns_records()
        self.get_txt_records()
        self.get_cname_records()
        self.get_soa_records()
        self.get_ptr_records()
        
        return self.results
    
    def get_report(self):
        """Generate DNS enumeration report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("DNS ENUMERATION REPORT")
        lines.append("=" * 70)
        lines.append(f"Domain: {self.domain}")
        lines.append("=" * 70)
        
        # A Records
        if self.results['A']:
            lines.append("\n[A] Records (IPv4):")
            for record in self.results['A']:
                lines.append(f"  - {record}")
        
        # AAAA Records
        if self.results['AAAA']:
            lines.append("\n[AAAA] Records (IPv6):")
            for record in self.results['AAAA']:
                lines.append(f"  - {record}")
        
        # MX Records
        if self.results['MX']:
            lines.append("\n[MX] Mail Exchangers:")
            for pref, exchange in self.results['MX']:
                lines.append(f"  - {pref} {exchange}")
        
        # NS Records
        if self.results['NS']:
            lines.append("\n[NS] Name Servers:")
            for record in self.results['NS']:
                lines.append(f"  - {record}")
        
        # TXT Records
        if self.results['TXT']:
            lines.append("\n[TXT] Text Records:")
            for record in self.results['TXT']:
                lines.append(f"  - {record[:100]}...")
        
        # CNAME Records
        if self.results['CNAME']:
            lines.append("\n[CNAME] Canonical Names:")
            for record in self.results['CNAME']:
                lines.append(f"  - {record}")
        
        # SOA Record
        if self.results['SOA']:
            soa = self.results['SOA']
            lines.append("\n[SOA] Start of Authority:")
            lines.append(f"  - Primary NS: {soa['mname']}")
            lines.append(f"  - Responsible: {soa['rname']}")
            lines.append(f"  - Serial: {soa['serial']}")
            lines.append(f"  - Refresh: {soa['refresh']}s")
            lines.append(f"  - Retry: {soa['retry']}s")
            lines.append(f"  - Expire: {soa['expire']}s")
            lines.append(f"  - Minimum TTL: {soa['minimum']}s")
        
        lines.append("\n" + "=" * 70)
        return "\n".join(lines)
