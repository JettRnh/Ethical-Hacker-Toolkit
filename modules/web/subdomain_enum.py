#!/usr/bin/env python3
"""
Subdomain enumeration module for web applications
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import dns.resolver
import dns.exception
import threading
from core.logger import log
from core.utils import ThreadPool, RateLimiter
from config.settings import DEFAULT_TIMEOUT

class SubdomainEnum:
    """Subdomain enumerator for target domain"""
    
    def __init__(self, domain, wordlist, threads=50, resolve=True):
        self.domain = domain.lower()
        self.wordlist = wordlist
        
        # SAFE: Use adaptive threading
        try:
            from core.adaptive import adapt_thread_count
            self.threads = adapt_thread_count(threads, max_limit=200)
        except Exception:
            self.threads = min(threads, 200)
        
        self.resolve = resolve
        self.found = []
        self.lock = threading.Lock()
        self.rate_limiter = RateLimiter(100)
        
        log.status(f"SubdomainEnum initialized for {domain}")
        log.info(f"Threads: {self.threads}, DNS Resolution: {resolve}")
    
    def _read_wordlist(self):
        """Read subdomain wordlist"""
        subdomains = []
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            log.error(f"Wordlist not found: {self.wordlist}")
            return []
        
        log.info(f"Loaded {len(subdomains)} subdomain candidates")
        return subdomains
    
    def check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        full_domain = f"{subdomain}.{self.domain}"
        
        if self.resolve:
            try:
                with self.rate_limiter:
                    ip = socket.gethostbyname(full_domain)
                
                result = {
                    'subdomain': full_domain,
                    'ip': ip,
                    'resolved': True
                }
                with self.lock:
                    self.found.append(result)
                log.success(f"Found: {full_domain} -> {ip}")
                return result
                
            except socket.gaierror:
                pass
            except Exception as e:
                log.debug(f"Error checking {full_domain}: {e}")
        else:
            # Just check if domain exists via DNS query
            try:
                dns.resolver.resolve(full_domain, 'A')
                result = {
                    'subdomain': full_domain,
                    'ip': None,
                    'resolved': False
                }
                with self.lock:
                    self.found.append(result)
                log.success(f"Found: {full_domain}")
                return result
            except:
                pass
        
        return None
    
    def check_subdomain_bruteforce(self, subdomain):
        """Check subdomain with brute-force approach (more aggressive)"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for answer in answers:
                result = {
                    'subdomain': full_domain,
                    'ip': str(answer),
                    'resolved': True,
                    'method': 'dns'
                }
                with self.lock:
                    self.found.append(result)
                log.success(f"Found: {full_domain} -> {str(answer)}")
                return result
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.Timeout:
            log.debug(f"DNS timeout for {full_domain}")
        except Exception as e:
            log.debug(f"Error checking {full_domain}: {e}")
        
        return None
    
    def run(self, aggressive=False):
        """Execute subdomain enumeration"""
        log.progress(f"Starting subdomain enumeration for {self.domain}")
        
        subdomains = self._read_wordlist()
        if not subdomains:
            return []
        
        log.info(f"Checking {len(subdomains)} subdomains...")
        
        pool = ThreadPool(self.threads)
        
        if aggressive:
            check_func = self.check_subdomain_bruteforce
        else:
            check_func = self.check_subdomain
        
        for subdomain in subdomains:
            pool.submit(check_func, args=(subdomain,))
        
        pool.wait()
        
        log.success(f"Found {len(self.found)} subdomains")
        return self.found
    
    def check_common_subdomains(self):
        """Check only common subdomains"""
        common = ['www', 'mail', 'ftp', 'api', 'admin', 'blog', 'forum', 
                  'shop', 'secure', 'portal', 'cpanel', 'webmail', 'dns',
                  'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap']
        
        log.progress(f"Checking {len(common)} common subdomains")
        
        for sub in common:
            self.check_subdomain(sub)
        
        return self.found
    
    def get_report(self):
        """Generate enumeration report"""
        lines = []
        lines.append("\n" + "=" * 60)
        lines.append("SUBDOMAIN ENUMERATION REPORT")
        lines.append("=" * 60)
        lines.append(f"Domain: {self.domain}")
        lines.append(f"Found Subdomains: {len(self.found)}")
        lines.append("=" * 60)
        lines.append(f"{'SUBDOMAIN':<40} {'IP'}")
        lines.append("-" * 60)
        
        for item in self.found:
            sub = item['subdomain']
            ip = item.get('ip', 'N/A')
            lines.append(f"{sub:<40} {ip}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
