#!/usr/bin/env python3
"""
Directory brute-force module for web applications
Author: Jet
GitHub: https://github.com/JettRnh
"""

import requests
import threading
from urllib.parse import urljoin
from core.logger import log
from core.utils import ThreadPool, RateLimiter
from config.settings import DEFAULT_USER_AGENT, DEFAULT_REQUEST_TIMEOUT

class DirBruteforce:
    """Directory and file brute-forcer for web applications"""
    
    def __init__(self, target_url, wordlist, threads=50, extensions=None, recursive=False):
        self.target_url = target_url.rstrip('/')
        self.wordlist = wordlist
        self.threads = min(threads, 200)
        self.extensions = extensions or []
        self.recursive = recursive
        self.found = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        self.rate_limiter = RateLimiter(50)  # 50 requests per second max
        
        log.status(f"DirBruteforce initialized for {target_url}")
        log.info(f"Threads: {threads}, Extensions: {extensions or 'none'}")
    
    def check_path(self, path):
        """Check if path exists on target"""
        url = urljoin(self.target_url + '/', path)
        
        try:
            with self.rate_limiter:
                response = self.session.get(
                    url,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                    allow_redirects=False,
                    verify=False
                )
            
            status = response.status_code
            
            if status in [200, 201, 202, 203, 204]:
                result = {
                    'url': url,
                    'status': status,
                    'size': len(response.content),
                    'type': 'file' if '.' in path.split('/')[-1] else 'directory'
                }
                with self.lock:
                    self.found.append(result)
                log.success(f"Found: {url} ({status}) - {result['size']} bytes")
                return result
            
            elif status == 403:
                result = {
                    'url': url,
                    'status': 403,
                    'size': len(response.content),
                    'type': 'forbidden'
                }
                with self.lock:
                    self.found.append(result)
                log.info(f"Forbidden: {url}")
                return result
            
            elif status == 401:
                log.info(f"Authentication required: {url}")
                
        except requests.exceptions.Timeout:
            log.debug(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            log.debug(f"Connection error: {url}")
        except Exception as e:
            log.debug(f"Error checking {url}: {e}")
        
        return None
    
    def _read_wordlist(self):
        """Read wordlist file"""
        words = []
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log.error(f"Wordlist not found: {self.wordlist}")
            return []
        
        log.info(f"Loaded {len(words)} words from wordlist")
        return words
    
    def _generate_paths(self, words):
        """Generate paths from words with extensions"""
        paths = words.copy()
        
        # Add extensions
        if self.extensions:
            for word in words:
                for ext in self.extensions:
                    paths.append(f"{word}.{ext}")
        
        return paths
    
    def run(self):
        """Execute directory brute-force"""
        log.progress(f"Starting directory brute-force on {self.target_url}")
        
        words = self._read_wordlist()
        if not words:
            return []
        
        paths = self._generate_paths(words)
        log.info(f"Total paths to check: {len(paths)}")
        
        pool = ThreadPool(self.threads)
        
        for path in paths:
            pool.submit(self.check_path, args=(path,))
        
        pool.wait()
        
        log.success(f"Found {len(self.found)} directories/files")
        
        # Handle recursion if enabled
        if self.recursive:
            directories = [f for f in self.found if f.get('type') == 'directory']
            for directory in directories:
                log.info(f"Recursively scanning: {directory['url']}")
                recursive_brute = DirBruteforce(
                    directory['url'],
                    self.wordlist,
                    self.threads,
                    self.extensions,
                    recursive=False  # Prevent infinite recursion
                )
                sub_results = recursive_brute.run()
                with self.lock:
                    self.found.extend(sub_results)
        
        return self.found
    
    def get_report(self):
        """Generate scan report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("DIRECTORY BRUTE-FORCE REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {self.target_url}")
        lines.append(f"Wordlist: {self.wordlist}")
        lines.append(f"Extensions: {self.extensions or 'none'}")
        lines.append(f"Found Items: {len(self.found)}")
        lines.append("=" * 70)
        lines.append(f"{'STATUS':<8} {'TYPE':<12} {'SIZE':<10} URL")
        lines.append("-" * 70)
        
        for item in self.found:
            status = item['status']
            item_type = item.get('type', 'unknown')
            size = item.get('size', 0)
            url = item['url']
            lines.append(f"{status:<8} {item_type:<12} {size:<10} {url}")
        
        lines.append("=" * 70)
        return "\n".join(lines)
