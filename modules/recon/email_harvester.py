#!/usr/bin/env python3
"""
Email harvester module for gathering email addresses from various sources
Author: Jet
GitHub: https://github.com/JettRnh
"""

import re
import requests
import threading
from urllib.parse import urljoin, urlparse
from core.logger import log
from core.utils import ThreadPool
from config.settings import DEFAULT_USER_AGENT

class EmailHarvester:
    """Email address harvester from websites and search engines"""
    
    def __init__(self, domain, threads=20):
        self.domain = domain.lower()
        self.threads = min(threads, 50)
        self.emails = set()
        self.urls_scanned = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
        
        self.email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        )
        
        log.status(f"EmailHarvester initialized for {domain}")
    
    def extract_emails_from_text(self, text):
        """Extract email addresses from text"""
        found = self.email_pattern.findall(text)
        
        # Filter by domain if specified
        if self.domain:
            filtered = [e for e in found if self.domain in e.lower()]
        else:
            filtered = found
        
        with self.lock:
            for email in filtered:
                self.emails.add(email.lower())
        
        return filtered
    
    def scrape_url(self, url):
        """Scrape a single URL for emails"""
        if url in self.urls_scanned:
            return []
        
        with self.lock:
            self.urls_scanned.add(url)
        
        try:
            response = self.session.get(
                url,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                emails = self.extract_emails_from_text(response.text)
                log.info(f"Found {len(emails)} emails on {url}")
                return emails
            
        except requests.exceptions.Timeout:
            log.debug(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            log.debug(f"Connection error: {url}")
        except Exception as e:
            log.debug(f"Error scraping {url}: {e}")
        
        return []
    
    def crawl_website(self, start_url, max_pages=100):
        """Crawl website for emails"""
        log.progress(f"Crawling {start_url} for emails")
        
        to_visit = [start_url]
        visited = set()
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            self.scrape_url(url)
            
            # Find links to crawl
            try:
                response = self.session.get(
                    url,
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Extract links
                    link_pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
                    links = link_pattern.findall(response.text)
                    
                    for link in links:
                        if link.startswith('http'):
                            full_url = link
                        elif link.startswith('/'):
                            parsed = urlparse(start_url)
                            full_url = f"{parsed.scheme}://{parsed.netloc}{link}"
                        else:
                            continue
                        
                        if self.domain in full_url and full_url not in visited:
                            to_visit.append(full_url)
                            
            except Exception:
                pass
        
        log.success(f"Crawled {len(visited)} pages, found {len(self.emails)} emails")
        return list(self.emails)
    
    def search_google(self, max_results=100):
        """Search Google for emails (simplified - requires API in production)"""
        log.warning("Google search requires API key. Using alternative method.")
        
        # Alternative: fetch from public sources
        sources = [
            f"https://www.google.com/search?q=%40{self.domain}"
        ]
        
        for source in sources:
            try:
                response = self.session.get(
                    source,
                    timeout=10,
                    headers={'User-Agent': DEFAULT_USER_AGENT}
                )
                
                if response.status_code == 200:
                    emails = self.extract_emails_from_text(response.text)
                    log.info(f"Found {len(emails)} emails from search")
                    
            except Exception as e:
                log.debug(f"Search error: {e}")
        
        return list(self.emails)
    
    def harvest_from_url(self, url):
        """Harvest emails from single URL"""
        log.progress(f"Harvesting emails from {url}")
        self.scrape_url(url)
        return list(self.emails)
    
    def harvest_from_file(self, file_path):
        """Harvest emails from local file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                emails = self.extract_emails_from_text(content)
                log.success(f"Found {len(emails)} emails in file")
                return list(self.emails)
        except FileNotFoundError:
            log.error(f"File not found: {file_path}")
            return []
    
    def get_report(self):
        """Generate email harvest report"""
        lines = []
        lines.append("\n" + "=" * 60)
        lines.append("EMAIL HARVEST REPORT")
        lines.append("=" * 60)
        lines.append(f"Domain: {self.domain or 'all'}")
        lines.append(f"Emails Found: {len(self.emails)}")
        lines.append(f"URLs Scanned: {len(self.urls_scanned)}")
        lines.append("=" * 60)
        
        if self.emails:
            lines.append("\n[EMAILS]")
            lines.append("-" * 40)
            for email in sorted(self.emails):
                lines.append(f"  {email}")
        
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)
