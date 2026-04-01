#!/usr/bin/env python3
"""
Advanced port scanner module with service detection and banner grabbing
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import ssl
import threading
from core.scanner import BaseScanner
from core.logger import log
from core.utils import timer, get_service_name, ThreadPool
from config.settings import DEFAULT_TIMEOUT, DEFAULT_THREADS

class PortScanner(BaseScanner):
    """Extended port scanner with service detection and banner grabbing"""
    
    def __init__(self, target, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT):
        super().__init__(target, threads, timeout)
        self.banners = {}
        self.service_versions = {}
    
    def grab_banner(self, port, service):
        """Grab service banner from open port"""
        banner = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, port))
            
            # Send appropriate probe based on service
            probes = {
                21: b"HELP\r\n",
                22: b"",
                23: b"\r\n",
                25: b"HELP\r\n",
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                110: b"HELP\r\n",
                111: b"",
                135: b"",
                139: b"",
                143: b"A001 CAPABILITY\r\n",
                443: b"HEAD / HTTP/1.0\r\n\r\n",
                445: b"",
                3306: b"",
                5432: b"",
                5900: b"",
                8080: b"HEAD / HTTP/1.0\r\n\r\n"
            }
            
            probe = probes.get(port, b"")
            if probe:
                sock.send(probe)
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Clean up banner
            if banner:
                banner = banner.replace('\r', ' ').replace('\n', ' ').strip()
                banner = ' '.join(banner.split())
                banner = banner[:200]
                
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception as e:
            log.debug(f"Banner grab failed on port {port}: {e}")
        
        return banner
    
    def detect_service_version(self, port, banner):
        """Attempt to detect service version from banner"""
        version = "unknown"
        
        if not banner:
            return version
        
        banner_lower = banner.lower()
        
        # SSH version detection
        if port == 22:
            if 'ssh' in banner_lower:
                import re
                match = re.search(r'SSH-([\d\.]+)', banner)
                if match:
                    version = f"SSH {match.group(1)}"
        
        # HTTP server detection
        elif port in [80, 443, 8080, 8443]:
            if 'server:' in banner_lower:
                import re
                match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
                if match:
                    version = match.group(1).strip()
        
        # FTP detection
        elif port == 21:
            if 'ftp' in banner_lower:
                version = banner.split('\n')[0].strip()
        
        # SMTP detection
        elif port == 25:
            version = banner.split('\n')[0].strip()
        
        return version[:100]
    
    def scan_with_banner(self, start_port, end_port):
        """Scan ports and grab banners"""
        results = self.scan_range(start_port, end_port)
        
        for result in results:
            port = result['port']
            service = result['service']
            
            banner = self.grab_banner(port, service)
            if banner:
                self.banners[port] = banner
                version = self.detect_service_version(port, banner)
                if version != "unknown":
                    self.service_versions[port] = version
                    log.info(f"Port {port} - {service} - {version}")
                else:
                    log.info(f"Port {port} banner: {banner[:50]}...")
        
        return results
    
    def scan_common_with_banner(self):
        """Scan common ports with banner grabbing"""
        results = self.scan_common_ports()
        
        for result in results:
            port = result['port']
            service = result['service']
            
            banner = self.grab_banner(port, service)
            if banner:
                self.banners[port] = banner
                version = self.detect_service_version(port, banner)
                if version != "unknown":
                    self.service_versions[port] = version
                    log.success(f"Port {port} - {service} - {version}")
        
        return results
    
    def full_report(self):
        """Generate detailed scan report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append(f"PORT SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {self.target}")
        lines.append(f"IP: {self.ip}")
        lines.append(f"Scan Time: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Open Ports: {len(self.results)}")
        lines.append("=" * 70)
        lines.append(f"{'PORT':<8} {'SERVICE':<15} {'STATUS':<8} {'VERSION'}")
        lines.append("-" * 70)
        
        for result in self.results:
            port = result['port']
            service = result['service']
            version = self.service_versions.get(port, '-')
            lines.append(f"{port:<8} {service:<15} {'open':<8} {version}")
        
        lines.append("=" * 70)
        
        if self.banners:
            lines.append("\nBANNER DETAILS:")
            lines.append("-" * 40)
            for port, banner in self.banners.items():
                lines.append(f"Port {port}: {banner}")
        
        return "\n".join(lines)
