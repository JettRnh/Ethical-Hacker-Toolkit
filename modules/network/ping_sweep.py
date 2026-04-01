#!/usr/bin/env python3
"""
Ping sweep module for network discovery
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import threading
import subprocess
import platform
from core.logger import log
from core.utils import ThreadPool, timer
from config.settings import DEFAULT_TIMEOUT, DEFAULT_THREADS

class PingSweep:
    """Network ping sweep for host discovery"""
    
    def __init__(self, network, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT):
        self.network = network
        self.threads = min(threads, 500)
        self.timeout = timeout
        self.active_hosts = []
        self.lock = threading.Lock()
        
        # Parse network
        self.base_ip, self.cidr = self._parse_network(network)
        self.hosts = self._generate_hosts()
        
        log.status(f"Ping sweep initialized for {network} ({len(self.hosts)} hosts)")
    
    def _parse_network(self, network):
        """Parse network string like '192.168.1.0/24' or '192.168.1.0'"""
        if '/' in network:
            base, cidr = network.split('/')
            return base, int(cidr)
        else:
            # Assume /24 if no CIDR
            return network, 24
    
    def _generate_hosts(self):
        """Generate list of host IPs to scan"""
        hosts = []
        parts = self.base_ip.split('.')
        
        if len(parts) != 4:
            raise ValueError(f"Invalid network: {self.network}")
        
        network_prefix = '.'.join(parts[:3])
        
        if self.cidr == 24:
            for i in range(1, 255):
                hosts.append(f"{network_prefix}.{i}")
        elif self.cidr == 16:
            for i in range(0, 256):
                for j in range(1, 255):
                    hosts.append(f"{parts[0]}.{parts[1]}.{i}.{j}")
        elif self.cidr == 8:
            for i in range(0, 256):
                for j in range(0, 256):
                    for k in range(1, 255):
                        hosts.append(f"{parts[0]}.{i}.{j}.{k}")
        else:
            raise ValueError(f"Unsupported CIDR: {self.cidr}. Only /8, /16, /24 supported")
        
        return hosts
    
    def ping_host(self, ip):
        """Ping a single host"""
        try:
            # Determine ping command based on OS
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(self.timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(self.timeout), ip]
            
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if result.returncode == 0:
                with self.lock:
                    self.active_hosts.append(ip)
                log.success(f"Host {ip} is up")
                return ip
        except Exception:
            pass
        return None
    
    def ping_arp(self, ip):
        """ARP ping for local network (Linux only)"""
        try:
            if platform.system().lower() == 'linux':
                cmd = ['arping', '-c', '1', '-w', str(self.timeout), ip]
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return result.returncode == 0
        except:
            pass
        return False
    
    @timer
    def scan(self, use_arp=False):
        """Perform ping sweep"""
        log.progress(f"Scanning {len(self.hosts)} hosts with ping sweep")
        
        pool = ThreadPool(self.threads)
        
        for ip in self.hosts:
            pool.submit(self.ping_host, args=(ip,))
        
        pool.wait()
        
        log.success(f"Found {len(self.active_hosts)} active hosts")
        return self.active_hosts
    
    @timer
    def scan_quick(self):
        """Quick scan for active hosts (first 50 hosts only)"""
        quick_hosts = self.hosts[:50]
        log.progress(f"Quick scan on {len(quick_hosts)} hosts")
        
        for ip in quick_hosts:
            self.ping_host(ip)
        
        return self.active_hosts
    
    def get_report(self):
        """Generate scan report"""
        lines = []
        lines.append("\n" + "=" * 50)
        lines.append("PING SWEEP REPORT")
        lines.append("=" * 50)
        lines.append(f"Network: {self.network}")
        lines.append(f"Hosts Scanned: {len(self.hosts)}")
        lines.append(f"Active Hosts: {len(self.active_hosts)}")
        lines.append("=" * 50)
        lines.append("\nActive Hosts:")
        
        for ip in self.active_hosts:
            lines.append(f"  [+] {ip}")
        
        return "\n".join(lines)
