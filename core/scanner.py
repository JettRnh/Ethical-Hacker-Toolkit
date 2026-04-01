#!/usr/bin/env python3
"""
Base scanner module for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import threading
from core.logger import log
from core.utils import (
    validate_ip, resolve_hostname, get_service_name,
    ThreadPool, timer
)
from config.settings import DEFAULT_TIMEOUT, DEFAULT_THREADS

class BaseScanner:
    """Base scanner class for network scanning operations"""
    
    def __init__(self, target, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.threads = min(threads, 500)
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()
        
        # Resolve hostname to IP
        if validate_ip(target):
            self.ip = target
            self.hostname = target
        else:
            self.ip = resolve_hostname(target)
            self.hostname = target
        
        if not self.ip:
            raise ValueError(f"Could not resolve target: {target}")
        
        log.status(f"Scanner initialized for {self.hostname} ({self.ip})")
    
    def add_result(self, result):
        """Add result to collection"""
        with self.lock:
            self.results.append(result)
    
    def get_results(self):
        """Get all results"""
        return self.results
    
    def get_summary(self):
        """Get summary of results"""
        return {
            'target': self.target,
            'ip': self.ip,
            'total_results': len(self.results)
        }
    
    @timer
    def scan_single_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            
            if result == 0:
                service = get_service_name(port)
                return {'port': port, 'service': service, 'status': 'open'}
        except Exception:
            pass
        return None
    
    @timer
    def scan_range(self, start_port, end_port, callback=None):
        """Scan a range of ports"""
        if start_port < 1 or end_port > 65535:
            raise ValueError("Port range must be between 1 and 65535")
        
        log.progress(f"Scanning ports {start_port}-{end_port} on {self.ip}")
        
        pool = ThreadPool(self.threads)
        
        for port in range(start_port, end_port + 1):
            pool.submit(self.scan_single_port, args=(port,), callback=callback)
        
        results = pool.wait()
        
        # Filter out None results
        valid_results = [r for r in results if r is not None]
        for result in valid_results:
            self.add_result(result)
        
        log.success(f"Found {len(valid_results)} open ports")
        return valid_results
    
    def scan_common_ports(self, ports=None, callback=None):
        """Scan common ports"""
        from config.settings import COMMON_PORTS
        
        if ports is None:
            ports = COMMON_PORTS
        
        log.progress(f"Scanning {len(ports)} common ports on {self.ip}")
        
        pool = ThreadPool(self.threads)
        
        for port in ports:
            pool.submit(self.scan_single_port, args=(port,), callback=callback)
        
        results = pool.wait()
        
        valid_results = [r for r in results if r is not None]
        for result in valid_results:
            self.add_result(result)
        
        log.success(f"Found {len(valid_results)} open ports")
        return valid_results
