#!/usr/bin/env python3
"""
Utility functions for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import threading
import queue
import time
import re
from functools import wraps
from core.logger import log

def timer(func):
    """Decorator to measure execution time"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        log.debug(f"{func.__name__} completed in {elapsed:.2f}s")
        return result
    return wrapper

def validate_ip(ip):
    """Validate IPv4 address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    for part in parts:
        if int(part) < 0 or int(part) > 255:
            return False
    return True

def validate_port(port):
    """Validate port number (1-65535)"""
    return isinstance(port, int) and 1 <= port <= 65535

def resolve_hostname(hostname):
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def reverse_lookup(ip):
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def is_private_ip(ip):
    """Check if IP is private (RFC 1918)"""
    if not validate_ip(ip):
        return False
    
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255')
    ]
    
    try:
        ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
        for start, end in private_ranges:
            start_int = int.from_bytes(socket.inet_aton(start), 'big')
            end_int = int.from_bytes(socket.inet_aton(end), 'big')
            if start_int <= ip_int <= end_int:
                return True
        return False
    except:
        return False

def get_service_name(port):
    """Get service name for a port"""
    services = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
        139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
        993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3306: 'mysql',
        3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy'
    }
    return services.get(port, 'unknown')

def parse_port_range(port_range):
    """Parse port range string like '1-1000' or '80,443,8080'"""
    ports = []
    
    if '-' in port_range:
        try:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, min(end + 1, 65536)))
        except:
            pass
    elif ',' in port_range:
        try:
            ports = [int(p.strip()) for p in port_range.split(',') if p.strip()]
        except:
            pass
    else:
        try:
            ports = [int(port_range)]
        except:
            pass
    
    return [p for p in ports if validate_port(p)]

class ThreadPool:
    """Thread pool for parallel execution"""
    
    def __init__(self, num_threads, max_queue_size=1000):
        self.num_threads = min(num_threads, 500)
        self.queue = queue.Queue(maxsize=max_queue_size)
        self.threads = []
        self.results = []
        self.errors = []
        self.lock = threading.Lock()
        self.running = True
        self.completed = 0
        self.total = 0
        
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
    
    def _worker(self):
        while self.running:
            try:
                task_id, func, args, kwargs, callback = self.queue.get(timeout=0.5)
                try:
                    result = func(*args, **kwargs)
                    if callback:
                        callback(result)
                    with self.lock:
                        self.results.append(result)
                        self.completed += 1
                except Exception as e:
                    with self.lock:
                        self.errors.append({'task': task_id, 'error': str(e)})
                finally:
                    self.queue.task_done()
            except queue.Empty:
                continue
    
    def submit(self, func, args=None, kwargs=None, callback=None):
        """Submit a task to the pool"""
        if args is None:
            args = ()
        if kwargs is None:
            kwargs = {}
        with self.lock:
            task_id = self.total
            self.total += 1
        self.queue.put((task_id, func, args, kwargs, callback))
    
    def wait(self):
        """Wait for all tasks to complete"""
        self.queue.join()
        self.running = False
        for thread in self.threads:
            thread.join(timeout=2)
        return self.results
    
    def get_results(self):
        """Get all results"""
        return self.results
    
    def get_errors(self):
        """Get all errors"""
        return self.errors
    
    def get_progress(self):
        """Get progress percentage"""
        if self.total == 0:
            return 0
        return (self.completed / self.total) * 100

class RateLimiter:
    """Simple rate limiter for controlling request frequency"""
    
    def __init__(self, max_per_second):
        self.max_per_second = max_per_second
        self.interval = 1.0 / max_per_second if max_per_second > 0 else 0
        self.last_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if needed to maintain rate limit"""
        if self.interval <= 0:
            return
        
        with self.lock:
            now = time.time()
            elapsed = now - self.last_time
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self.last_time = time.time()
    
    def __enter__(self):
        self.wait()
        return self
    
    def __exit__(self, *args):
        pass
