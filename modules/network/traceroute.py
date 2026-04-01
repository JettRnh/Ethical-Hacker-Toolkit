#!/usr/bin/env python3
"""
Traceroute module for network path discovery
Author: Jet
GitHub: https://github.com/JettRnh
"""

import socket
import time
import threading
from core.logger import log
from core.utils import timer, resolve_hostname
from config.settings import DEFAULT_TIMEOUT

class Traceroute:
    """Network traceroute for path discovery"""
    
    def __init__(self, target, max_hops=30, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.max_hops = max_hops
        self.timeout = timeout
        self.route = []
        
        # Resolve target
        self.ip = resolve_hostname(target)
        if not self.ip:
            raise ValueError(f"Could not resolve target: {target}")
        
        log.status(f"Traceroute initialized for {target} ({self.ip})")
    
    def _send_probe(self, ttl):
        """Send a single probe with given TTL"""
        try:
            # Create ICMP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            
            # Set TTL
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            
            # Create ICMP echo request packet
            packet = b'\x08\x00'  # Type 8, Code 0 (Echo Request)
            packet += b'\x00\x00'  # Checksum placeholder
            packet += b'\x12\x34'  # Identifier
            packet += b'\x00\x00'  # Sequence number
            packet += b'\x00' * 56  # Data
            
            # Calculate checksum
            checksum = self._calculate_checksum(packet)
            packet = packet[:2] + checksum.to_bytes(2, 'big') + packet[4:]
            
            start_time = time.time()
            sock.sendto(packet, (self.ip, 0))
            
            try:
                data, addr = sock.recvfrom(1024)
                elapsed = (time.time() - start_time) * 1000
                return addr[0], elapsed
            except socket.timeout:
                return None, None
            finally:
                sock.close()
                
        except PermissionError:
            log.error("Need root privileges for ICMP traceroute. Try: sudo python eht.py")
            return None, None
        except Exception as e:
            log.debug(f"Probe failed: {e}")
            return None, None
    
    def _calculate_checksum(self, data):
        """Calculate ICMP checksum"""
        checksum = 0
        if len(data) % 2 != 0:
            data += b'\x00'
        
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum
    
    @timer
    def trace(self, probes_per_hop=3):
        """Perform traceroute"""
        log.progress(f"Tracing route to {self.target} ({self.ip})")
        
        for ttl in range(1, self.max_hops + 1):
            hop_ips = []
            hop_times = []
            
            for probe in range(probes_per_hop):
                ip, ms = self._send_probe(ttl)
                if ip:
                    hop_ips.append(ip)
                    if ms:
                        hop_times.append(ms)
            
            if hop_ips:
                # Get most common IP for this hop
                hop_ip = max(set(hop_ips), key=hop_ips.count)
                avg_time = sum(hop_times) / len(hop_times) if hop_times else 0
                
                self.route.append({
                    'hop': ttl,
                    'ip': hop_ip,
                    'time': avg_time,
                    'hostname': self._resolve_host(hop_ip)
                })
                
                log.info(f"Hop {ttl}: {hop_ip} ({avg_time:.1f}ms)")
                
                # Check if we reached target
                if hop_ip == self.ip:
                    log.success(f"Reached target at hop {ttl}")
                    break
            else:
                self.route.append({
                    'hop': ttl,
                    'ip': '*',
                    'time': 0,
                    'hostname': None
                })
                log.info(f"Hop {ttl}: *")
        
        return self.route
    
    def _resolve_host(self, ip):
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def get_report(self):
        """Generate traceroute report"""
        lines = []
        lines.append("\n" + "=" * 60)
        lines.append("TRACEROUTE REPORT")
        lines.append("=" * 60)
        lines.append(f"Target: {self.target} ({self.ip})")
        lines.append("=" * 60)
        lines.append(f"{'Hop':<6} {'IP':<20} {'Time':<12} {'Hostname'}")
        lines.append("-" * 60)
        
        for hop in self.route:
            if hop['ip'] == '*':
                lines.append(f"{hop['hop']:<6} *")
            else:
                time_str = f"{hop['time']:.1f}ms" if hop['time'] > 0 else "-"
                hostname = hop['hostname'] or '-'
                lines.append(f"{hop['hop']:<6} {hop['ip']:<20} {time_str:<12} {hostname}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
