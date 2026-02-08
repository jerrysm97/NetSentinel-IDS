"""
syn_flood_monitor.py
Detects volumetric Denial of Service attacks by tracking packet frequency.

Security Fixes:
- LRU eviction to prevent memory exhaustion from random source IPs
- Bounded dictionary size
"""

import time
from collections import OrderedDict
from typing import Optional

from scapy.all import IP, TCP

from threat_monitor import ThreatMonitor


class BoundedCounter:
    """
    Bounded counter with LRU eviction to prevent memory exhaustion.
    Attacker cannot exhaust memory by flooding with random source IPs.
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.counts = OrderedDict()
    
    def increment(self, key) -> int:
        """Increment counter for key, return new count."""
        if key in self.counts:
            self.counts[key] += 1
            self.counts.move_to_end(key)
        else:
            # Evict oldest if at capacity
            while len(self.counts) >= self.max_size:
                self.counts.popitem(last=False)
            self.counts[key] = 1
        return self.counts[key]
    
    def clear(self):
        """Clear all counts."""
        self.counts.clear()
    
    def __len__(self):
        return len(self.counts)


class SynFloodMonitor(ThreatMonitor):
    """
    Detects potential DoS attacks by monitoring SYN packet frequency.
    
    Security Features:
    - Bounded counter with max 10,000 tracked IPs (prevents memory DoS)
    - LRU eviction for oldest IPs when limit reached
    - Sliding window per-second rate limiting
    """
    
    def __init__(self, threshold: int = 50, max_tracked_ips: int = 10000):
        """
        Initialize the SYN flood detector.
        
        Args:
            threshold: Maximum SYN packets per second before alerting
            max_tracked_ips: Maximum IPs to track (LRU eviction after)
        """
        super().__init__("SYN Flood Detector")
        self.threshold = threshold
        
        # Bounded counter with LRU eviction
        self.ip_counts = BoundedCounter(max_size=max_tracked_ips)
        
        # Timestamp for sliding window reset
        self.last_reset = time.time()
        
        # Stats
        self.total_syn_packets = 0
        
    def inspect(self, packet) -> Optional[str]:
        """
        Count SYN packets per source IP and alert on threshold breach.
        
        Args:
            packet: Scapy packet to analyze
            
        Returns:
            Alert string if threshold exceeded, None otherwise
        """
        # Sliding window: Reset counts every second
        current_time = time.time()
        if current_time - self.last_reset >= 1.0:
            self.ip_counts.clear()
            self.last_reset = current_time
        
        # Only process packets with IP layer
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        
        # Check if this is a SYN packet (TCP flags = 0x02)
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
            self.total_syn_packets += 1
            count = self.ip_counts.increment(src_ip)
            
            # Alert if threshold exceeded (only alert once per window)
            if count == self.threshold + 1:
                self.alert_count += 1
                return (f"[CRITICAL] DoS Attack Detected from {src_ip}: "
                       f"{count} SYN packets/sec "
                       f"(Threshold: {self.threshold})")
        
        return None
    
    def get_statistics(self) -> dict:
        """Return monitoring statistics."""
        stats = super().get_statistics()
        stats["total_syn_packets"] = self.total_syn_packets
        stats["tracked_ips"] = len(self.ip_counts)
        return stats
