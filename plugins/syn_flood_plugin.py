"""
syn_flood_plugin.py
NetSentinel Cortex Plugin - SYN Flood Detection

Detects volumetric DoS attacks by monitoring SYN packet frequency.
Migrated from legacy SynFloodMonitor with plugin architecture.
"""

import time
import sys
import os
from collections import OrderedDict
from typing import Optional, List

from scapy.all import IP, TCP
from scapy.packet import Packet

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from plugin_engine import AnalysisPlugin, PluginInfo, PluginAlert, AlertSeverity


class BoundedCounter:
    """Bounded counter with LRU eviction to prevent memory exhaustion."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.counts = OrderedDict()
    
    def increment(self, key) -> int:
        if key in self.counts:
            self.counts[key] += 1
            self.counts.move_to_end(key)
        else:
            while len(self.counts) >= self.max_size:
                self.counts.popitem(last=False)
            self.counts[key] = 1
        return self.counts[key]
    
    def clear(self):
        self.counts.clear()
    
    def __len__(self):
        return len(self.counts)


class SynFloodPlugin(AnalysisPlugin):
    """
    Detects potential DoS attacks by monitoring SYN packet frequency.
    
    Features:
    - Bounded counter with LRU eviction (10,000 IPs max)
    - Sliding window per-second rate limiting
    - Configurable threshold
    """
    
    def __init__(self, threshold: int = 50, max_tracked_ips: int = 10000):
        super().__init__()
        self.threshold = threshold
        self.ip_counts = BoundedCounter(max_size=max_tracked_ips)
        self.last_reset = time.time()
        self.total_syn_packets = 0
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="SYN Flood Detector",
            version="2.0.0",
            author="NetSentinel Team",
            description="Detects volumetric DoS attacks by monitoring SYN packet frequency",
            tags=["network", "dos", "ddos", "syn-flood"]
        )
    
    def analyze(self, packet: Packet) -> Optional[List[PluginAlert]]:
        # Sliding window: Reset counts every second
        current_time = time.time()
        if current_time - self.last_reset >= 1.0:
            self.ip_counts.clear()
            self.last_reset = current_time
        
        # Only process IP packets
        if not packet.haslayer(IP):
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        
        # Check for SYN packets (TCP flags = 0x02)
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
            self.total_syn_packets += 1
            count = self.ip_counts.increment(src_ip)
            
            # Alert if threshold exceeded (only once per window)
            if count == self.threshold + 1:
                return [PluginAlert(
                    plugin_name=self.get_info().name,
                    severity=AlertSeverity.CRITICAL,
                    message=f"DoS Attack Detected: {count} SYN packets/sec (Threshold: {self.threshold})",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    metadata={
                        "syn_count": count,
                        "threshold": self.threshold,
                        "tracked_ips": len(self.ip_counts)
                    }
                )]
        
        return None
    
    def get_statistics(self) -> dict:
        stats = super().get_statistics()
        stats["total_syn_packets"] = self.total_syn_packets
        stats["tracked_ips"] = len(self.ip_counts)
        stats["threshold"] = self.threshold
        return stats


# Plugin discovery marker
PLUGIN_CLASS = SynFloodPlugin
