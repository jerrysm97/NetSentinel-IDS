"""
arp_spoof_plugin.py
NetSentinel Cortex Plugin - ARP Spoofing Detection

Detects Man-in-the-Middle attacks via ARP poisoning.
Migrated from legacy ARPSpoofMonitor with plugin architecture.
"""

import time
import sys
import os
from collections import OrderedDict
from typing import Optional, List

from scapy.all import ARP
from scapy.packet import Packet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from plugin_engine import AnalysisPlugin, PluginInfo, PluginAlert, AlertSeverity


class LRUCache:
    """LRU cache with TTL support."""
    
    def __init__(self, max_size: int = 10000, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache = OrderedDict()
    
    def get(self, key):
        if key not in self.cache:
            return None
        value, timestamp = self.cache[key]
        if time.time() - timestamp > self.ttl_seconds:
            del self.cache[key]
            return None
        self.cache.move_to_end(key)
        return value
    
    def set(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = (value, time.time())
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
    
    def __contains__(self, key):
        return self.get(key) is not None
    
    def __len__(self):
        return len(self.cache)


class ARPSpoofPlugin(AnalysisPlugin):
    """
    Detects ARP cache poisoning attempts.
    
    Features:
    - LRU cache with max 10,000 entries
    - TTL expiration (handles DHCP)
    - Static binding support for trusted IPs
    """
    
    def __init__(self, trusted_bindings: dict = None, max_entries: int = 10000,
                 ttl_seconds: int = 300):
        super().__init__()
        self.arp_table = LRUCache(max_size=max_entries, ttl_seconds=ttl_seconds)
        self.trusted_bindings = trusted_bindings or {}
        self.alerted_pairs = set()
        self.eviction_count = 0
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="ARP Spoofing Detector",
            version="2.0.0",
            author="NetSentinel Team",
            description="Detects Man-in-the-Middle attacks via ARP poisoning",
            tags=["network", "arp", "mitm", "poisoning"]
        )
    
    def analyze(self, packet: Packet) -> Optional[List[PluginAlert]]:
        if not packet.haslayer(ARP):
            return None
            
        arp = packet[ARP]
        
        # ARP opcode 2 = Reply
        if arp.op == 2:
            ip = arp.psrc
            mac = arp.hwsrc
            
            # Check trusted bindings
            if ip in self.trusted_bindings:
                trusted_mac = self.trusted_bindings[ip]
                if mac.lower() != trusted_mac.lower():
                    return [PluginAlert(
                        plugin_name=self.get_info().name,
                        severity=AlertSeverity.CRITICAL,
                        message=f"ARP Spoofing of TRUSTED IP! Expected: {trusted_mac}, Got: {mac}",
                        source_ip=ip,
                        metadata={
                            "expected_mac": trusted_mac,
                            "received_mac": mac,
                            "is_trusted": True
                        }
                    )]
                return None
            
            # Check dynamic table
            stored_mac = self.arp_table.get(ip)
            
            if stored_mac is not None:
                if stored_mac.lower() != mac.lower():
                    alert_key = (ip, stored_mac, mac)
                    
                    if alert_key not in self.alerted_pairs:
                        self.alerted_pairs.add(alert_key)
                        
                        return [PluginAlert(
                            plugin_name=self.get_info().name,
                            severity=AlertSeverity.CRITICAL,
                            message=f"ARP Spoofing Detected: {ip} changed from {stored_mac} to {mac}",
                            source_ip=ip,
                            metadata={
                                "original_mac": stored_mac,
                                "new_mac": mac,
                                "attack_type": "MITM"
                            }
                        )]
            else:
                old_size = len(self.arp_table)
                self.arp_table.set(ip, mac)
                if len(self.arp_table) == old_size and old_size > 0:
                    self.eviction_count += 1
                
        return None
    
    def get_statistics(self) -> dict:
        stats = super().get_statistics()
        stats["arp_table_size"] = len(self.arp_table)
        stats["trusted_bindings"] = len(self.trusted_bindings)
        stats["evictions"] = self.eviction_count
        return stats


PLUGIN_CLASS = ARPSpoofPlugin
