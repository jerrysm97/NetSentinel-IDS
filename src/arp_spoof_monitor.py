"""
arp_spoof_monitor.py
Detects Man-in-the-Middle attacks via ARP poisoning.

Security Fixes:
- LRU eviction to prevent memory exhaustion
- TTL expiration to handle DHCP false positives  
- Static binding support for trusted IPs
"""

import time
from collections import OrderedDict
from typing import Optional

from scapy.all import ARP

from threat_monitor import ThreatMonitor


class LRUCache:
    """LRU cache with TTL support to prevent memory exhaustion."""
    
    def __init__(self, max_size: int = 10000, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache = OrderedDict()  # {key: (value, timestamp)}
    
    def get(self, key):
        """Get value if exists and not expired."""
        if key not in self.cache:
            return None
        value, timestamp = self.cache[key]
        if time.time() - timestamp > self.ttl_seconds:
            del self.cache[key]
            return None
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return value
    
    def set(self, key, value):
        """Set value with LRU eviction."""
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = (value, time.time())
        # Evict oldest if over capacity
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
    
    def __contains__(self, key):
        return self.get(key) is not None
    
    def __len__(self):
        return len(self.cache)


class ARPSpoofMonitor(ThreatMonitor):
    """
    Detects ARP cache poisoning attempts.
    
    Security Features:
    - LRU cache with max 10,000 entries (prevents memory DoS)
    - TTL expiration of 5 minutes (handles DHCP reassignment)
    - Static binding support for trusted IP-MAC pairs
    """
    
    def __init__(self, trusted_bindings: dict = None, max_entries: int = 10000, 
                 ttl_seconds: int = 300):
        """
        Initialize the ARP spoof detector.
        
        Args:
            trusted_bindings: Dict of {IP: MAC} for static trusted entries
            max_entries: Maximum ARP table size before LRU eviction
            ttl_seconds: Time-to-live for ARP entries (handles DHCP)
        """
        super().__init__("ARP Spoofing Detector")
        
        # LRU cache with TTL: {IP_address: MAC_address}
        self.arp_table = LRUCache(max_size=max_entries, ttl_seconds=ttl_seconds)
        
        # Static trusted bindings (never evicted, never trigger alerts)
        self.trusted_bindings = trusted_bindings or {}
        
        # Track previous alerts to avoid spam
        self.alerted_pairs = set()
        
        # Stats
        self.eviction_count = 0
        
    def inspect(self, packet) -> Optional[str]:
        """
        Monitor ARP packets for MAC address inconsistencies.
        
        Args:
            packet: Scapy packet to analyze
            
        Returns:
            Alert string if spoofing detected, None otherwise
        """
        # Only process ARP packets
        if not packet.haslayer(ARP):
            return None
            
        arp = packet[ARP]
        
        # ARP opcode 2 = Reply (responses to "who-has" queries)
        if arp.op == 2:  # is-at (ARP reply)
            ip = arp.psrc   # IP address being claimed
            mac = arp.hwsrc # MAC address claiming the IP
            
            # Check static trusted bindings first
            if ip in self.trusted_bindings:
                trusted_mac = self.trusted_bindings[ip]
                if mac.lower() != trusted_mac.lower():
                    self.alert_count += 1
                    return (f"[CRITICAL] ARP Spoofing of TRUSTED IP!\n"
                           f"  IP Address: {ip}\n"
                           f"  Expected MAC: {trusted_mac}\n"
                           f"  Received MAC: {mac}\n"
                           f"  CONFIRMED ATTACK on critical infrastructure!")
                return None  # Trusted and valid
            
            # Check dynamic ARP table
            stored_mac = self.arp_table.get(ip)
            
            if stored_mac is not None:
                # MAC address mismatch = potential spoofing
                if stored_mac.lower() != mac.lower():
                    alert_key = (ip, stored_mac, mac)
                    
                    # Only alert once per unique spoof attempt
                    if alert_key not in self.alerted_pairs:
                        self.alerted_pairs.add(alert_key)
                        self.alert_count += 1
                        
                        return (f"[CRITICAL] ARP Spoofing Detected!\n"
                               f"  IP Address: {ip}\n"
                               f"  Original MAC: {stored_mac}\n"
                               f"  New MAC: {mac}\n"
                               f"  Possible Man-in-the-Middle Attack")
            else:
                # First time seeing this IP, store the mapping
                old_size = len(self.arp_table)
                self.arp_table.set(ip, mac)
                if len(self.arp_table) == old_size and old_size > 0:
                    self.eviction_count += 1
                
        return None
    
    def get_statistics(self) -> dict:
        """Return monitoring statistics."""
        stats = super().get_statistics()
        stats["arp_table_size"] = len(self.arp_table)
        stats["trusted_bindings"] = len(self.trusted_bindings)
        stats["evictions"] = self.eviction_count
        return stats
