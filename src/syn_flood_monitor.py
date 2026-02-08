"""
syn_flood_monitor.py
Detects volumetric Denial of Service attacks by tracking packet frequency.
"""

import time
from collections import defaultdict
from typing import Optional

from scapy.all import IP, TCP

from threat_monitor import ThreatMonitor


class SynFloodMonitor(ThreatMonitor):
    """
    Detects potential DoS attacks by monitoring SYN packet frequency.
    
    Theory:
        A legitimate TCP connection follows the three-way handshake:
        Client sends SYN, server responds with SYN-ACK, client sends ACK.
        
        In a SYN flood attack, the attacker sends thousands of SYN packets
        without completing the handshake, exhausting server resources.
        
    Implementation:
        Uses a sliding window approach with a dictionary keyed by source IP.
        Counts are reset every second to maintain accurate per-second rates.
    """
    
    def __init__(self, threshold: int = 50):
        """
        Initialize the SYN flood detector.
        
        Args:
            threshold: Maximum SYN packets per second before alerting
                      (Default: 50, which is aggressive for testing)
        """
        super().__init__("SYN Flood Detector")
        self.threshold = threshold
        
        # Dictionary storing request counts per IP address
        # Using defaultdict eliminates need for key existence checks
        self.ip_counts = defaultdict(int)
        
        # Timestamp for sliding window reset
        self.last_reset = time.time()
        
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
            self.ip_counts[src_ip] += 1
            
            # Alert if threshold exceeded
            if self.ip_counts[src_ip] > self.threshold:
                self.alert_count += 1
                return (f"[CRITICAL] DoS Attack Detected from {src_ip}: "
                       f"{self.ip_counts[src_ip]} SYN packets/sec "
                       f"(Threshold: {self.threshold})")
        
        return None
