"""
arp_spoof_monitor.py
Detects Man-in-the-Middle attacks via ARP poisoning.
"""

from typing import Optional

from scapy.all import ARP

from threat_monitor import ThreatMonitor


class ARPSpoofMonitor(ThreatMonitor):
    """
    Detects ARP cache poisoning attempts.
    
    Theory:
        ARP (Address Resolution Protocol) maps IP addresses to MAC addresses
        on local networks. It has no authentication, making it vulnerable.
        
        In ARP poisoning, an attacker sends fake ARP responses claiming:
        "I am 192.168.1.1 (the router)" but provides their own MAC address.
        
        The victim's computer updates its ARP cache, sending all internet
        traffic to the attacker instead of the legitimate router.
        
    Implementation:
        Maintains a mapping of IP to MAC addresses. If an IP announces
        a different MAC than previously seen in the same session, it
        indicates potential poisoning.
    """
    
    def __init__(self):
        """Initialize the ARP spoof detector."""
        super().__init__("ARP Spoofing Detector")
        
        # Dictionary: {IP_address: MAC_address}
        self.arp_table = {}
        
        # Track previous alerts to avoid spam
        self.alerted_pairs = set()
        
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
            
            # Check if we've seen this IP before
            if ip in self.arp_table:
                stored_mac = self.arp_table[ip]
                
                # MAC address mismatch = potential spoofing
                if stored_mac != mac:
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
                self.arp_table[ip] = mac
                
        return None
