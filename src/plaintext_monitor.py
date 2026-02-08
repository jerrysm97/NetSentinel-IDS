"""
plaintext_monitor.py
Detects sensitive data transmitted without encryption.
"""

import re
from typing import Optional

from scapy.all import IP, TCP, Raw

from threat_monitor import ThreatMonitor


class PlainTextMonitor(ThreatMonitor):
    """
    Hunts for credentials and API keys in unencrypted traffic.
    
    Theory:
        Protocols like HTTP, Telnet, and FTP transmit data in cleartext.
        If authentication occurs over these protocols, credentials are
        vulnerable to network sniffing.
        
    Implementation:
        Extracts the Raw payload layer from packets, decodes as ASCII,
        and uses regex patterns to identify authentication parameters.
    """
    
    def __init__(self):
        """Initialize the plaintext credential hunter."""
        super().__init__("Plaintext Credential Detector")
        
        # Patterns commonly used in authentication
        # These appear in HTTP POST bodies, URL parameters, and headers
        self.sensitive_patterns = [
            r'password=([^&\s]+)',      # Form submissions
            r'passwd=([^&\s]+)',         # Alternative form field
            r'apikey=([^&\s]+)',         # API authentication
            r'api_key=([^&\s]+)',        # API authentication (snake_case)
            r'token=([^&\s]+)',          # Session or auth tokens
            r'Bearer\s+([^\s]+)',        # OAuth2 bearer tokens
            r'Authorization:\s*Basic\s+([^\s]+)',  # HTTP Basic Auth
        ]
        
        # Compile regex patterns for performance
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) 
                                 for p in self.sensitive_patterns]
    
    def inspect(self, packet) -> Optional[str]:
        """
        Search packet payload for plaintext credentials.
        
        Args:
            packet: Scapy packet to analyze
            
        Returns:
            Alert string if credentials found, None otherwise
        """
        # Only process packets with payload data
        if not packet.haslayer(Raw):
            return None
            
        try:
            # Decode payload to string, ignoring invalid UTF-8
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check each pattern
            for pattern in self.compiled_patterns:
                match = pattern.search(payload)
                if match:
                    self.alert_count += 1
                    
                    # Extract the matched credential (with truncation)
                    credential = match.group(1)[:20] + "..." if len(match.group(1)) > 20 else match.group(1)
                    
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
                    
                    return (f"[DANGER] Cleartext Credential Detected!\n"
                           f"  Source: {src_ip} → Destination: {dst_ip}\n"
                           f"  Pattern: {pattern.pattern}\n"
                           f"  Value: {credential}")
                           
        except Exception as e:
            # Silently ignore decode errors in binary protocols
            pass
            
        return None
