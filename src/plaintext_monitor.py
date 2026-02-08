"""
plaintext_monitor.py
Detects sensitive data transmitted without encryption.

Security Fixes:
- Fast byte search before expensive regex (Boyer-Moore optimization)
- Reduced CPU load on high-throughput networks
"""

import re
from typing import Optional

from scapy.all import IP, Raw

from threat_monitor import ThreatMonitor


class PlainTextMonitor(ThreatMonitor):
    """
    Hunts for credentials and API keys in unencrypted traffic.
    
    Performance Optimizations:
    - Fast byte search before regex (avoids CPU exhaustion)
    - Compiled regex patterns
    - Early exit on first match
    """
    
    def __init__(self):
        """Initialize the plaintext credential hunter."""
        super().__init__("Plaintext Credential Detector")
        
        # Fast check keywords (byte search before regex)
        # These are checked first using Python's fast 'in' operator
        self.fast_check_keywords = [
            b"password", b"passwd", b"apikey", b"api_key",
            b"token", b"bearer", b"authorization", b"secret",
            b"credential", b"auth"
        ]
        
        # Patterns commonly used in authentication
        self.sensitive_patterns = [
            r'password=([^&\s]+)',      # Form submissions
            r'passwd=([^&\s]+)',         # Alternative form field
            r'apikey=([^&\s]+)',         # API authentication
            r'api_key=([^&\s]+)',        # API authentication (snake_case)
            r'token=([^&\s]+)',          # Session or auth tokens
            r'Bearer\s+([^\s]+)',        # OAuth2 bearer tokens
            r'Authorization:\s*Basic\s+([^\s]+)',  # HTTP Basic Auth
            r'secret=([^&\s]+)',         # Secret keys
        ]
        
        # Compile regex patterns for performance
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) 
                                 for p in self.sensitive_patterns]
        
        # Stats
        self.packets_inspected = 0
        self.regex_runs = 0
    
    def inspect(self, packet) -> Optional[str]:
        """
        Search packet payload for plaintext credentials.
        
        Uses fast byte search before expensive regex to minimize CPU load.
        
        Args:
            packet: Scapy packet to analyze
            
        Returns:
            Alert string if credentials found, None otherwise
        """
        # Only process packets with payload data
        if not packet.haslayer(Raw):
            return None
        
        self.packets_inspected += 1
            
        try:
            raw_bytes = packet[Raw].load
            
            # OPTIMIZATION: Fast byte search before regex
            # This is O(n) string search, much faster than regex
            should_run_regex = False
            for keyword in self.fast_check_keywords:
                if keyword in raw_bytes.lower():
                    should_run_regex = True
                    break
            
            if not should_run_regex:
                return None  # No keywords found, skip expensive regex
            
            # Only decode and run regex if fast check passed
            self.regex_runs += 1
            payload = raw_bytes.decode('utf-8', errors='ignore')
            
            # Check each pattern
            for pattern in self.compiled_patterns:
                match = pattern.search(payload)
                if match:
                    self.alert_count += 1
                    
                    # Extract the matched credential (with truncation for security)
                    credential = match.group(1)
                    if len(credential) > 20:
                        credential = credential[:20] + "..."
                    
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
                    
                    return (f"[DANGER] Cleartext Credential Detected!\n"
                           f"  Source: {src_ip} → Destination: {dst_ip}\n"
                           f"  Pattern: {pattern.pattern}\n"
                           f"  Value: {credential}")
                           
        except Exception:
            # Silently ignore decode errors in binary protocols
            pass
            
        return None
    
    def get_statistics(self) -> dict:
        """Return monitoring statistics."""
        stats = super().get_statistics()
        stats["packets_inspected"] = self.packets_inspected
        stats["regex_runs"] = self.regex_runs
        if self.packets_inspected > 0:
            stats["regex_skip_rate"] = f"{100 * (1 - self.regex_runs/self.packets_inspected):.1f}%"
        return stats
