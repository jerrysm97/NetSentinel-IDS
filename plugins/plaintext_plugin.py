"""
plaintext_plugin.py
NetSentinel Cortex Plugin - Plaintext Credential Detection

Detects sensitive data transmitted without encryption.
Migrated from legacy PlainTextMonitor with plugin architecture.
"""

import re
import sys
import os
from typing import Optional, List

from scapy.all import IP, Raw
from scapy.packet import Packet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from plugin_engine import AnalysisPlugin, PluginInfo, PluginAlert, AlertSeverity


class PlaintextPlugin(AnalysisPlugin):
    """
    Hunts for credentials and API keys in unencrypted traffic.
    
    Features:
    - Fast byte search before regex (performance optimization)
    - Compiled regex patterns
    - Early exit on first match
    """
    
    def __init__(self):
        super().__init__()
        
        # Fast check keywords (byte search before regex)
        self.fast_check_keywords = [
            b"password", b"passwd", b"apikey", b"api_key",
            b"token", b"bearer", b"authorization", b"secret",
            b"credential", b"auth"
        ]
        
        # Sensitive patterns
        self.sensitive_patterns = [
            r'password=([^&\s]+)',
            r'passwd=([^&\s]+)',
            r'apikey=([^&\s]+)',
            r'api_key=([^&\s]+)',
            r'token=([^&\s]+)',
            r'Bearer\s+([^\s]+)',
            r'Authorization:\s*Basic\s+([^\s]+)',
            r'secret=([^&\s]+)',
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) 
                                 for p in self.sensitive_patterns]
        
        self.packets_inspected = 0
        self.regex_runs = 0
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="Plaintext Credential Detector",
            version="2.0.0",
            author="NetSentinel Team",
            description="Hunts for credentials and API keys in unencrypted traffic",
            tags=["network", "credentials", "dlp", "cleartext"]
        )
    
    def analyze(self, packet: Packet) -> Optional[List[PluginAlert]]:
        if not packet.haslayer(Raw):
            return None
        
        self.packets_inspected += 1
            
        try:
            raw_bytes = packet[Raw].load
            
            # Fast byte search before expensive regex
            should_run_regex = False
            for keyword in self.fast_check_keywords:
                if keyword in raw_bytes.lower():
                    should_run_regex = True
                    break
            
            if not should_run_regex:
                return None
            
            self.regex_runs += 1
            payload = raw_bytes.decode('utf-8', errors='ignore')
            
            for pattern in self.compiled_patterns:
                match = pattern.search(payload)
                if match:
                    credential = match.group(1)
                    if len(credential) > 20:
                        credential = credential[:20] + "..."
                    
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
                    
                    return [PluginAlert(
                        plugin_name=self.get_info().name,
                        severity=AlertSeverity.HIGH,
                        message=f"Cleartext Credential Detected: {pattern.pattern}",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        metadata={
                            "pattern": pattern.pattern,
                            "value_preview": credential
                        }
                    )]
                    
        except Exception:
            pass
            
        return None
    
    def get_statistics(self) -> dict:
        stats = super().get_statistics()
        stats["packets_inspected"] = self.packets_inspected
        stats["regex_runs"] = self.regex_runs
        if self.packets_inspected > 0:
            stats["regex_skip_rate"] = f"{100 * (1 - self.regex_runs/self.packets_inspected):.1f}%"
        return stats


PLUGIN_CLASS = PlaintextPlugin
