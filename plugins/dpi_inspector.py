"""
dpi_inspector.py
NetSentinel Cortex Plugin - Deep Packet Inspection

Inspects packet payloads for:
- Sensitive data (credit cards, passwords, API keys)
- Shellcode patterns (NOP sleds, common signatures)
- Suspicious content (base64 encoded payloads, etc.)
"""

import re
import sys
import os
from typing import Optional, List

from scapy.all import IP, Raw
from scapy.packet import Packet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from plugin_engine import AnalysisPlugin, PluginInfo, PluginAlert, AlertSeverity


class DPIInspectorPlugin(AnalysisPlugin):
    """
    Deep Packet Inspection for sensitive data and malicious patterns.
    
    Detects:
    - Credit card numbers (with basic Luhn validation)
    - Password fields in cleartext
    - API keys and tokens
    - Shellcode signatures (NOP sleds, common byte patterns)
    - Base64 encoded suspicious payloads
    """
    
    def __init__(self):
        super().__init__()
        
        # Sensitive data patterns
        self.sensitive_patterns = {
            "credit_card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
            "password_form": re.compile(r'password[=:]\s*[^\s&]{4,}', re.IGNORECASE),
            "api_key": re.compile(r'(api[_-]?key|apikey)[=:]\s*[\w-]{20,}', re.IGNORECASE),
            "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
            "bearer_token": re.compile(r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        }
        
        # Shellcode patterns (byte sequences)
        self.shellcode_patterns = {
            "nop_sled": b'\x90' * 10,           # 10+ NOPs
            "nop_sled_alt": b'\x90\x90\x90\x90\x90\x90\x90\x90',
            "int3_chain": b'\xcc\xcc\xcc\xcc',  # Debugger traps
            "jmp_esp": b'\xff\xe4',              # JMP ESP
            "call_esp": b'\xff\xd4',             # CALL ESP
            "push_ret": b'\x68' + b'\x00' * 4 + b'\xc3',  # PUSH addr; RET
        }
        
        # Quick-check byte markers
        self.suspicious_bytes = [
            b'\x90\x90\x90',   # NOP chain
            b'\xcc\xcc',      # INT3 chain
            b'\xff\xe4',      # JMP ESP
            b'\xff\xd4',      # CALL ESP
            b'/etc/passwd',   # Path traversal
            b'/etc/shadow',
            b'cmd.exe',       # Windows shell
            b'powershell',
            b'/bin/sh',       # Unix shell
            b'/bin/bash',
        ]
        
        self.packets_deep_inspected = 0
        self.sensitive_matches = 0
        self.shellcode_matches = 0
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="DPI Inspector",
            version="1.0.0",
            author="NetSentinel Team",
            description="Deep Packet Inspection for sensitive data and shellcode",
            tags=["dpi", "dlp", "shellcode", "forensics", "credit-card"]
        )
    
    def _luhn_check(self, card_number: str) -> bool:
        """Basic Luhn algorithm check for credit card validation."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
    
    def _bytes_to_hex(self, data: bytes, max_len: int = 64) -> str:
        """Convert bytes to hex string for display."""
        if len(data) > max_len:
            data = data[:max_len]
        return ' '.join(f'{b:02x}' for b in data)
    
    def analyze(self, packet: Packet) -> Optional[List[PluginAlert]]:
        if not packet.haslayer(Raw):
            return None
        
        alerts = []
        raw_bytes = packet[Raw].load
        self.packets_deep_inspected += 1
        
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        
        # === SHELLCODE DETECTION ===
        for name, pattern in self.shellcode_patterns.items():
            if pattern in raw_bytes:
                self.shellcode_matches += 1
                # Find offset and create hex dump
                offset = raw_bytes.find(pattern)
                context = raw_bytes[max(0, offset-8):offset+len(pattern)+8]
                
                alerts.append(PluginAlert(
                    plugin_name=self.get_info().name,
                    severity=AlertSeverity.CRITICAL,
                    message=f"SHELLCODE DETECTED: {name} pattern at offset {offset}",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    payload_hex=self._bytes_to_hex(context),
                    metadata={
                        "pattern_name": name,
                        "offset": offset,
                        "payload_size": len(raw_bytes)
                    }
                ))
        
        # === SUSPICIOUS BYTE CHECK ===
        for marker in self.suspicious_bytes:
            if marker in raw_bytes:
                alerts.append(PluginAlert(
                    plugin_name=self.get_info().name,
                    severity=AlertSeverity.HIGH,
                    message=f"Suspicious bytes detected: {marker[:20]}",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    metadata={"marker": str(marker[:30])}
                ))
                break  # One alert per packet for markers
        
        # === SENSITIVE DATA DETECTION ===
        try:
            payload_text = raw_bytes.decode('utf-8', errors='ignore')
            
            for pattern_name, pattern in self.sensitive_patterns.items():
                match = pattern.search(payload_text)
                if match:
                    self.sensitive_matches += 1
                    matched_value = match.group(0)
                    
                    # Special handling for credit cards
                    if pattern_name == "credit_card":
                        digits = ''.join(c for c in matched_value if c.isdigit())
                        if not self._luhn_check(digits):
                            continue  # Skip if Luhn check fails
                        # Mask the card number
                        masked = digits[:4] + '*' * (len(digits)-8) + digits[-4:]
                        matched_value = masked
                    else:
                        # Truncate other matches for security
                        if len(matched_value) > 40:
                            matched_value = matched_value[:40] + "..."
                    
                    severity = AlertSeverity.CRITICAL if pattern_name in ["credit_card", "private_key", "ssn"] else AlertSeverity.HIGH
                    
                    alerts.append(PluginAlert(
                        plugin_name=self.get_info().name,
                        severity=severity,
                        message=f"SENSITIVE DATA: {pattern_name.upper()} detected",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        metadata={
                            "pattern_type": pattern_name,
                            "value_preview": matched_value
                        }
                    ))
                    
        except Exception:
            pass
        
        return alerts if alerts else None
    
    def get_statistics(self) -> dict:
        stats = super().get_statistics()
        stats["packets_deep_inspected"] = self.packets_deep_inspected
        stats["sensitive_matches"] = self.sensitive_matches
        stats["shellcode_matches"] = self.shellcode_matches
        return stats


PLUGIN_CLASS = DPIInspectorPlugin
