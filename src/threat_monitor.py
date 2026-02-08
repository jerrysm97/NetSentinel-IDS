"""
threat_monitor.py
Abstract Base Class for all threat detection monitors.
This defines the contract that all concrete monitors must follow.
"""

from abc import ABC, abstractmethod
from typing import Optional


class ThreatMonitor(ABC):
    """
    Abstract base class for polymorphic threat detection.
    
    Each concrete implementation must provide its own inspect() logic,
    allowing the engine to treat all monitors uniformly while enabling
    diverse detection algorithms.
    """
    
    def __init__(self, name: str):
        """
        Initialize the monitor with a human-readable name.
        
        Args:
            name: Identifier for this monitor (used in alerts)
        """
        self.name = name
        self.alert_count = 0
        
    @abstractmethod
    def inspect(self, packet) -> Optional[str]:
        """
        Analyze a packet and return an alert if malicious.
        
        Args:
            packet: Scapy packet object to analyze
            
        Returns:
            Alert string if threat detected, None if benign
            
        Note:
            This method must be implemented by all child classes.
            The engine will call this method polymorphically.
        """
        pass
    
    def get_statistics(self) -> dict:
        """
        Return monitoring statistics.
        
        Returns:
            Dictionary containing alert counts and monitor info
        """
        return {
            "monitor_name": self.name,
            "total_alerts": self.alert_count
        }
