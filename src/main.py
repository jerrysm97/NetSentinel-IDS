"""
main.py
Entry point for NetSentinel IDS.
"""

import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from netsentinel import NetSentinel
from syn_flood_monitor import SynFloodMonitor
from plaintext_monitor import PlainTextMonitor
from arp_spoof_monitor import ARPSpoofMonitor


def main():
    """Initialize and start the IDS with all monitors."""
    
    # Configuration
    INTERFACE = "eth0"  # Change this to match your interface
    
    # Create engine
    ids = NetSentinel(interface=INTERFACE)
    
    # Register all monitors
    ids.add_monitor(SynFloodMonitor(threshold=50))
    ids.add_monitor(PlainTextMonitor())
    ids.add_monitor(ARPSpoofMonitor())
    
    # Start monitoring (blocking call)
    ids.start()


if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: NetSentinel requires root privileges for packet capture")
        print("Please run with: sudo python3 main.py")
        sys.exit(1)
        
    main()
