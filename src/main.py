"""
main.py
Entry point for NetSentinel IDS.

Note: For safer operation without full root, use Linux capabilities:
  sudo setcap cap_net_raw,cap_net_admin=eip /path/to/venv/bin/python3
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
    CONFIG_PATH = "config/allowlist.json"
    
    # Create engine
    ids = NetSentinel(interface=INTERFACE, config_path=CONFIG_PATH)
    
    # Get trusted bindings from config for ARP monitor
    trusted_bindings = ids.get_trusted_bindings()
    
    # Register all monitors with security features
    ids.add_monitor(SynFloodMonitor(
        threshold=50,
        max_tracked_ips=10000  # LRU eviction after 10k IPs
    ))
    ids.add_monitor(PlainTextMonitor())
    ids.add_monitor(ARPSpoofMonitor(
        trusted_bindings=trusted_bindings,
        max_entries=10000,  # LRU eviction
        ttl_seconds=300     # 5 min TTL for DHCP handling
    ))
    
    # Start monitoring (blocking call)
    ids.start()


if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: NetSentinel requires root privileges for packet capture")
        print("Please run with: sudo python3 main.py")
        print()
        print("For safer operation (recommended), use Linux capabilities:")
        print("  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
        sys.exit(1)
        
    main()
