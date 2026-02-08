import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from netsentinel import NetSentinel


def main():
    """Initialize and start the NetSentinel Cortex IDS."""
    
    # Configuration
    INTERFACE = "lo0"  # Default to loopback for easier testing/dev
    PLUGINS_DIR = "plugins"
    CONFIG_PATH = "config/allowlist.json"
    
    # Check if interface passed as arg
    if len(sys.argv) > 1:
        INTERFACE = sys.argv[1]
    
    # Create engine (Cortex v2.0)
    ids = NetSentinel(
        interface=INTERFACE, 
        plugins_dir=PLUGINS_DIR,
        config_path=CONFIG_PATH
    )
    
    # Start monitoring (blocking call)
    # Note: NetSentinel.start() now handles loading plugins via PluginLoader
    ids.start()


if __name__ == "__main__":
    # Check for root privileges (required for Scapy on most systems)
    if os.geteuid() != 0:
        print("\n\033[91m[!] Error: NetSentinel requires root privileges for packet capture\033[0m")
        print("Please run with: sudo venv/bin/python3 src/main.py")
        print()
        sys.exit(1)
        
    main()
