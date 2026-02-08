"""
netsentinel.py
Core engine implementing producer-consumer pattern for packet analysis.

Security Fixes:
- Poison pill shutdown for clean thread termination
- Allowlist filtering to ignore trusted IPs early
- Improved error handling
"""

import threading
import queue
import json
import logging
import os
from typing import List, Set

from colorama import init, Fore, Style
from scapy.all import sniff, conf, IP

from threat_monitor import ThreatMonitor

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Sentinel value for clean shutdown
POISON_PILL = None


class NetSentinel:
    """
    Main IDS engine coordinating packet capture and analysis.
    
    Security Features:
    - Allowlist filtering (drops benign traffic early)
    - Poison pill shutdown (clean thread termination)
    - Configurable trusted IP bindings
    """
    
    def __init__(self, interface: str = "eth0", config_path: str = "config/allowlist.json"):
        """
        Initialize the NetSentinel engine.
        
        Args:
            interface: Network interface to monitor
            config_path: Path to allowlist configuration
        """
        self.interface = interface
        self.monitors: List[ThreatMonitor] = []
        
        # Thread-safe queue for packet passing
        self.packet_queue = queue.Queue(maxsize=1000)
        
        # Control flag for graceful shutdown
        self.is_running = False
        
        # Load configuration
        self.allowed_ips: Set[str] = set()
        self.trusted_bindings: dict = {}
        self._load_config(config_path)
        
        # Setup logging
        self._setup_logging()
        
        # Validate network interface
        self._validate_interface()
        
        # Stats
        self.packets_captured = 0
        self.packets_filtered = 0
        
    def _load_config(self, config_path: str):
        """Load allowlist configuration."""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self.allowed_ips = set(config.get("allowed_ips", []))
                    self.trusted_bindings = config.get("trusted_ips", {})
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load config: {e}{Style.RESET_ALL}")
        
    def _setup_logging(self):
        """Configure logging with both file and console output."""
        os.makedirs('logs', exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/netsentinel.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _validate_interface(self):
        """Verify that the specified interface exists."""
        available_interfaces = conf.ifaces
        
        if self.interface not in available_interfaces:
            self.logger.warning(f"Interface '{self.interface}' not found")
            self.logger.info(f"Available: {list(available_interfaces.keys())}")
            
        self.logger.info(f"Target interface: {self.interface}")
        
    def add_monitor(self, monitor: ThreatMonitor):
        """Register a new threat detection monitor."""
        self.monitors.append(monitor)
        self.logger.info(f"Registered monitor: {monitor.name}")
        
    def get_trusted_bindings(self) -> dict:
        """Return trusted IP-MAC bindings for monitors."""
        return self.trusted_bindings
        
    def _packet_callback(self, packet):
        """Producer: Called by Scapy for each captured packet."""
        self.packets_captured += 1
        
        # OPTIMIZATION: Filter allowed IPs early (before queue)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in self.allowed_ips:
                self.packets_filtered += 1
                return  # Drop benign traffic, save CPU
        
        try:
            self.packet_queue.put(packet, timeout=1)
        except queue.Full:
            self.logger.warning("Packet queue full - dropping packet")
            
    def _analysis_loop(self):
        """Consumer: Continuously processes packets from queue."""
        self.logger.info("Analysis engine started")
        
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                
                # POISON PILL: Clean shutdown signal
                if packet is POISON_PILL:
                    self.logger.info("Received shutdown signal")
                    break
                
                # Distribute packet to all monitors polymorphically
                for monitor in self.monitors:
                    alert = monitor.inspect(packet)
                    
                    if alert:
                        # Color-code alerts by severity
                        if "CRITICAL" in alert:
                            print(f"{Fore.RED}{alert}{Style.RESET_ALL}")
                        elif "DANGER" in alert:
                            print(f"{Fore.YELLOW}{alert}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.CYAN}{alert}{Style.RESET_ALL}")
                            
                        self.logger.warning(alert)
                        
            except queue.Empty:
                if not self.is_running:
                    break
                continue
            except Exception as e:
                self.logger.error(f"Analysis error: {e}")
                
    def start(self):
        """Start the IDS engine. Blocks until Ctrl+C."""
        self.is_running = True
        
        if not self.monitors:
            self.logger.error("No monitors registered.")
            return
            
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}NetSentinel IDS - Starting")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"Interface: {self.interface}")
        print(f"Monitors Active: {len(self.monitors)}")
        for monitor in self.monitors:
            print(f"  - {monitor.name}")
        print(f"Allowed IPs (ignored): {len(self.allowed_ips)}")
        print(f"Trusted Bindings: {len(self.trusted_bindings)}")
        print(f"\nPress Ctrl+C to stop\n")
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        analysis_thread.start()
        
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Shutting down...{Style.RESET_ALL}")
            self.stop()
        except Exception as e:
            self.logger.error(f"Sniffer error: {e}")
            self.stop()
            
    def stop(self):
        """Gracefully shut down the engine using poison pill."""
        self.is_running = False
        
        # Send poison pill to unblock consumer thread
        try:
            self.packet_queue.put(POISON_PILL, timeout=1)
        except queue.Full:
            pass
        
        # Print statistics
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Session Statistics")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Packets Captured: {self.packets_captured}")
        print(f"Packets Filtered (allowlist): {self.packets_filtered}")
        print()
        
        for monitor in self.monitors:
            stats = monitor.get_statistics()
            print(f"{stats['monitor_name']}:")
            for key, value in stats.items():
                if key != 'monitor_name':
                    print(f"  {key}: {value}")
            
        print(f"\n{Fore.GREEN}NetSentinel stopped successfully{Style.RESET_ALL}\n")
