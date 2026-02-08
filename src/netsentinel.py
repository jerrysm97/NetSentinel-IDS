"""
netsentinel.py
Core engine implementing producer-consumer pattern for packet analysis.
"""

import threading
import queue
import time
import logging
import os
from datetime import datetime
from typing import List

from colorama import init, Fore, Style
from scapy.all import sniff, conf

from threat_monitor import ThreatMonitor

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class NetSentinel:
    """
    Main IDS engine coordinating packet capture and analysis.
    
    Architecture:
        Uses a multi-threaded design to separate I/O-bound operations
        (packet capture) from CPU-bound operations (analysis).
        
        Thread 1 (Sniffer): Runs Scapy's sniff() function, pushing packets
                           to a thread-safe queue as they arrive.
                           
        Thread 2 (Analyzer): Continuously pulls packets from the queue,
                            distributing them to all registered monitors.
    """
    
    def __init__(self, interface: str = "eth0"):
        """
        Initialize the NetSentinel engine.
        
        Args:
            interface: Network interface to monitor (e.g., "eth0")
        """
        self.interface = interface
        self.monitors: List[ThreatMonitor] = []
        
        # Thread-safe queue for packet passing
        # maxsize=1000 prevents memory exhaustion under extreme load
        self.packet_queue = queue.Queue(maxsize=1000)
        
        # Control flag for graceful shutdown
        self.is_running = False
        
        # Setup logging
        self._setup_logging()
        
        # Validate network interface
        self._validate_interface()
        
    def _setup_logging(self):
        """Configure logging with both file and console output."""
        # Ensure logs directory exists
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
        """
        Verify that the specified interface exists and is accessible.
        
        Raises:
            ValueError: If interface doesn't exist
            PermissionError: If insufficient privileges
        """
        available_interfaces = conf.ifaces
        
        if self.interface not in available_interfaces:
            self.logger.warning(f"Interface '{self.interface}' not found")
            self.logger.info(f"Available interfaces: {list(available_interfaces.keys())}")
            # Don't raise error, just warn - interface might be valid on target system
            
        self.logger.info(f"Target interface: {self.interface}")
        
    def add_monitor(self, monitor: ThreatMonitor):
        """
        Register a new threat detection monitor.
        
        Args:
            monitor: ThreatMonitor instance to add to the pipeline
        """
        self.monitors.append(monitor)
        self.logger.info(f"Registered monitor: {monitor.name}")
        
    def _packet_callback(self, packet):
        """
        Producer: Called by Scapy for each captured packet.
        
        Args:
            packet: Captured packet from network interface
        """
        try:
            # Non-blocking put with timeout to prevent deadlock
            self.packet_queue.put(packet, timeout=1)
        except queue.Full:
            # Queue full indicates analysis can't keep pace
            # In production, this would trigger backpressure alerts
            self.logger.warning("Packet queue full - dropping packet")
            
    def _analysis_loop(self):
        """
        Consumer: Continuously processes packets from queue.
        
        This runs in a separate thread, pulling packets and distributing
        them to all registered monitors for analysis.
        """
        self.logger.info("Analysis engine started")
        
        while self.is_running:
            try:
                # Block for up to 1 second waiting for packets
                packet = self.packet_queue.get(timeout=1)
                
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
                            
                        # Also log to file
                        self.logger.warning(alert)
                        
            except queue.Empty:
                # No packets available, continue loop
                continue
            except Exception as e:
                self.logger.error(f"Analysis error: {e}")
                
    def start(self):
        """
        Start the IDS engine.
        
        This method blocks until interrupted with Ctrl+C.
        """
        self.is_running = True
        
        # Verify we have monitors registered
        if not self.monitors:
            self.logger.error("No monitors registered. Add at least one before starting.")
            return
            
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}NetSentinel IDS - Starting")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"Interface: {self.interface}")
        print(f"Monitors Active: {len(self.monitors)}")
        for monitor in self.monitors:
            print(f"  - {monitor.name}")
        print(f"\nPress Ctrl+C to stop\n")
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        analysis_thread.start()
        
        try:
            # Start packet capture (blocking call)
            # prn=callback function for each packet
            # store=False prevents memory buildup
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
        """Gracefully shut down the engine."""
        self.is_running = False
        
        # Print statistics
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Session Statistics")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        for monitor in self.monitors:
            stats = monitor.get_statistics()
            print(f"{stats['monitor_name']}: {stats['total_alerts']} alerts")
            
        print(f"\n{Fore.GREEN}NetSentinel stopped successfully{Style.RESET_ALL}\n")
