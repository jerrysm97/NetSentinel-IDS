"""
netsentinel.py
Core IDS engine implementing producer-consumer pattern with shared alert file.

Production Features:
- Poison pill shutdown for clean thread termination
- Allowlist filtering to ignore trusted IPs early
- Shared JSON alert file for dashboard integration
- Thread-safe alert logging
"""

import threading
import queue
import json
import logging
import os
from datetime import datetime
from typing import List, Set

from colorama import init, Fore, Style
from scapy.all import sniff, conf, IP

from threat_monitor import ThreatMonitor

# Initialize colorama
init(autoreset=True)

# Sentinel for shutdown
POISON_PILL = None

# Shared alert file path
ALERTS_FILE = "logs/alerts.json"


import sqlite3

class AlertLogger:
    """Thread-safe alert logger that writes to shared JSON file and SQLite DB."""
    
    def __init__(self, filepath: str, db_path: str = "net_sentinel.db"):
        self.filepath = filepath
        self.db_path = db_path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        """Initialize DB table if it doesn't exist (fallback)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert (
                        id INTEGER PRIMARY KEY,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        alert_type VARCHAR(100) NOT NULL,
                        source_ip VARCHAR(50),
                        details TEXT,
                        severity VARCHAR(20)
                    )
                ''')
                conn.commit()
        except Exception as e:
            logging.error(f"DB Init failed: {e}")
        
    def log(self, alert: dict):
        """Append alert to JSON file and SQLite DB (thread-safe)."""
        timestamp = datetime.now()
        alert["timestamp"] = timestamp.isoformat()
        line = json.dumps(alert) + "\n"
        
        with self.lock:
            # Write to JSON (Backup)
            try:
                with open(self.filepath, 'a') as f:
                    f.write(line)
            except Exception as e:
                logging.error(f"Failed to write alert to JSON: {e}")
            
            # Write to SQLite (Primary)
            try:
                # Parse alert message for fields
                # Expected format differs by monitor, but usually contains "IP: <ip>" or similar
                # We'll treat the whole message as 'details' and try to extract IP/Type
                
                alert_type = "Threat Detected"
                severity = alert.get("severity", "INFO")
                message = alert.get("message", "")
                source_ip = "Unknown"
                
                # Simple heuristic extraction
                if "SYN Flood" in message: alert_type = "SYN Flood"
                elif "Plaintext" in message: alert_type = "Credential Leak"
                elif "ARP Spoofing" in message: alert_type = "ARP Spoofing"
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO alert (timestamp, alert_type, source_ip, details, severity) VALUES (?, ?, ?, ?, ?)",
                        (timestamp, alert_type, source_ip, message, severity)
                    )
                    conn.commit()
            except Exception as e:
                logging.error(f"Failed to write alert to DB: {e}")
                
    def clear(self):
        """Clear the alert file."""
        with self.lock:
            try:
                with open(self.filepath, 'w') as f:
                    f.write('')
            except Exception:
                pass


class NetSentinel:
    """
    Main IDS engine coordinating packet capture and analysis.
    
    Production Features:
    - Allowlist filtering (drops benign traffic early)
    - Poison pill shutdown (clean thread termination)
    - Shared alert file for dashboard integration
    """
    
    def __init__(self, interface: str = "eth0", config_path: str = "config/allowlist.json"):
        self.interface = interface
        self.monitors: List[ThreatMonitor] = []
        
        # Thread-safe queue
        self.packet_queue = queue.Queue(maxsize=2000)
        
        # Control flag
        self.is_running = False
        
        # Alert logger for dashboard integration
        self.alert_logger = AlertLogger(ALERTS_FILE)
        
        # Load configuration
        self.allowed_ips: Set[str] = set()
        self.trusted_bindings: dict = {}
        self._load_config(config_path)
        
        # Setup logging
        self._setup_logging()
        
        # Validate interface
        self._validate_interface()
        
        # Stats
        self.packets_captured = 0
        self.packets_filtered = 0
        self.alerts_generated = 0
        
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
        """Configure logging."""
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
        """Verify network interface."""
        available = conf.ifaces
        
        if self.interface not in available:
            self.logger.warning(f"Interface '{self.interface}' not found")
            self.logger.info(f"Available: {list(available.keys())}")
            
        self.logger.info(f"Target interface: {self.interface}")
        
    def add_monitor(self, monitor: ThreatMonitor):
        """Register a threat monitor."""
        self.monitors.append(monitor)
        self.logger.info(f"Registered: {monitor.name}")
        
    def get_trusted_bindings(self) -> dict:
        """Return trusted IP-MAC bindings."""
        return self.trusted_bindings
        
    def _packet_callback(self, packet):
        """Producer: Handle captured packets."""
        self.packets_captured += 1
        
        # Early filtering
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in self.allowed_ips:
                self.packets_filtered += 1
                return
        
        try:
            self.packet_queue.put(packet, timeout=1)
        except queue.Full:
            self.logger.warning("Queue full - dropping packet")
            
    def _analysis_loop(self):
        """Consumer: Process and analyze packets."""
        self.logger.info("Analysis engine started")
        
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                
                # Poison pill shutdown
                if packet is POISON_PILL:
                    self.logger.info("Received shutdown signal")
                    break
                
                # Distribute to monitors
                for monitor in self.monitors:
                    try:
                        alert = monitor.inspect(packet)
                        
                        if alert:
                            self.alerts_generated += 1
                            
                            # Determine severity
                            if "CRITICAL" in alert:
                                severity = "CRITICAL"
                            elif "DANGER" in alert:
                                severity = "DANGER"
                            else:
                                severity = "INFO"
                            
                            # Write to shared alert file
                            self.alert_logger.log({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "severity": severity,
                                "monitor": monitor.name,
                                "message": alert
                            })
                            
                            # Console output
                            if severity == "CRITICAL":
                                print(f"{Fore.RED}{alert}{Style.RESET_ALL}")
                            elif severity == "DANGER":
                                print(f"{Fore.YELLOW}{alert}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.CYAN}{alert}{Style.RESET_ALL}")
                                
                            self.logger.warning(alert)
                            
                    except Exception as e:
                        self.logger.error(f"Monitor {monitor.name} error: {e}")
                        
            except queue.Empty:
                if not self.is_running:
                    break
                continue
            except Exception as e:
                self.logger.error(f"Analysis error: {e}")
                
    def start(self):
        """Start the IDS engine."""
        self.is_running = True
        
        if not self.monitors:
            self.logger.error("No monitors registered.")
            return
        
        # Clear old alerts on start
        self.alert_logger.clear()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}NetSentinel IDS - Production Mode")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Interface: {self.interface}")
        print(f"Monitors: {len(self.monitors)}")
        for m in self.monitors:
            print(f"  • {m.name}")
        print(f"Allowed IPs: {len(self.allowed_ips)}")
        print(f"Trusted MACs: {len(self.trusted_bindings)}")
        print(f"Alert File: {ALERTS_FILE}")
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
        """Graceful shutdown with poison pill."""
        self.is_running = False
        
        try:
            self.packet_queue.put(POISON_PILL, timeout=1)
        except queue.Full:
            pass
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Session Statistics")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Packets Captured: {self.packets_captured}")
        print(f"Packets Filtered: {self.packets_filtered}")
        print(f"Alerts Generated: {self.alerts_generated}")
        print()
        
        for monitor in self.monitors:
            stats = monitor.get_statistics()
            print(f"{stats['monitor_name']}:")
            for key, value in stats.items():
                if key != 'monitor_name':
                    print(f"  {key}: {value}")
            
        print(f"\n{Fore.GREEN}NetSentinel stopped{Style.RESET_ALL}\n")
