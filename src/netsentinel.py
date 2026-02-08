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

from plugin_engine import PluginLoader, PluginAlert, AlertSeverity

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
        """Initialize DB table if it doesn't exist."""
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
            
    def log_plugin_alert(self, alert: PluginAlert):
        """Append PluginAlert to JSON and SQLite DB."""
        alert_dict = alert.to_dict()
        line = json.dumps(alert_dict) + "\n"
        
        with self.lock:
            # Write to JSON (Backup)
            try:
                with open(self.filepath, 'a') as f:
                    f.write(line)
            except Exception as e:
                logging.error(f"Failed to write alert to JSON: {e}")
            
            # Write to SQLite (Primary)
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO alert (timestamp, alert_type, source_ip, details, severity) VALUES (?, ?, ?, ?, ?)",
                        (alert.timestamp, alert.plugin_name, alert.source_ip or "Unknown", alert.message, alert.severity.name)
                    )
                    conn.commit()
            except Exception as e:
                logging.error(f"Failed to write alert to DB: {e}")

    def log(self, alert: dict):
        """Legacy support for dict alerts."""
        timestamp = datetime.now()
        alert["timestamp"] = timestamp.isoformat()
        line = json.dumps(alert) + "\n"
        
        with self.lock:
            try:
                with open(self.filepath, 'a') as f:
                    f.write(line)
            except Exception: pass
            
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO alert (timestamp, alert_type, source_ip, details, severity) VALUES (?, ?, ?, ?, ?)",
                        (timestamp, alert.get("monitor", "Threat"), "Unknown", alert.get("message", ""), alert.get("severity", "INFO"))
                    )
                    conn.commit()
            except Exception: pass
                
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
    Main IDS engine coordinating packet capture and analysis via plugins.
    """
    
    def __init__(self, interface: str = "eth0", plugins_dir: str = "plugins", config_path: str = "config/allowlist.json"):
        self.interface = interface
        self.plugin_loader = PluginLoader(plugins_dir)
        
        # Thread-safe queue
        self.packet_queue = queue.Queue(maxsize=5000)
        
        # Control flag
        self.is_running = False
        
        # Alert logger
        self.alert_logger = AlertLogger(ALERTS_FILE)
        
        # Load configuration
        self.allowed_ips: Set[str] = set()
        self._load_config(config_path)
        
        self._setup_logging()
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
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load config: {e}{Style.RESET_ALL}")
        
    def _setup_logging(self):
        """Configure logging."""
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler('logs/netsentinel.log'), logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)
        
    def _validate_interface(self):
        """Verify network interface."""
        available = conf.ifaces
        if self.interface not in available:
            self.logger.warning(f"Interface '{self.interface}' not found")
        self.logger.info(f"Target interface: {self.interface}")
        
    def _packet_callback(self, packet):
        """Producer: Handle captured packets."""
        self.packets_captured += 1
        
        if packet.haslayer(IP):
            if packet[IP].src in self.allowed_ips:
                self.packets_filtered += 1
                return
        
        try:
            self.packet_queue.put(packet, block=False)
        except queue.Full:
            pass
            
    def _analysis_loop(self):
        """Consumer: Process packets through plugins."""
        self.logger.info("Cortex Analysis Engine started")
        
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                
                if packet is POISON_PILL:
                    break
                
                # Analyze via plugins
                alerts = self.plugin_loader.analyze_packet(packet)
                
                if alerts:
                    for alert in alerts:
                        self.alerts_generated += 1
                        self.alert_logger.log_plugin_alert(alert)
                        print(str(alert))
                        self.logger.warning(f"[{alert.plugin_name}] {alert.message}")
                        
            except queue.Empty:
                if not self.is_running:
                    break
            except Exception as e:
                self.logger.error(f"Analysis error: {e}")
                
    def start(self):
        """Start the IDS engine."""
        self.is_running = True
        
        # Load plugins
        loaded_count = self.plugin_loader.load_all_plugins()
        if loaded_count == 0:
            self.logger.error("No plugins loaded. Exiting.")
            return
        
        self.alert_logger.clear()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}NetSentinel Cortex v2.0 - Active Monitoring")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Interface: {self.interface}")
        print(f"Plugins: {loaded_count}")
        print(f"Alert File: {ALERTS_FILE}")
        print(f"\nPress Ctrl+C to stop\n")
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        analysis_thread.start()
        
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger.error(f"Sniffer error: {e}")
            self.stop()
            
    def stop(self):
        """Graceful shutdown."""
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
        
        stats = self.plugin_loader.get_all_statistics()
        for plugin_id, pstats in stats.items():
            print(f"{pstats['plugin_name']}:")
            print(f"  Packets: {pstats['packets_analyzed']}")
            print(f"  Alerts: {pstats['alerts_generated']}\n")
            
        print(f"{Fore.GREEN}NetSentinel Cortex stopped{Style.RESET_ALL}\n")

