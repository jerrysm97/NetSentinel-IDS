"""
plugin_engine.py
NetSentinel Cortex v2.0 - Modular Plugin Engine

Provides the foundation for dynamically loading analysis plugins.
Plugins are discovered from the `plugins/` directory and executed
in parallel for each captured packet.
"""

import os
import sys
import importlib
import importlib.util
import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional, Type
from dataclasses import dataclass, field
from enum import Enum, auto
from queue import Queue

from colorama import Fore, Style
from scapy.packet import Packet


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class PluginAlert:
    """Structured alert from a plugin."""
    plugin_name: str
    severity: AlertSeverity
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    payload_hex: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "severity": self.severity.name,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "payload_hex": self.payload_hex,
            "metadata": self.metadata
        }
    
    def __str__(self) -> str:
        colors = {
            AlertSeverity.INFO: Fore.CYAN,
            AlertSeverity.LOW: Fore.GREEN,
            AlertSeverity.MEDIUM: Fore.YELLOW,
            AlertSeverity.HIGH: Fore.RED,
            AlertSeverity.CRITICAL: f"{Fore.RED}{Style.BRIGHT}"
        }
        color = colors.get(self.severity, Fore.WHITE)
        return f"{color}[{self.severity.name}] [{self.plugin_name}] {self.message}{Style.RESET_ALL}"


@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str
    author: str
    description: str
    tags: List[str] = field(default_factory=list)


class AnalysisPlugin(ABC):
    """
    Abstract base class for all NetSentinel analysis plugins.
    
    Plugins must implement:
    - get_info(): Return plugin metadata
    - analyze(packet): Analyze a packet and optionally return alerts
    
    Optional overrides:
    - on_load(): Called when plugin is loaded
    - on_unload(): Called when plugin is unloaded
    - get_statistics(): Return plugin-specific stats
    """
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._packet_count = 0
        self._alert_count = 0
        self._enabled = True
    
    @abstractmethod
    def get_info(self) -> PluginInfo:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def analyze(self, packet: Packet) -> Optional[List[PluginAlert]]:
        """
        Analyze a packet and return any alerts.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            List of PluginAlert objects, or None if no alerts
        """
        pass
    
    def on_load(self) -> None:
        """Called when the plugin is loaded. Override for initialization."""
        pass
    
    def on_unload(self) -> None:
        """Called when the plugin is unloaded. Override for cleanup."""
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Return plugin statistics."""
        info = self.get_info()
        return {
            "plugin_name": info.name,
            "version": info.version,
            "packets_analyzed": self._packet_count,
            "alerts_generated": self._alert_count,
            "enabled": self._enabled
        }
    
    def enable(self) -> None:
        """Enable the plugin."""
        self._enabled = True
        self.logger.info(f"Plugin {self.get_info().name} enabled")
    
    def disable(self) -> None:
        """Disable the plugin."""
        self._enabled = False
        self.logger.info(f"Plugin {self.get_info().name} disabled")
    
    def _process_packet(self, packet: Packet) -> Optional[List[PluginAlert]]:
        """Internal wrapper that tracks statistics."""
        if not self._enabled:
            return None
            
        self._packet_count += 1
        
        try:
            alerts = self.analyze(packet)
            if alerts:
                self._alert_count += len(alerts)
            return alerts
        except Exception as e:
            self.logger.error(f"Error in analyze(): {e}")
            return None


class PluginLoader:
    """
    Dynamically loads and manages analysis plugins.
    
    Plugins are discovered from a specified directory and must:
    1. Be Python files (*.py)
    2. Contain a class that inherits from AnalysisPlugin
    3. Have a module-level `PLUGIN_CLASS` variable pointing to the class
    """
    
    PLUGIN_CLASS_VAR = "PLUGIN_CLASS"
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, AnalysisPlugin] = {}
        self.logger = logging.getLogger("PluginLoader")
        self._lock = threading.Lock()
        
        # Ensure plugins directory exists
        os.makedirs(plugins_dir, exist_ok=True)
    
    def discover_plugins(self) -> List[str]:
        """Discover available plugin files."""
        if not os.path.isdir(self.plugins_dir):
            self.logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return []
        
        plugin_files = []
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                plugin_files.append(filename[:-3])  # Remove .py
        
        return plugin_files
    
    def load_plugin(self, module_name: str) -> Optional[AnalysisPlugin]:
        """Load a single plugin by module name."""
        try:
            # Build full path
            module_path = os.path.join(self.plugins_dir, f"{module_name}.py")
            
            if not os.path.exists(module_path):
                self.logger.error(f"Plugin file not found: {module_path}")
                return None
            
            # Load the module
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                self.logger.error(f"Could not load spec for: {module_name}")
                return None
                
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find the plugin class
            plugin_class = getattr(module, self.PLUGIN_CLASS_VAR, None)
            
            if plugin_class is None:
                # Try to find any class that inherits from AnalysisPlugin
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, AnalysisPlugin) and 
                        attr is not AnalysisPlugin):
                        plugin_class = attr
                        break
            
            if plugin_class is None:
                self.logger.error(f"No AnalysisPlugin found in: {module_name}")
                return None
            
            # Instantiate and initialize
            plugin = plugin_class()
            plugin.on_load()
            
            with self._lock:
                self.plugins[module_name] = plugin
            
            info = plugin.get_info()
            print(f"{Fore.GREEN}>> [PLUGIN] Loaded: {info.name} v{info.version}{Style.RESET_ALL}")
            self.logger.info(f"Loaded plugin: {info.name} v{info.version}")
            
            return plugin
            
        except Exception as e:
            self.logger.error(f"Failed to load plugin {module_name}: {e}")
            print(f"{Fore.RED}>> [PLUGIN ERROR] {module_name}: {e}{Style.RESET_ALL}")
            return None
    
    def load_all_plugins(self) -> int:
        """Load all discovered plugins. Returns count of loaded plugins."""
        discovered = self.discover_plugins()
        loaded = 0
        
        print(f"\n{Fore.CYAN}>> [CORTEX] Discovering plugins in '{self.plugins_dir}/'...{Style.RESET_ALL}")
        
        for module_name in discovered:
            if self.load_plugin(module_name):
                loaded += 1
        
        print(f"{Fore.GREEN}>> [CORTEX] Loaded {loaded}/{len(discovered)} plugins{Style.RESET_ALL}\n")
        return loaded
    
    def unload_plugin(self, module_name: str) -> bool:
        """Unload a plugin."""
        with self._lock:
            if module_name not in self.plugins:
                return False
            
            plugin = self.plugins[module_name]
            plugin.on_unload()
            del self.plugins[module_name]
            
            # Remove from sys.modules
            if module_name in sys.modules:
                del sys.modules[module_name]
            
            print(f"{Fore.YELLOW}>> [PLUGIN] Unloaded: {module_name}{Style.RESET_ALL}")
            return True
    
    def reload_plugin(self, module_name: str) -> Optional[AnalysisPlugin]:
        """Hot-reload a plugin."""
        self.unload_plugin(module_name)
        return self.load_plugin(module_name)
    
    def analyze_packet(self, packet: Packet) -> List[PluginAlert]:
        """Run all plugins on a packet and collect alerts."""
        all_alerts = []
        
        with self._lock:
            plugins = list(self.plugins.values())
        
        for plugin in plugins:
            try:
                alerts = plugin._process_packet(packet)
                if alerts:
                    all_alerts.extend(alerts)
            except Exception as e:
                self.logger.error(f"Plugin error: {e}")
        
        return all_alerts
    
    def get_all_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics from all plugins."""
        with self._lock:
            return {name: plugin.get_statistics() 
                    for name, plugin in self.plugins.items()}
    
    def get_plugin(self, name: str) -> Optional[AnalysisPlugin]:
        """Get a plugin by name."""
        with self._lock:
            return self.plugins.get(name)
    
    def list_plugins(self) -> List[PluginInfo]:
        """List all loaded plugins."""
        with self._lock:
            return [plugin.get_info() for plugin in self.plugins.values()]
