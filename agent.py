#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
  Sentinel Agent v6.0 — King Edition: Multi-Method Network Discovery
═══════════════════════════════════════════════════════════════════════════════

  3-Layer Discovery Stack (run as root for full power):
      Layer 1: Scapy ARP Broadcast  — catches stealth/firewalled devices
      Layer 2: Nmap host discovery  — TCP SYN + ICMP probes
      Layer 3: ARP cache parsing    — catches already-cached entries

  All results are merged and deduplicated by MAC address.

  Usage:
      sudo python3 agent.py                  →  Full network discovery
      sudo python3 agent.py <IP>             →  Deep scan (ports + hostname)
      sudo python3 agent.py audit <IP>       →  HTTP credential audit
"""

import sys
import json
import socket
import platform
import subprocess
import re
import os
import base64
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime
from typing import Optional, List, Dict, Tuple


class NetworkScanner:
    """
    King-edition scanner with 3-layer discovery,
    multithreaded port scanning, and credential auditing.
    """

    TOP_PORTS: List[int] = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 502, 554, 993, 995, 3306, 3389, 5900, 8080,
    ]

    CRITICAL_PORTS = frozenset({23, 502, 554, 5900})
    HIGH_RISK_PORTS = frozenset({21, 22, 3389, 445})
    MEDIUM_RISK_PORTS = frozenset({80, 8080, 443, 3306})

    SOCKET_TIMEOUT: float = 0.5
    ARP_TIMEOUT: int = 15
    MAX_PORT_WORKERS: int = 20
    MAX_PING_WORKERS: int = 50

    DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
        ("admin", ""), ("root", "root"), ("root", ""),
        ("user", "user"), ("admin", "admin123"),
    ]

    def __init__(self, interface: str = None):
        self._os_type: str = platform.system() or "Linux"
        self._is_root: bool = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self.interface = interface or self._get_default_interface()
        self._log(f"OS: {self._os_type} | Root: {self._is_root} | Interface: {self.interface}")

    @staticmethod
    def _log(message: str) -> None:
        try:
            print(message, file=sys.stderr, flush=True)
        except Exception:
            pass

    def _get_default_interface(self) -> str:
        """Auto-detect the active network interface."""
        # Try to find a WiFi interface first if on Linux
        if self._os_type == "Linux":
            try:
                # Check for wlan0 or similar that has an IP
                out = subprocess.check_output(
                    "ip -o -4 addr show | awk '{print $2}'", 
                    shell=True, stderr=subprocess.DEVNULL
                ).decode().strip().split('\n')
                for iface in out:
                    if iface.startswith('wlan') or iface.startswith('wl'):
                        return iface
            except Exception:
                pass

        try:
            # Linux: use `ip route` to find the default interface
            out = subprocess.check_output(
                "ip route | grep default | awk '{print $5}' | head -n 1",
                shell=True, stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()
            if out:
                return out
        except Exception:
            pass
            
        return 'eth0'

    # ═══════════════════════════════════════════════════════════════════════════
    #  NETWORK DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _get_local_ip(self) -> str:
        """Get IP address of the bound interface."""
        if self.interface:
            try:
                if self._os_type == "Linux":
                    cmd = f"ip -4 addr show {self.interface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'"
                    out = subprocess.check_output(cmd, shell=True).decode().strip()
                    if out: return out.splitlines()[0]
                elif self._os_type == "Darwin":
                    out = subprocess.check_output(
                        ["ipconfig", "getifaddr", self.interface],
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                    if out: return out
            except Exception:
                pass

        # Fallback to connection method
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0)
            try:
                sock.connect(("10.254.254.254", 1))
                local_ip    = sock.getsockname()[0]
            except Exception:
                local_ip = "127.0.0.1"
            finally:
                sock.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def _get_subnet(self) -> str:
        ip = self._get_local_ip()
        return ".".join(ip.split(".")[:3])

    # ═══════════════════════════════════════════════════════════════════════════
    #  LAYER 1: SCAPY ARP BROADCAST (catches everything)
    # ═══════════════════════════════════════════════════════════════════════════

    def _scapy_arp_scan(self, subnet: str) -> List[Dict]:
        """
        Send ARP 'who-has' broadcast to entire /24 subnet via Scapy.
        This is the most reliable way to find ALL devices including:
        - Devices that block ICMP/ping
        - Stealth-mode phones and IoT
        - Devices behind firewalls
        Requires root/sudo.
        """
        devices = []
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0  # Suppress scapy output

            target = f"{subnet}.0/24"
            self._log(f"Running Scapy ARP broadcast on {target}")

            # Build ARP request: broadcast Ethernet + ARP who-has
            arp_request = ARP(pdst=target)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            # Send and receive (timeout 5s, retry 2x)
            answered, _ = srp(packet, timeout=5, retry=2, verbose=False)

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.lower()

                # Skip broadcast/multicast
                if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue
                if self._is_multicast_or_broadcast(ip):
                    continue

                # Normalize MAC
                parts = mac.split(":")
                if len(parts) == 6:
                    mac = ":".join(p.zfill(2) for p in parts)

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "discovery_method": "scapy_arp",
                })

            self._log(f"Scapy found {len(devices)} device(s)")

        except ImportError:
            self._log("Scapy not installed, skipping Layer 1")
        except PermissionError:
            self._log("Not root — Scapy ARP requires sudo, skipping Layer 1")
        except Exception as e:
            self._log(f"Scapy error: {e}")

        return devices

    # ═══════════════════════════════════════════════════════════════════════════
    #  LAYER 2: NMAP HOST DISCOVERY (TCP SYN + ICMP probes)
    # ═══════════════════════════════════════════════════════════════════════════

    def _nmap_discovery(self, subnet: str) -> List[Dict]:
        """
        Use nmap -sn (host discovery) to find hosts via:
        - ICMP echo/timestamp
        - TCP SYN to port 443
        - TCP ACK to port 80
        - ARP (when on same subnet)
        """
        devices = []
        try:
            target = f"{subnet}.0/24"
            self._log(f"Running Nmap host discovery on {target}")

            cmd = f"nmap -sn -T4 --max-retries 2 {target} -oX -"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60
            )

            if result.returncode != 0 and not result.stdout:
                self._log(f"Nmap failed: {result.stderr[:100]}")
                return devices

            output = result.stdout

            # Parse XML output for hosts
            host_blocks = re.findall(r'<host\s.*?</host>', output, re.DOTALL)
            for block in host_blocks:
                # Get IP
                ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
                mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"', block)
                status_match = re.search(r'<status state="(\w+)"', block)

                if not ip_match:
                    continue

                ip = ip_match.group(1)
                state = status_match.group(1) if status_match else "unknown"

                if state != "up":
                    continue
                if self._is_multicast_or_broadcast(ip):
                    continue

                mac = ""
                if mac_match:
                    mac = mac_match.group(1).lower()
                    parts = mac.split(":")
                    if len(parts) == 6:
                        mac = ":".join(p.zfill(2) for p in parts)

                # Include devices even without MAC (e.g., localhost or non-root scans)
                if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue

                if not mac:
                    # Generate a placeholder MAC from IP so device still appears
                    octets = ip.split(".")
                    mac = f"00:00:00:00:{int(octets[2]):02x}:{int(octets[3]):02x}"

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "discovery_method": "nmap",
                })

            self._log(f"Nmap found {len(devices)} device(s)")

        except FileNotFoundError:
            self._log("Nmap not installed, skipping Layer 2")
        except subprocess.TimeoutExpired:
            self._log("Nmap timed out, skipping Layer 2")
        except Exception as e:
            self._log(f"Nmap error: {e}")

        return devices

    # ═══════════════════════════════════════════════════════════════════════════
    #  LAYER 3: ARP CACHE + IP NEIGH (already-known entries)
    # ═══════════════════════════════════════════════════════════════════════════

    def _arp_cache_scan(self) -> List[Dict]:
        """
        Parse both `arp -a` AND `ip neigh` to catch cached entries.
        Also does a quick ping sweep first to populate the cache.
        """
        self._log("Checking ARP cache + ip neigh")
        devices = []

        # Quick ping sweep to populate cache
        self._ping_sweep()

        # Method A: arp -a
        try:
            raw = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=self.ARP_TIMEOUT
            ).decode("utf-8", errors="ignore")

            for line in raw.splitlines():
                parsed = self._parse_arp_line(line)
                if parsed:
                    ip, mac = parsed
                    devices.append({"ip": ip, "mac": mac, "discovery_method": "arp_cache"})
        except Exception as e:
            self._log(f"arp -a error: {e}")

        # Method B: ip neigh (Linux only, more complete)
        if self._os_type == "Linux":
            try:
                raw = subprocess.check_output(
                    ["ip", "neigh"], stderr=subprocess.DEVNULL, timeout=10
                ).decode("utf-8", errors="ignore")

                for line in raw.splitlines():
                    # Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                    # Strict regex to capture IP at start
                    match = re.search(
                        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+)',
                        line.strip()
                    )
                    if match:
                        ip = match.group(1)
                        mac_raw = match.group(2).lower()
                        parts = mac_raw.split(":")
                        if len(parts) == 6:
                            mac = ":".join(p.zfill(2) for p in parts)
                            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                                if not self._is_multicast_or_broadcast(ip):
                                    devices.append({"ip": ip, "mac": mac, "discovery_method": "ip_neigh"})
            except Exception as e:
                self._log(f"ip neigh error: {e}")

        # Method C: /proc/net/arp (Linux kernel ARP table, most raw)
        if self._os_type == "Linux":
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac_raw = parts[3].lower()
                            if mac_raw not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                                mac_parts = mac_raw.split(":")
                                if len(mac_parts) == 6:
                                    mac = ":".join(p.zfill(2) for p in mac_parts)
                                    if not self._is_multicast_or_broadcast(ip):
                                        devices.append({"ip": ip, "mac": mac, "discovery_method": "proc_arp"})
            except Exception:
                pass

        self._log(f"ARP cache found {len(devices)} entries")
        return devices

    def _ping_host(self, ip: str) -> None:
        try:
            if self._os_type == "Windows":
                subprocess.run(["ping", "-n", "1", "-w", "100", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            else:
                subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass

    def _ping_sweep(self) -> None:
        subnet = self._get_subnet()
        self._log(f"Ping sweep on {subnet}.0/24...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_PING_WORKERS) as executor:
            futures = [executor.submit(self._ping_host, f"{subnet}.{i}") for i in range(1, 255)]
            concurrent.futures.wait(futures, timeout=30)

    # ═══════════════════════════════════════════════════════════════════════════
    #  UNIFIED SCAN — Merges all 3 layers
    # ═══════════════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════════════
    #  UNIFIED SCAN — Merges all 3 layers
    # ═══════════════════════════════════════════════════════════════════════════

    def scan(self) -> dict:
        """
        Master discovery: runs all 3 layers, merges, deduplicates by MAC.
        """
        subnet = self._get_subnet()
        self._log(f"Starting detailed scan on subnet: {subnet}.0/24")

        all_devices = []
        methods_used = []

        # Layer 1: Scapy ARP (most reliable, needs root)
        if self._is_root:
            scapy_results = self._scapy_arp_scan(subnet)
            all_devices.extend(scapy_results)
            if scapy_results:
                methods_used.append("scapy_arp")
        else:
            self._log("Notice: Not running as root. Scapy ARP scan skipped.")

        # Layer 2: Nmap host discovery
        nmap_results = self._nmap_discovery(subnet)
        all_devices.extend(nmap_results)
        if nmap_results:
            methods_used.append("nmap")

        # Layer 3: ARP cache + ip neigh
        arp_results = self._arp_cache_scan()
        all_devices.extend(arp_results)
        if arp_results:
            methods_used.append("arp_cache")

        # Deduplication Strategy:
        # 1. Use a dictionary keyed by MAC address to ensure unique devices.
        # 2. If a MAC is seen again, update the entry but keep the first seen IP (usually most reliable from active scan).
        # 3. Filter out any entries with duplicate IPs that have different MACs (rare config error or spoofing, mostly noise).

        unique_devices_map = {}
        
        for dev in all_devices:
            mac = dev["mac"]
            ip = dev["ip"]
            
            # Skip invalid IPs/MACs
            if not ip or not mac: continue
            if ip.endswith(".0") or ip.endswith(".255"): continue

            if mac not in unique_devices_map:
                unique_devices_map[mac] = dev
            else:
                # Update existing entry with new methods found
                existing = unique_devices_map[mac]
                if dev["discovery_method"] not in existing["discovery_method"]:
                    existing["discovery_method"] += f"+{dev['discovery_method']}"

        # Final pass: Ensure IP uniqueness. If multiple MACs claim the same IP, keep the one from active scan (scapy/nmap)
        # or the most recent one.
        final_devices = []
        seen_ips = set()
        
        # Sort by method priority: scapy > nmap > arp
        sorted_devices = sorted(unique_devices_map.values(), key=lambda x: (
            0 if "scapy" in x["discovery_method"] else 
            1 if "nmap" in x["discovery_method"] else 
            2
        ))

        for dev in sorted_devices:
            if dev["ip"] not in seen_ips:
                seen_ips.add(dev["ip"])
                final_devices.append(dev)

        self._log(f"Scan complete. Found {len(final_devices)} unique devices.")

        return self._build_scan_result(final_devices, methods_used)

    def _parse_arp_line(self, line: str) -> Optional[Tuple[str, str]]:
        ip_addr = None
        mac_addr_raw = None

        if self._os_type == "Windows":
            match = re.search(
                r"((?:\d{1,3}\.){3}\d{1,3})\s+"
                r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-"
                r"[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})",
                line,
            )
            if match:
                ip_addr = match.group(1)
                mac_addr_raw = match.group(2).replace("-", ":")
        else:
            match = re.search(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]+)",
                line,
            )
            if match:
                ip_addr = match.group(1)
                mac_addr_raw = match.group(2)

        if not ip_addr or not mac_addr_raw:
            return None

        try:
            parts = mac_addr_raw.split(":")
            if len(parts) == 6:
                mac_addr = ":".join(p.zfill(2) for p in parts).lower()
            else:
                return None
        except Exception:
            return None

        if mac_addr in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None
        if self._is_multicast_or_broadcast(ip_addr):
            return None

        return (ip_addr, mac_addr)

    @staticmethod
    def _is_multicast_or_broadcast(ip: str) -> bool:
        try:
            first_octet = int(ip.split('.')[0])
            if 224 <= first_octet <= 239:
                return True
            if ip == '255.255.255.255':
                return True
        except (ValueError, IndexError):
            pass
        return False

    def _build_scan_result(self, device_list: list, methods_used: list) -> dict:
        for device in device_list:
            device['last_seen'] = datetime.now().isoformat()

            if device['ip'].endswith('.1') or device['ip'].endswith('.254'):
                device['type'] = 'gateway'
            else:
                device['type'] = 'device'

        return {
            "status": "success",
            "scan_mode": "multi_layer",
            "methods": methods_used,
            "subnet": self._get_subnet(),
            "count": len(device_list),
            "devices": device_list,
            "is_root": self._is_root,
            "timestamp": datetime.now().isoformat(),
        }

    # ═══════════════════════════════════════════════════════════════════════════
    #  DEEP SCAN — Port Scanner
    # ═══════════════════════════════════════════════════════════════════════════

    def deep_scan(self, target_ip: str) -> dict:
        self._log(f"[>] Deep scanning {target_ip} with {self.MAX_PORT_WORKERS} threads...")

        hostname = "Unknown"
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        open_ports: List[dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_PORT_WORKERS) as executor:
            future_to_port = {
                executor.submit(self._probe_port, target_ip, port): port
                for port in self.TOP_PORTS
            }
            for future in concurrent.futures.as_completed(future_to_port):
                try:
                    result = future.result(timeout=5)
                    if result is not None:
                        open_ports.append(result)
                except Exception:
                    pass

        open_ports.sort(key=lambda p: p["port"])
        risk_level = self._classify_risk(open_ports)

        return {
            "ip": target_ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "risk_level": risk_level,
            "timestamp": datetime.now().isoformat(),
        }

    def _probe_port(self, ip: str, port: int) -> Optional[dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)
            if sock.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    sock.send(b"\r\n")
                    raw = sock.recv(128)
                    banner = raw.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                finally:
                    sock.close()
                return {"port": port, "banner": banner}
            sock.close()
        except Exception:
            pass
        return None

    def _classify_risk(self, open_ports: List[dict]) -> str:
        port_numbers = frozenset(p["port"] for p in open_ports)
        if port_numbers & self.CRITICAL_PORTS:
            return "CRITICAL"
        if port_numbers & self.HIGH_RISK_PORTS:
            return "HIGH"
        if port_numbers & self.MEDIUM_RISK_PORTS:
            return "MEDIUM"
        return "LOW"

    # ═══════════════════════════════════════════════════════════════════════════
    #  CREDENTIAL AUDIT
    # ═══════════════════════════════════════════════════════════════════════════

    def audit_credentials(self, target_ip: str) -> dict:
        self._log(f"[>] Auditing credentials on {target_ip}:80...")
        url = f"http://{target_ip}"
        audit_results: List[dict] = []
        reachable = False

        for username, password in self.DEFAULT_CREDENTIALS:
            cred = f"{username}:{password}"
            encoded = base64.b64encode(cred.encode()).decode("utf-8")
            headers = {"Authorization": f"Basic {encoded}"}
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=2) as response:
                    reachable = True
                    if response.getcode() == 200:
                        audit_results.append({"credential": cred, "status": "VULNERABLE"})
            except urllib.error.HTTPError as e:
                reachable = True
                if e.code == 401:
                    audit_results.append({"credential": cred, "status": "REJECTED"})
            except Exception:
                pass

        vuln_count = sum(1 for r in audit_results if r["status"] == "VULNERABLE")

        if vuln_count > 0:
            return {"ip": target_ip, "status": "VULNERABLE", "risk": "CRITICAL",
                    "message": f"{vuln_count} default credential(s) accepted!",
                    "details": audit_results, "timestamp": datetime.now().isoformat()}
        if not reachable:
            return {"ip": target_ip, "status": "SECURE", "risk": "LOW",
                    "message": "No HTTP endpoint on port 80.",
                    "details": [], "timestamp": datetime.now().isoformat()}
        return {"ip": target_ip, "status": "SECURE", "risk": "LOW",
                "message": "All default credentials rejected.",
                "details": audit_results, "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    # Simple CLI argument parsing
    command = "scan"
    target = None
    interface = None
    
    args = sys.argv[1:]
    if args:
        if args[0] == "audit":
            command = "audit"
            target = args[1] if len(args) > 1 else None
        elif args[0] == "scan":
            command = "scan"
            if len(args) > 1:
                interface = args[1]
        elif re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", args[0]):
            command = "deep"
            target = args[0]
        else:
            # Assume it's an interface name if not an IP
            interface = args[0]
            
    scanner = NetworkScanner(interface=interface)

    if command == "scan":
        print(json.dumps(scanner.scan()))
    elif command == "audit":
        if not target:
            print(json.dumps({"error": "Usage: python3 agent.py audit <IP>"}))
        else:
            print(json.dumps(scanner.audit_credentials(target)))
    elif command == "deep":
        print(json.dumps(scanner.deep_scan(target)))