"""
test_arp_spoof.py
Simulate ARP cache poisoning for testing.
WARNING: Only run in isolated test environment.
"""

import time
from scapy.all import ARP, send, get_if_hwaddr, conf


def simulate_arp_spoof(target_ip: str, fake_mac: str):
    """
    Send fake ARP reply to simulate poisoning.
    
    Args:
        target_ip: IP to poison
        fake_mac: Attacker MAC address
    """
    # First, send legitimate ARP
    real_mac = get_if_hwaddr(conf.iface)
    legitimate = ARP(op=2, psrc=target_ip, hwsrc=real_mac)
    send(legitimate, verbose=False)
    print(f"Sent legitimate ARP: {target_ip} is-at {real_mac}")
    
    time.sleep(2)
    
    # Now send poisoned ARP with different MAC
    poisoned = ARP(op=2, psrc=target_ip, hwsrc=fake_mac)
    send(poisoned, verbose=False)
    print(f"Sent poisoned ARP: {target_ip} is-at {fake_mac}")
    
    print("\nTest complete - check NetSentinel for ARP spoofing alert")


if __name__ == "__main__":
    # Use a common router IP for testing
    ROUTER_IP = "192.168.1.1"
    FAKE_MAC = "aa:bb:cc:dd:ee:ff"
    
    print("="*50)
    print("WARNING: Only run this on YOUR OWN test network!")
    print("ARP spoofing can disrupt network connectivity.")
    print("="*50)
    print()
    
    print("Simulating ARP spoofing attack...")
    simulate_arp_spoof(ROUTER_IP, FAKE_MAC)
