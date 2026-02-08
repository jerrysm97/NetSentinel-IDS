"""
test_syn_flood.py
Generate synthetic SYN flood traffic for testing.
"""

import time
from scapy.all import IP, TCP, send, RandShort


def simulate_syn_flood(target_ip: str, count: int = 100):
    """
    Send SYN packets rapidly to trigger the monitor.
    
    Args:
        target_ip: Destination IP (can be non-existent for testing)
        count: Number of packets to send
    """
    print(f"Simulating SYN flood: {count} packets to {target_ip}")
    
    for i in range(count):
        # Randomize source port to simulate different connections
        packet = IP(dst=target_ip)/TCP(sport=RandShort(), dport=80, flags="S")
        send(packet, verbose=False)
        
        # Small delay to avoid overwhelming the network
        time.sleep(0.01)
        
    print("Test complete")


if __name__ == "__main__":
    # Use a non-routable IP for safety (TEST-NET-1)
    simulate_syn_flood("192.0.2.1", count=60)
