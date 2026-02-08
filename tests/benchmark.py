"""
benchmark.py
Measure NetSentinel's packet processing throughput.
"""

import time
import threading
from scapy.all import sniff, conf


class PacketBenchmark:
    """Benchmark packet capture and processing throughput."""
    
    def __init__(self):
        self.packet_count = 0
        self.start_time = None
        self.running = True
        
    def count_packets(self, packet):
        """Callback for each captured packet."""
        self.packet_count += 1
        
    def monitor_rate(self):
        """Print packets per second in real-time."""
        last_count = 0
        while self.running:
            time.sleep(1)
            current_count = self.packet_count
            pps = current_count - last_count
            print(f"Throughput: {pps} packets/sec (Total: {current_count})")
            last_count = current_count
            
    def run(self, duration: int = 30):
        """
        Capture packets and measure processing rate.
        
        Args:
            duration: How many seconds to run the test
        """
        print(f"Starting {duration}-second benchmark on interface: {conf.iface}")
        print("="*50)
        self.start_time = time.time()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_rate, daemon=True)
        monitor_thread.start()
        
        # Capture packets
        try:
            sniff(iface=conf.iface, prn=self.count_packets, timeout=duration, store=False)
        except Exception as e:
            print(f"Capture error: {e}")
        
        self.running = False
        
        # Calculate statistics
        elapsed = time.time() - self.start_time
        avg_pps = self.packet_count / elapsed if elapsed > 0 else 0
        
        print()
        print("="*50)
        print("Benchmark Results:")
        print("="*50)
        print(f"  Duration: {elapsed:.2f} seconds")
        print(f"  Total Packets: {self.packet_count}")
        print(f"  Average Rate: {avg_pps:.2f} packets/sec")
        print()
        
        # Performance assessment
        if avg_pps >= 10000:
            print("Performance: EXCELLENT")
        elif avg_pps >= 5000:
            print("Performance: GOOD")
        elif avg_pps >= 1000:
            print("Performance: ACCEPTABLE")
        else:
            print("Performance: LOW (consider optimizations)")


if __name__ == "__main__":
    print("NetSentinel Packet Processing Benchmark")
    print()
    benchmark = PacketBenchmark()
    benchmark.run(duration=30)
