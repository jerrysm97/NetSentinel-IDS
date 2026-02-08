# NetSentinel IDS

A modular, object-oriented Intrusion Detection System built on Python that demonstrates advanced software engineering principles with practical cybersecurity implementation.

## Features

- **Polymorphic Design**: Pluggable threat detection using Strategy Pattern
- **Multi-threaded Architecture**: Producer-consumer pattern prevents packet loss
- **Three Detection Mechanisms**:
  - SYN Flood (DoS) Detection
  - Plaintext Credential Leakage
  - ARP Spoofing (MITM) Detection

## Requirements

- Linux environment (Ubuntu 20.04+ recommended)
- Python 3.8+
- Root/sudo privileges for packet capture
- VM in Bridged network mode for real traffic

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Start the IDS (requires root)
sudo venv/bin/python3 src/main.py
```

**Note**: Edit `src/main.py` to set your network interface (default: `eth0`).

## Testing

Run these in separate terminals:

```bash
# Terminal 1: Start NetSentinel
sudo venv/bin/python3 src/main.py

# Terminal 2: Run tests
sudo venv/bin/python3 tests/test_syn_flood.py    # DoS simulation
sudo venv/bin/python3 tests/test_plaintext.py   # Credential test
sudo venv/bin/python3 tests/test_arp_spoof.py   # ARP poisoning test
sudo venv/bin/python3 tests/benchmark.py        # Performance test
```

## Architecture

```
ThreatMonitor (ABC)
    ├── SynFloodMonitor   - DoS Detection
    ├── PlainTextMonitor  - Credential Leakage
    └── ARPSpoofMonitor   - MITM Detection
```

## Project Structure

```
NetSentinel/
├── src/
│   ├── main.py              # Entry point
│   ├── netsentinel.py       # Core engine
│   ├── threat_monitor.py    # Abstract base class
│   ├── syn_flood_monitor.py
│   ├── plaintext_monitor.py
│   └── arp_spoof_monitor.py
├── tests/
│   ├── test_syn_flood.py
│   ├── test_plaintext.py
│   ├── test_arp_spoof.py
│   └── benchmark.py
├── logs/
├── config/
│   └── settings.py
└── requirements.txt
```

## License

Educational use only. Use responsibly on networks you own or have explicit permission to monitor.
