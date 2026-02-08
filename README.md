# NetSentinel IDS

A modular, security-hardened Intrusion Detection System using polymorphic design patterns.

## Security Features (v2.0)

- **LRU Eviction**: Prevents memory exhaustion attacks (max 10k entries)
- **TTL Expiration**: Handles DHCP reassignment false positives
- **Fast Path Analysis**: Byte search before regex (CPU optimization)
- **Allowlist Filtering**: Ignore trusted IPs early
- **Poison Pill Shutdown**: Clean thread termination
- **Static Bindings**: Trusted IP-MAC pairs for critical infrastructure

## Monitors

| Monitor | Detection | Security Fix |
|---------|-----------|--------------|
| SYN Flood | DoS attacks | Bounded counter with LRU |
| Plaintext | Credential leaks | Fast byte search before regex |
| ARP Spoof | MITM attacks | LRU cache + TTL + trusted bindings |

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Console Mode (requires Linux + root)
```bash
sudo venv/bin/python3 src/main.py
```

### Web Dashboard (Demo Mode)
```bash
venv/bin/python3 dashboard.py
# Open http://localhost:5000
```

## Configuration

Edit `config/allowlist.json`:
```json
{
    "trusted_ips": {
        "192.168.1.1": "aa:bb:cc:dd:ee:ff"
    },
    "allowed_ips": ["127.0.0.1"]
}
```

## Project Structure

```
NetSentinel/
├── src/
│   ├── main.py              # Entry point
│   ├── netsentinel.py       # Core engine
│   ├── threat_monitor.py    # Abstract base class
│   ├── syn_flood_monitor.py # LRU-protected DoS detector
│   ├── plaintext_monitor.py # Fast-path credential detector
│   └── arp_spoof_monitor.py # TTL-cached MITM detector
├── dashboard.py             # Web UI
├── config/
│   └── allowlist.json       # Trusted IPs/MACs
├── tests/
└── requirements.txt
```

## License

Educational use only. Monitor networks you own or have permission to access.
