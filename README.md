# NetSentinel + Scam Sentinel

**Production-Ready Cybersecurity Command Center**

A modular Intrusion Detection System with integrated URL risk analyzer.

## Features

### NetSentinel IDS
| Monitor | Detection | Security |
|---------|-----------|----------|
| SYN Flood | DoS attacks | LRU bounded counter |
| Plaintext | Credential leaks | Fast byte search |
| ARP Spoof | MITM attacks | TTL cache + trusted bindings |

### Scam Sentinel URL Analyzer
- **Domain Age**: WHOIS analysis (new domains flagged)
- **SSL Certificates**: Issuer validation
- **Content Analysis**: Urgency keywords, scam patterns
- **URL Patterns**: Suspicious structures detected
- **DNS Configuration**: MX/SPF record checks

## Quick Start

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run Dashboard (Browser Mode)
python3 dashboard.py
# Open http://localhost:8080

# Run IDS Engine (Linux + root)
sudo venv/bin/python3 src/main.py
```

## Dashboard

The web dashboard provides:
- 📊 Real-time IDS statistics
- 🔍 URL risk analyzer with detailed signals
- 🚨 Live alert feed with search
- 📜 Analysis history tracking

## Architecture

```
┌──────────────────────────────────────────┐
│         Production Dashboard             │
│  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Alerts   │  │ URL      │  │ History│ │
│  │ Panel    │  │ Analyzer │  │ Panel  │ │
│  └────┬─────┘  └────┬─────┘  └────────┘ │
│       │             │                    │
│       ▼             ▼                    │
│  ┌────────────────────────────────────┐  │
│  │     logs/alerts.json (shared)      │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
                    ▲
                    │ Writes
┌──────────────────────────────────────────┐
│           NetSentinel IDS Engine         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │ SYN Flood│ │ Plaintext│ │ARP Spoof │ │
│  │ Monitor  │ │ Monitor  │ │ Monitor  │ │
│  └──────────┘ └──────────┘ └──────────┘ │
└──────────────────────────────────────────┘
```

## Configuration

Edit `config/allowlist.json`:
```json
{
    "trusted_ips": {"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
    "allowed_ips": ["127.0.0.1"]
}
```

## Security Hardening

- LRU eviction (max 10k entries)
- TTL expiration (5 min cache)
- Fast path analysis (byte search before regex)
- Poison pill shutdown
- Thread-safe logging

## License

Educational use. Only monitor networks you own.
