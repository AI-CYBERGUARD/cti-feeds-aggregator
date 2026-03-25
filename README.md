<p align="center">
  <img src="https://aiguardai.com/og-image.png" alt="CTI Feeds Aggregator" width="600">
</p>

<h1 align="center">CTI Feeds Aggregator</h1>

<p align="center">
  <strong>Open-source Cyber Threat Intelligence feed aggregator for security teams</strong>
</p>

<p align="center">
  <a href="https://github.com/aiguardai/cti-feeds-aggregator/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="https://pypi.org/project/cti-feeds-aggregator/"><img src="https://img.shields.io/badge/pypi-v0.1.0-orange" alt="PyPI"></a>
</p>

---

A lightweight, zero-dependency Python tool that aggregates **free** Cyber Threat Intelligence (CTI) feeds into a normalized, queryable format. No API keys required.

Built and maintained by the team behind **[AIguard](https://aiguardai.com)** — an AI-powered Security as a Service (SECaaS) platform.

## Why?

Most security teams need IOC feeds but don't want to:
- Pay for commercial threat intel platforms just for basic IOC ingestion
- Write custom parsers for each feed format (CSV, JSON, plaintext)
- Maintain deduplication and normalization logic

This tool solves all three. One command, 6 feeds, normalized output.

## Supported Feeds (all free, no API key)

| Feed | Provider | IOC Types | Update Frequency |
|------|----------|-----------|-----------------|
| [URLhaus](https://urlhaus.abuse.ch/) | abuse.ch | Malicious URLs | Every 5 min |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | abuse.ch | C2 server IPs | Every 5 min |
| [MalwareBazaar](https://bazaar.abuse.ch/) | abuse.ch | Malware hashes (SHA256) | Real-time |
| [ThreatFox](https://threatfox.abuse.ch/) | abuse.ch | IOCs (mixed) | Real-time |
| [Emerging Threats](https://rules.emergingthreats.net/) | Proofpoint | Compromised IPs | Daily |
| [Blocklist.de](https://www.blocklist.de/) | blocklist.de | Attacking IPs | Hourly |

## Quick Start

```bash
pip install cti-feeds-aggregator

# Fetch all feeds and print summary
cti-feeds fetch --all

# Export to JSON
cti-feeds fetch --all --format json --output iocs.json

# Export to CSV
cti-feeds fetch --all --format csv --output iocs.csv

# Fetch specific feed only
cti-feeds fetch --feed urlhaus --format json

# Check a specific IOC against all feeds
cti-feeds check --ioc "185.220.101.34"
cti-feeds check --ioc "https://malicious-domain.com/payload.exe"
cti-feeds check --ioc "a1b2c3d4e5f6..."  # SHA256 hash
```

## Python API

```python
from cti_feeds import CTIAggregator

agg = CTIAggregator()

# Fetch all feeds
iocs = agg.fetch_all()
print(f"Total IOCs: {len(iocs)}")

# Query specific IOC
result = agg.check("185.220.101.34")
if result.found:
    print(f"MALICIOUS: {result.source} — {result.threat_type}")

# Filter by type
urls = agg.filter(ioc_type="url")
ips = agg.filter(ioc_type="ip")
hashes = agg.filter(ioc_type="hash")

# Export
agg.export("iocs.json", format="json")
agg.export("iocs.csv", format="csv")
```

## Normalized IOC Format

Every IOC is normalized to a consistent schema:

```json
{
  "ioc_value": "185.220.101.34",
  "ioc_type": "ip",
  "threat_type": "c2_server",
  "source": "feodo_tracker",
  "confidence": 90,
  "first_seen": "2026-03-20T14:22:00Z",
  "last_seen": "2026-03-25T08:15:00Z",
  "tags": ["botnet", "heodo", "emotet"],
  "reference": "https://feodotracker.abuse.ch/browse/host/185.220.101.34/"
}
```

## Integration with AIguard

This tool powers the CTI layer of [AIguard SECaaS platform](https://aiguardai.com), which uses these feeds as input to its 18-layer detection pipeline with 15 AI agents and 12 ML sensors. For enterprise-grade threat detection with autonomous response, see [aiguardai.com](https://aiguardai.com).

## Architecture

```
┌──────────────────────────────────────────────┐
│              CTI Feeds Aggregator             │
├──────────────────────────────────────────────┤
│                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │
│  │URLhaus  │  │ Feodo   │  │MalwareBazaar│  │
│  │ Parser  │  │ Parser  │  │   Parser    │  │
│  └────┬────┘  └────┬────┘  └──────┬──────┘  │
│       │            │              │          │
│  ┌────┴────┐  ┌────┴────┐  ┌─────┴───────┐  │
│  │ThreatFox│  │   ET    │  │ Blocklist.de│  │
│  │ Parser  │  │ Parser  │  │   Parser    │  │
│  └────┬────┘  └────┬────┘  └──────┬──────┘  │
│       │            │              │          │
│       └────────────┼──────────────┘          │
│                    ▼                         │
│          ┌─────────────────┐                 │
│          │   Normalizer    │                 │
│          │  (dedup + tag)  │                 │
│          └────────┬────────┘                 │
│                   ▼                          │
│          ┌─────────────────┐                 │
│          │    Exporter     │                 │
│          │ JSON/CSV/STIX   │                 │
│          └─────────────────┘                 │
└──────────────────────────────────────────────┘
```

## Requirements

- Python 3.10+
- No external dependencies for core functionality
- Optional: `requests` for HTTP fetching (falls back to `urllib`)

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where help is needed:
- Additional feed parsers (MISP, OTX, VirusTotal public feeds)
- STIX 2.1 export format
- Async fetching for faster aggregation
- Unit tests for edge cases in feed parsing

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Related Projects

- **[AIguard](https://aiguardai.com)** — AI-powered SECaaS platform with 15 AI agents, 12 ML sensors, and RL-based defense
- [abuse.ch](https://abuse.ch) — Swiss non-profit tracking malware and botnets
- [MISP Project](https://www.misp-project.org/) — Open-source threat intelligence platform

---

<p align="center">
  Made with care by the <a href="https://aiguardai.com">AIguard</a> team in Barcelona
</p>
