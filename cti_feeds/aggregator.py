"""Core CTI feed aggregator — fetches, parses, normalizes, and deduplicates IOCs."""

import csv
import io
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from .models import IOC, IOCType, ThreatType, FeedResult

logger = logging.getLogger("cti-feeds")

# ─── Feed URLs (all free, no API key) ───
FEEDS = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "Malicious URLs (recent 30 days)",
        "provider": "abuse.ch",
    },
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "description": "Feodo/Emotet/Dridex C2 server IPs",
        "provider": "abuse.ch",
    },
    "malwarebazaar": {
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "description": "Recent malware samples (SHA256 hashes)",
        "provider": "abuse.ch",
    },
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "description": "Recent IOCs from ThreatFox",
        "provider": "abuse.ch",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "description": "Compromised IP addresses",
        "provider": "Proofpoint/ET",
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "description": "IPs detected attacking services",
        "provider": "blocklist.de",
    },
}

# ─── Regex patterns ───
RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_URL = re.compile(r"^https?://")
RE_DOMAIN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")

USER_AGENT = "CTI-Feeds-Aggregator/0.1.0 (+https://github.com/aiguardai/cti-feeds-aggregator)"


def _classify_ioc(value: str) -> IOCType:
    """Classify an IOC value into its type."""
    value = value.strip()
    if RE_IPV4.match(value):
        return IOCType.IP
    if RE_SHA256.match(value):
        return IOCType.HASH_SHA256
    if RE_SHA1.match(value):
        return IOCType.HASH_SHA1
    if RE_MD5.match(value):
        return IOCType.HASH_MD5
    if RE_URL.match(value):
        return IOCType.URL
    if RE_DOMAIN.match(value):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN


def _fetch_text(url: str, timeout: int = 30) -> str:
    """Fetch text content from URL using stdlib (zero dependencies)."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        # Try UTF-8 first, fall back to latin-1
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")


class CTIAggregator:
    """Aggregates multiple free CTI feeds into normalized IOCs."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._iocs: dict[str, IOC] = {}  # keyed by ioc_value for dedup
        self._results: list[FeedResult] = []

    # ─── Public API ───

    def fetch_all(self) -> list[IOC]:
        """Fetch all supported feeds and return deduplicated IOCs."""
        for feed_name in FEEDS:
            self.fetch(feed_name)
        return list(self._iocs.values())

    def fetch(self, feed_name: str) -> FeedResult:
        """Fetch a single feed by name."""
        if feed_name not in FEEDS:
            raise ValueError(f"Unknown feed: {feed_name}. Available: {list(FEEDS.keys())}")

        feed = FEEDS[feed_name]
        t0 = time.time()
        try:
            text = _fetch_text(feed["url"], self.timeout)
            parser = getattr(self, f"_parse_{feed_name}")
            iocs = parser(text)

            # Deduplicate into main store
            new_count = 0
            for ioc in iocs:
                key = ioc.ioc_value.lower().strip()
                if key not in self._iocs:
                    self._iocs[key] = ioc
                    new_count += 1

            result = FeedResult(
                feed_name=feed_name,
                ioc_count=len(iocs),
                fetch_time=round(time.time() - t0, 2),
                success=True,
                iocs=iocs,
            )
            logger.info(f"[{feed_name}] {len(iocs)} IOCs fetched ({new_count} new) in {result.fetch_time}s")

        except Exception as e:
            result = FeedResult(
                feed_name=feed_name,
                ioc_count=0,
                fetch_time=round(time.time() - t0, 2),
                success=False,
                error=str(e),
            )
            logger.warning(f"[{feed_name}] FAILED: {e}")

        self._results.append(result)
        return result

    def check(self, ioc_value: str) -> Optional[IOC]:
        """Check if a specific IOC exists in fetched data."""
        return self._iocs.get(ioc_value.lower().strip())

    def filter(self, ioc_type: Optional[str] = None, source: Optional[str] = None,
               min_confidence: int = 0) -> list[IOC]:
        """Filter IOCs by type, source, or confidence."""
        results = list(self._iocs.values())
        if ioc_type:
            ioc_type_enum = IOCType(ioc_type)
            results = [i for i in results if i.ioc_type == ioc_type_enum]
        if source:
            results = [i for i in results if i.source == source]
        if min_confidence > 0:
            results = [i for i in results if i.confidence >= min_confidence]
        return results

    def export(self, filepath: str, format: str = "json"):
        """Export IOCs to file (json or csv)."""
        iocs = list(self._iocs.values())
        if format == "json":
            with open(filepath, "w") as f:
                json.dump([i.to_dict() for i in iocs], f, indent=2)
        elif format == "csv":
            with open(filepath, "w", newline="") as f:
                if not iocs:
                    return
                writer = csv.DictWriter(f, fieldnames=iocs[0].to_dict().keys())
                writer.writeheader()
                for ioc in iocs:
                    d = ioc.to_dict()
                    d["tags"] = ";".join(d["tags"])
                    writer.writerow(d)
        else:
            raise ValueError(f"Unsupported format: {format}. Use 'json' or 'csv'.")
        logger.info(f"Exported {len(iocs)} IOCs to {filepath} ({format})")

    def summary(self) -> dict:
        """Return aggregation summary."""
        iocs = list(self._iocs.values())
        return {
            "total_iocs": len(iocs),
            "by_type": {t.value: sum(1 for i in iocs if i.ioc_type == t) for t in IOCType if sum(1 for i in iocs if i.ioc_type == t) > 0},
            "by_source": {r.feed_name: r.ioc_count for r in self._results if r.success},
            "feeds_ok": sum(1 for r in self._results if r.success),
            "feeds_failed": sum(1 for r in self._results if not r.success),
        }

    def clear(self):
        """Clear all fetched data."""
        self._iocs.clear()
        self._results.clear()

    # ─── Feed Parsers ───

    def _parse_urlhaus(self, text: str) -> list[IOC]:
        """Parse URLhaus CSV (recent URLs)."""
        iocs = []
        now = datetime.now(timezone.utc).isoformat()
        for line in text.strip().split("\n"):
            if line.startswith("#") or line.startswith('"id"'):
                continue
            try:
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                if len(row) >= 8:
                    url = row[2].strip('" ')
                    date_added = row[1].strip('" ') if len(row) > 1 else now
                    threat = row[4].strip('" ').lower() if len(row) > 4 else ""
                    tags_str = row[6].strip('" ') if len(row) > 6 else ""
                    tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

                    threat_type = ThreatType.MALWARE_DISTRIBUTION
                    if "phish" in threat:
                        threat_type = ThreatType.PHISHING

                    iocs.append(IOC(
                        ioc_value=url,
                        ioc_type=IOCType.URL,
                        threat_type=threat_type,
                        source="urlhaus",
                        confidence=85,
                        first_seen=date_added,
                        last_seen=now,
                        tags=tags,
                        reference=f"https://urlhaus.abuse.ch/url/{row[0].strip('\" ')}/" if row[0].strip('" ').isdigit() else "",
                    ))
            except Exception:
                continue
        return iocs

    def _parse_feodo(self, text: str) -> list[IOC]:
        """Parse Feodo Tracker IP blocklist."""
        iocs = []
        now = datetime.now(timezone.utc).isoformat()
        for line in text.strip().split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if RE_IPV4.match(line):
                iocs.append(IOC(
                    ioc_value=line,
                    ioc_type=IOCType.IP,
                    threat_type=ThreatType.C2_SERVER,
                    source="feodo",
                    confidence=90,
                    first_seen=now,
                    last_seen=now,
                    tags=["botnet", "c2"],
                    reference=f"https://feodotracker.abuse.ch/browse/host/{line}/",
                ))
        return iocs

    def _parse_malwarebazaar(self, text: str) -> list[IOC]:
        """Parse MalwareBazaar recent samples CSV."""
        iocs = []
        now = datetime.now(timezone.utc).isoformat()
        for line in text.strip().split("\n"):
            if line.startswith("#") or line.startswith('"first_seen'):
                continue
            try:
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                if len(row) >= 8:
                    sha256 = row[1].strip('" ')
                    if RE_SHA256.match(sha256):
                        date = row[0].strip('" ') if row[0] else now
                        sig = row[5].strip('" ') if len(row) > 5 else ""
                        tags_str = row[7].strip('" ') if len(row) > 7 else ""
                        tags = [t.strip() for t in tags_str.split(",") if t.strip()]
                        if sig:
                            tags.append(sig)

                        iocs.append(IOC(
                            ioc_value=sha256,
                            ioc_type=IOCType.HASH_SHA256,
                            threat_type=ThreatType.MALWARE_SAMPLE,
                            source="malwarebazaar",
                            confidence=95,
                            first_seen=date,
                            last_seen=now,
                            tags=tags,
                            reference=f"https://bazaar.abuse.ch/sample/{sha256}/",
                        ))
            except Exception:
                continue
        return iocs

    def _parse_threatfox(self, text: str) -> list[IOC]:
        """Parse ThreatFox recent IOCs CSV."""
        iocs = []
        now = datetime.now(timezone.utc).isoformat()
        for line in text.strip().split("\n"):
            if line.startswith("#") or line.startswith('"first_seen'):
                continue
            try:
                reader = csv.reader(io.StringIO(line))
                row = next(reader)
                if len(row) >= 6:
                    ioc_value = row[2].strip('" ')
                    ioc_type_str = row[1].strip('" ').lower()
                    threat = row[4].strip('" ').lower() if len(row) > 4 else ""
                    malware = row[5].strip('" ') if len(row) > 5 else ""

                    # Classify
                    if "url" in ioc_type_str:
                        ioc_type = IOCType.URL
                    elif "ip" in ioc_type_str:
                        # ThreatFox format: ip:port
                        ioc_value = ioc_value.split(":")[0]
                        ioc_type = IOCType.IP
                    elif "domain" in ioc_type_str:
                        ioc_type = IOCType.DOMAIN
                    elif "sha256" in ioc_type_str or "hash" in ioc_type_str:
                        ioc_type = IOCType.HASH_SHA256
                    else:
                        ioc_type = _classify_ioc(ioc_value)

                    threat_type = ThreatType.C2_SERVER if "c2" in threat else ThreatType.MALWARE_DISTRIBUTION
                    tags = [malware] if malware else []

                    iocs.append(IOC(
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        threat_type=threat_type,
                        source="threatfox",
                        confidence=80,
                        first_seen=row[0].strip('" ') if row[0] else now,
                        last_seen=now,
                        tags=tags,
                        reference="https://threatfox.abuse.ch/",
                    ))
            except Exception:
                continue
        return iocs

    def _parse_emerging_threats(self, text: str) -> list[IOC]:
        """Parse Emerging Threats compromised IPs."""
        iocs = []
        now = datetime.now(timezone.utc).isoformat()
        for line in text.strip().split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if RE_IPV4.match(line):
                iocs.append(IOC(
                    ioc_value=line,
                    ioc_type=IOCType.IP,
                    threat_type=ThreatType.COMPROMISED,
                    source="emerging_threats",
                    confidence=70,
                    first_seen=now,
                    last_seen=now,
                    tags=["compromised"],
                    reference="https://rules.emergingthreats.net/",
                ))
        return iocs

    def _parse_blocklist_de(self, text: str) -> list[IOC]:
        """Parse blocklist.de all attacks list."""
        iocs = []
        now = datetime.now(timezone.utc).isoformat()
        for line in text.strip().split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if RE_IPV4.match(line):
                iocs.append(IOC(
                    ioc_value=line,
                    ioc_type=IOCType.IP,
                    threat_type=ThreatType.BRUTE_FORCE,
                    source="blocklist_de",
                    confidence=65,
                    first_seen=now,
                    last_seen=now,
                    tags=["attacking", "brute-force"],
                    reference="https://www.blocklist.de/",
                ))
        return iocs
