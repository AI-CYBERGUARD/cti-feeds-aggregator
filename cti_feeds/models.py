"""Data models for normalized IOCs."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional
import json


class IOCType(str, Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    UNKNOWN = "unknown"


class ThreatType(str, Enum):
    C2_SERVER = "c2_server"
    MALWARE_DISTRIBUTION = "malware_distribution"
    PHISHING = "phishing"
    BOTNET = "botnet"
    SCANNER = "scanner"
    BRUTE_FORCE = "brute_force"
    EXPLOIT = "exploit"
    MALWARE_SAMPLE = "malware_sample"
    COMPROMISED = "compromised"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    """Normalized Indicator of Compromise."""
    ioc_value: str
    ioc_type: IOCType
    threat_type: ThreatType = ThreatType.UNKNOWN
    source: str = ""
    confidence: int = 50
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: list = field(default_factory=list)
    reference: str = ""
    raw_data: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ioc_type"] = self.ioc_type.value
        d["threat_type"] = self.threat_type.value
        del d["raw_data"]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @property
    def is_ip(self) -> bool:
        return self.ioc_type == IOCType.IP

    @property
    def is_url(self) -> bool:
        return self.ioc_type == IOCType.URL

    @property
    def is_hash(self) -> bool:
        return self.ioc_type in (IOCType.HASH_SHA256, IOCType.HASH_MD5, IOCType.HASH_SHA1)


@dataclass
class FeedResult:
    """Result from fetching a single feed."""
    feed_name: str
    ioc_count: int
    fetch_time: float
    success: bool
    error: Optional[str] = None
    iocs: list = field(default_factory=list, repr=False)
