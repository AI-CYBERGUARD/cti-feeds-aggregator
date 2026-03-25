"""CTI Feeds Aggregator — Open-source Cyber Threat Intelligence feed aggregator."""

__version__ = "0.1.0"
__author__ = "AIguard Team"
__url__ = "https://aiguardai.com"

from .aggregator import CTIAggregator
from .models import IOC, IOCType, ThreatType

__all__ = ["CTIAggregator", "IOC", "IOCType", "ThreatType"]
