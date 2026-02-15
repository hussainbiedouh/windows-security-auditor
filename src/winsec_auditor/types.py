"""Type definitions for the Windows Security Auditor."""

from typing import TypedDict, Literal, Optional
from datetime import datetime


class SecurityFinding(TypedDict):
    """Represents a single security finding."""
    category: str
    status: Literal["info", "ok", "warning", "critical", "error"]
    description: str
    details: Optional[dict]


class ScanResult(TypedDict):
    """Represents the complete scan result."""
    timestamp: str
    scan_type: str
    findings: list[SecurityFinding]
    summary: dict


class CheckInfo(TypedDict):
    """Information about an available check."""
    name: str
    description: str
    scan_type: Literal["basic", "full"]
