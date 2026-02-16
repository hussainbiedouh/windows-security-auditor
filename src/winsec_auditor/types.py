"""Type definitions for the Windows Security Auditor."""

from typing import TypedDict, Literal, Optional, Protocol, Callable
from datetime import datetime


class SecurityFinding(TypedDict):
    """Represents a single security finding."""
    category: str
    status: Literal["info", "ok", "warning", "critical", "error"]
    description: str
    details: Optional[dict]


# Type alias for list of security findings
SecurityFindings = list[SecurityFinding]


class ScanResult(TypedDict):
    """Represents the complete scan result."""
    timestamp: str
    scan_type: str
    findings: SecurityFindings
    summary: dict


class CheckInfo(TypedDict):
    """Information about an available check."""
    name: str
    description: str
    scan_type: Literal["basic", "full"]


class CheckDefinition(CheckInfo):
    """Complete check definition including the check function."""
    function: Callable[[], list["SecurityFinding"]]


class ProgressCallback(Protocol):
    """Protocol for progress callback functions."""
    
    def __call__(self, message: str) -> None:
        """Report progress update.
        
        Args:
            message: Progress message to display.
        """
        ...
