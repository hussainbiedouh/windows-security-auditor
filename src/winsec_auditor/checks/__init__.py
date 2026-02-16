"""Security check modules for Windows Security Auditor."""

from typing import Callable, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding, CheckInfo, CheckDefinition

# Import all check modules
from winsec_auditor.checks import (
    system,
    updates,
    firewall,
    autorun,
    users,
    services,
    registry,
    network,
    security_sw,
    events,
)

# Define available checks with their metadata
# Using TypedDict for type safety - each check has name, description, scan_type, and function
AVAILABLE_CHECKS: dict[str, "CheckDefinition"] = {
    "system": {
        "name": "System Information",
        "description": "Basic system information and resource usage",
        "scan_type": "basic",
        "function": system.check_system,
    },
    "updates": {
        "name": "Windows Updates",
        "description": "Check Windows Update status",
        "scan_type": "basic",
        "function": updates.check_updates,
    },
    "firewall": {
        "name": "Firewall Status",
        "description": "Check Windows Firewall status for all profiles",
        "scan_type": "basic",
        "function": firewall.check_firewall,
    },
    "autorun": {
        "name": "Autorun Programs",
        "description": "Check startup programs with suspicious detection",
        "scan_type": "full",
        "function": autorun.check_autorun,
    },
    "users": {
        "name": "User Accounts",
        "description": "Analyze user accounts and privileges",
        "scan_type": "full",
        "function": users.check_users,
    },
    "services": {
        "name": "Running Services",
        "description": "Enumerate running system services",
        "scan_type": "full",
        "function": services.check_services,
    },
    "registry": {
        "name": "Registry Security",
        "description": "Check registry security settings (UAC, PowerShell policy)",
        "scan_type": "full",
        "function": registry.check_registry,
    },
    "network": {
        "name": "Network Security",
        "description": "Check listening ports and active connections",
        "scan_type": "full",
        "function": network.check_network,
    },
    "security_sw": {
        "name": "Security Software",
        "description": "Check antivirus, firewall, and antispyware status",
        "scan_type": "full",
        "function": security_sw.check_security_software,
    },
    "events": {
        "name": "Event Log Analysis",
        "description": "Analyze event logs for security threats",
        "scan_type": "full",
        "function": events.check_events,
    },
}


def get_checks_for_scan_type(scan_type: str) -> list[str]:
    """Get list of check IDs for a scan type.
    
    Args:
        scan_type: 'basic' or 'full'
        
    Returns:
        List of check IDs.
    """
    if scan_type == "basic":
        return [k for k, v in AVAILABLE_CHECKS.items() if v["scan_type"] == "basic"]
    elif scan_type == "full":
        return list(AVAILABLE_CHECKS.keys())
    return []


def get_check_function(check_id: str) -> Optional[Callable[[], list["SecurityFinding"]]]:
    """Get the function for a specific check.
    
    Args:
        check_id: The check identifier.
        
    Returns:
        The check function or None if not found.
    """
    check = AVAILABLE_CHECKS.get(check_id)
    return check["function"] if check else None


def get_check_info(check_id: str) -> Optional["CheckInfo"]:
    """Get information about a specific check.
    
    Args:
        check_id: The check identifier.
        
    Returns:
        Check info dict or None if not found.
    """
    check = AVAILABLE_CHECKS.get(check_id)
    if check:
        return {
            "name": check["name"],
            "description": check["description"],
            "scan_type": check["scan_type"],
        }
    return None
