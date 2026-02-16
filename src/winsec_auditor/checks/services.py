"""Running services checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell, parse_services
from winsec_auditor.config import config

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# Services that might be unnecessary and could be security risks
POTENTIALLY_RISKY_SERVICES = [
    "telnet",
    "tftp",
    "ftp",
    "remote registry",
    "ssdp discovery",
    "upnp device host",
]


def check_services() -> list["SecurityFinding"]:
    """Check running system services."""
    findings: list["SecurityFinding"] = []
    
    # Get running services count
    success, output = run_powershell(
        "(Get-Service | Where-Object {$_.Status -eq 'Running'}).Count",
        timeout=30
    )
    
    if success:
        try:
            running_count = int(output.strip())
            findings.append({
                "category": "Services",
                "status": "info",
                "description": f"Running services: {running_count}",
                "details": {"running_count": running_count},
            })
        except ValueError:
            findings.append({
                "category": "Services",
                "status": "info",
                "description": "Running services: count unavailable",
                "details": None,
            })
    
    # Get detailed service list and check for risky ones
    success, output = run_powershell(
        "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
        "Select-Object Name, DisplayName, StartType | Format-List",
        timeout=30
    )
    
    if success:
        try:
            # Parse services using utility function
            services = parse_services(output)

            if not services:
                findings.append({
                    "category": "Services",
                    "status": "info",
                    "description": "No running services data available",
                    "details": None,
                })
            else:
                # Check for potentially risky services
                risky_found = []
                for service in services:
                    # Use .get() with defaults to avoid KeyError
                    name = service.get('Name', '').lower()
                    display = service.get('DisplayName', '').lower()

                    for risky in POTENTIALLY_RISKY_SERVICES:
                        if risky in name or risky in display:
                            risky_found.append(service)
                            break

                if risky_found:
                    for svc in risky_found[:config.max_risky_services_report]:  # Use config
                        display_name = svc.get('DisplayName') or svc.get('Name') or 'Unknown'
                        findings.append({
                            "category": "Services",
                            "status": "warning",
                            "description": f"Potentially unnecessary service running: {display_name}",
                            "details": {
                                "name": svc.get('Name'),
                                "display_name": svc.get('DisplayName'),
                                "start_type": svc.get('StartType'),
                            },
                        })
        except Exception as e:
            findings.append({
                "category": "Services",
                "status": "error",
                "description": f"Error parsing service data: {e}",
                "details": None,
            })
    
    # Check for services running as SYSTEM that might be exploitable
    success, output = run_powershell(
        "Get-WmiObject Win32_Service | Where-Object {$_.State -eq 'Running' -and $_.StartName -eq 'LocalSystem'} | "
        "Select-Object Name, DisplayName | Format-List",
        timeout=30
    )
    
    if success:
        system_services = [l for l in output.split('\n') if l.strip().startswith('Name')]
        system_count = len(system_services)
        
        if system_count > config.system_services_warning_threshold:  # Use config
            findings.append({
                "category": "Services",
                "status": "warning",
                "description": f"High number of services running as SYSTEM: {system_count}",
                "details": {"system_services": system_count},
            })
    
    return findings
