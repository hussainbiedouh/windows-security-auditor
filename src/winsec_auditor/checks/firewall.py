"""Firewall status checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_command, run_powershell, parse_firewall_profiles
from winsec_auditor.config import config

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_firewall() -> list["SecurityFinding"]:
    """Check Windows Firewall status for all profiles."""
    findings: list["SecurityFinding"] = []
    
    # Try PowerShell first for more detailed info
    success, output = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | Format-List",
        timeout=10
    )
    
    if success and output.strip():
        # Parse firewall profiles using utility function
        profiles_data = parse_firewall_profiles(output)
        enabled_count = 0
        
        # Process parsed profiles
        profile_status = {}
        for profile in profiles_data:
            name = profile.get('Name', '')
            enabled_str = profile.get('Enabled', 'False').lower()
            is_enabled = enabled_str == 'true'
            profile_status[name] = is_enabled
            
            if is_enabled:
                enabled_count += 1
                findings.append({
                    "category": "Firewall",
                    "status": "ok",
                    "description": f"{name} Profile: Active",
                    "details": {"profile": name, "enabled": True},
                })
            else:
                findings.append({
                    "category": "Firewall",
                    "status": "warning",
                    "description": f"{name} Profile: Inactive",
                    "details": {"profile": name, "enabled": False},
                })
        
        # Overall status
        if enabled_count == 3:
            findings.append({
                "category": "Firewall",
                "status": "ok",
                "description": "All firewall profiles are enabled",
                "details": {"enabled_profiles": enabled_count},
            })
        elif enabled_count == 0:
            findings.append({
                "category": "Firewall",
                "status": "critical",
                "description": "All firewall profiles are disabled - system is unprotected",
                "details": {"enabled_profiles": enabled_count},
            })
    else:
        # Fallback to netsh
        success, output = run_command(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            timeout=10
        )
        
        if success:
            profiles = ["Domain Profile", "Private Profile", "Public Profile"]
            enabled_count = 0
            
            for profile in profiles:
                if profile in output:
                    status_start = output.find(profile)
                    status_end = output.find('\n', status_start)
                    profile_section = output[status_start:status_end]
                    
                    if 'ON' in profile_section.upper():
                        enabled_count += 1
                        findings.append({
                            "category": "Firewall",
                            "status": "ok",
                            "description": f"{profile}: Active",
                            "details": None,
                        })
                    else:
                        findings.append({
                            "category": "Firewall",
                            "status": "warning",
                            "description": f"{profile}: Inactive",
                            "details": None,
                        })
            
            if enabled_count == 0:
                findings.append({
                    "category": "Firewall",
                    "status": "critical",
                    "description": "All firewall profiles are disabled - system is unprotected",
                    "details": None,
                })
        else:
            findings.append({
                "category": "Firewall",
                "status": "error",
                "description": "Could not retrieve firewall status",
                "details": None,
            })
    
    return findings
