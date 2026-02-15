"""Firewall status checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_command, run_powershell

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
        profiles = ["Domain", "Private", "Public"]
        enabled_count = 0
        
        for profile in profiles:
            if profile in output:
                # Check if enabled
                is_enabled = "True" in output[output.find(profile):output.find(profile)+100]
                
                if is_enabled:
                    enabled_count += 1
                    findings.append({
                        "category": "Firewall",
                        "status": "ok",
                        "description": f"{profile} Profile: Active",
                        "details": {"profile": profile, "enabled": True},
                    })
                else:
                    findings.append({
                        "category": "Firewall",
                        "status": "warning",
                        "description": f"{profile} Profile: Inactive",
                        "details": {"profile": profile, "enabled": False},
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
