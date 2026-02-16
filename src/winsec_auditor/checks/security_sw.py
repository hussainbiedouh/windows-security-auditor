"""Security software checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell, parse_firewall_profiles, parse_av_products
from winsec_auditor.config import config

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# Common AV product states
AV_ACTIVE_STATES = [266240, 266496, 393472]  # Various "active" states from WMI


def _parse_av_products(output: str) -> list[dict]:
    """Parse AV products from PowerShell output.
    
    Args:
        output: PowerShell command output.
        
    Returns:
        List of AV product dictionaries with name and state.
    """
    raw_products = parse_av_products(output)
    av_products = []
    
    for product in raw_products:
        name = product.get('displayName', '')
        state_str = product.get('productState', '')
        try:
            state = int(state_str) if state_str else None
        except ValueError:
            state = None
        
        if name:  # Only add if we have a name
            av_products.append({'name': name, 'state': state})
    
    return av_products


def _get_active_products(av_products: list[dict]) -> list[str]:
    """Get list of active AV product names.
    
    Args:
        av_products: List of AV product dictionaries.
        
    Returns:
        List of active product names (duplicates removed).
    """
    active_products = []
    
    for product in av_products:
        name = product.get('name', 'Unknown')
        state = product.get('state')
        
        if state in AV_ACTIVE_STATES:
            active_products.append(name)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_active = []
    for name in active_products:
        if name not in seen:
            seen.add(name)
            unique_active.append(name)
    
    return unique_active


def _check_windows_defender() -> tuple[bool, str]:
    """Check if Windows Defender is active.
    
    Returns:
        Tuple of (is_active, output_message).
    """
    success, output = run_powershell(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | Format-List",
        timeout=15
    )
    
    if success and 'True' in output:
        return True, "Windows Defender is active"
    return False, ""


def _check_windows_defender_antispyware() -> bool:
    """Check if Windows Defender antispyware is enabled.
    
    Returns:
        True if antispyware is enabled.
    """
    success, output = run_powershell(
        "Get-MpComputerStatus | Select-Object AntispywareEnabled | Format-List",
        timeout=10
    )
    return success and 'True' in output


def _check_installed_antivirus(findings: list["SecurityFinding"]) -> bool:
    """Check for installed antivirus and return True if any found.
    
    Args:
        findings: List to append findings to.
        
    Returns:
        True if antivirus was found (active or not).
    """
    success, output = run_powershell(
        "Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntivirusProduct | "
        "Select-Object displayName, productState | Format-List",
        timeout=15
    )
    
    if not success or not output.strip():
        return False
    
    av_products = _parse_av_products(output)
    
    if not av_products:
        return False
    
    active_products = _get_active_products(av_products)
    
    if active_products:
        findings.append({
            "category": "Security Software",
            "status": "ok",
            "description": f"Active antivirus: {', '.join(active_products)}",
            "details": {"antivirus": active_products},
        })
        return True
    
    # Antivirus installed but not active
    product_names = [p.get('name', 'Unknown') for p in av_products]
    findings.append({
        "category": "Security Software",
        "status": "warning",
        "description": f"Antivirus installed but not active: {', '.join(product_names)}",
        "details": {"antivirus": product_names, "active": False},
    })
    return True


def _check_firewall(findings: list["SecurityFinding"]) -> None:
    """Check Windows Firewall status.
    
    Args:
        findings: List to append findings to.
    """
    success, output = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | Format-List",
        timeout=10
    )
    
    if not success or not output.strip():
        return
    
    profiles = parse_firewall_profiles(output)
    enabled_count = sum(
        1 for p in profiles 
        if p.get('Enabled', '').lower() == 'true'
    )
    
    if enabled_count >= 1:
        findings.append({
            "category": "Security Software",
            "status": "ok",
            "description": f"Windows Firewall is active ({enabled_count}/3 profiles)",
            "details": {"enabled_profiles": enabled_count},
        })
    else:
        findings.append({
            "category": "Security Software",
            "status": "critical",
            "description": "Windows Firewall is not active - security risk",
            "details": {"enabled_profiles": 0},
        })


def _check_antispyware(findings: list["SecurityFinding"]) -> None:
    """Check for antispyware software.
    
    Args:
        findings: List to append findings to.
    """
    # Check for third-party antispyware
    success, output = run_powershell(
        "Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiSpywareProduct | "
        "Select-Object displayName | Format-List",
        timeout=15
    )
    
    if success and output.strip() and 'displayName' in output:
        as_products = [line.split(':', 1)[-1].strip() for line in output.split('\n') if 'displayName' in line]
        if as_products:
            findings.append({
                "category": "Security Software",
                "status": "ok",
                "description": f"Antispyware detected: {', '.join(as_products)}",
                "details": {"antispyware": as_products},
            })
            return
    
    # Check for Windows Defender Antispyware as fallback
    if _check_windows_defender_antispyware():
        findings.append({
            "category": "Security Software",
            "status": "ok",
            "description": "Windows Defender Antispyware is enabled",
            "details": {"antispyware": "Windows Defender"},
        })


def check_security_software() -> list["SecurityFinding"]:
    """Check for installed security software."""
    findings: list["SecurityFinding"] = []
    
    # Check for antivirus - returns True if any AV found
    av_found = _check_installed_antivirus(findings)
    
    # Check Windows Defender as fallback if no other AV found
    if not av_found:
        is_defender_active, _ = _check_windows_defender()
        if is_defender_active:
            findings.append({
                "category": "Security Software",
                "status": "ok",
                "description": "Windows Defender is active",
                "details": {"antivirus": "Windows Defender"},
            })
        else:
            findings.append({
                "category": "Security Software",
                "status": "critical",
                "description": "No antivirus software detected - major security risk",
                "details": {"antivirus": None},
            })
    
    # Check Windows Firewall
    _check_firewall(findings)
    
    # Check for antispyware
    _check_antispyware(findings)
    
    return findings
