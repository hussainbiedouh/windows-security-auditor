"""Security software checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# Common AV product states
AV_ACTIVE_STATES = [266240, 266496, 393472]  # Various "active" states from WMI


def check_security_software() -> list["SecurityFinding"]:
    """Check for installed security software."""
    findings: list["SecurityFinding"] = []
    
    # Check for antivirus
    success, output = run_powershell(
        "Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntivirusProduct | "
        "Select-Object displayName, productState | Format-List",
        timeout=15
    )
    
    av_found = False
    av_active = False
    
    if success and output.strip():
        lines = output.strip().split('\n')
        av_products = []
        current_product = {}
        
        for line in lines:
            line_lower = line.lower()
            if 'displayname' in line_lower and ':' in line:
                if current_product and 'name' in current_product:
                    av_products.append(current_product)
                current_product = {'name': line.split(':', 1)[-1].strip()}
            elif 'productstate' in line_lower and ':' in line:
                try:
                    state = int(line.split(':', 1)[-1].strip())
                    current_product['state'] = state
                except ValueError:
                    current_product['state'] = None
        
        if current_product and 'name' in current_product:
            av_products.append(current_product)
        
        if av_products:
            av_found = True
            active_products = []
            
            for product in av_products:
                name = product.get('name', 'Unknown')
                state = product.get('state')
                
                if state in AV_ACTIVE_STATES:
                    active_products.append(name)
                    av_active = True
            
            if active_products:
                # Remove duplicates
                seen = set()
                unique_active = []
                for name in active_products:
                    if name not in seen:
                        seen.add(name)
                        unique_active.append(name)
                
                findings.append({
                    "category": "Security Software",
                    "status": "ok",
                    "description": f"Active antivirus: {', '.join(unique_active)}",
                    "details": {"antivirus": unique_active},
                })
            else:
                product_names = [p.get('name', 'Unknown') for p in av_products]
                findings.append({
                    "category": "Security Software",
                    "status": "warning",
                    "description": f"Antivirus installed but not active: {', '.join(product_names)}",
                    "details": {"antivirus": product_names, "active": False},
                })
    
    # Check Windows Defender as fallback
    if not av_active:
        success, output = run_powershell(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | Format-List",
            timeout=15
        )
        
        if success and 'True' in output:
            av_found = True
            av_active = True
            findings.append({
                "category": "Security Software",
                "status": "ok",
                "description": "Windows Defender is active",
                "details": {"antivirus": "Windows Defender"},
            })
        elif not av_found:
            findings.append({
                "category": "Security Software",
                "status": "critical",
                "description": "No antivirus software detected - major security risk",
                "details": {"antivirus": None},
            })
    
    # Check Windows Firewall
    success, output = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | Format-List",
        timeout=10
    )
    
    if success and output.strip():
        enabled_count = output.count('True')
        
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
    
    # Check for antispyware
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
    
    # Check for Windows Defender Antispyware as fallback
    if not any(f.get('category') == 'Security Software' and 'antispyware' in str(f.get('details', '')).lower() for f in findings):
        success, output = run_powershell(
            "Get-MpComputerStatus | Select-Object AntispywareEnabled | Format-List",
            timeout=10
        )
        
        if success and 'True' in output:
            findings.append({
                "category": "Security Software",
                "status": "ok",
                "description": "Windows Defender Antispyware is enabled",
                "details": {"antispyware": "Windows Defender"},
            })
    
    return findings
