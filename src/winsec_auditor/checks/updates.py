"""Windows Updates checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_updates() -> list["SecurityFinding"]:
    """Check Windows Update status."""
    findings: list["SecurityFinding"] = []
    
    # Check installed updates
    success, output = run_powershell(
        "Get-WmiObject -Class Win32_QuickFixEngineering | "
        "Select-Object -Property HotFixID, Description, InstalledOn | "
        "Format-Table -AutoSize",
        timeout=30
    )
    
    if success and output.strip():
        lines = [line for line in output.strip().split('\n') if line.strip()]
        # Subtract header lines (usually 2)
        update_count = max(0, len(lines) - 2)
        
        findings.append({
            "category": "Windows Updates",
            "status": "info",
            "description": f"Installed updates: {update_count}",
            "details": {"count": update_count},
        })
    else:
        findings.append({
            "category": "Windows Updates",
            "status": "warning",
            "description": "Could not retrieve Windows Update history",
            "details": None,
        })
    
    # Check for update service status
    success, output = run_powershell(
        "Get-Service -Name wuauserv | Select-Object Status, StartType",
        timeout=10
    )
    
    if success and "Running" in output:
        findings.append({
            "category": "Windows Updates",
            "status": "ok",
            "description": "Windows Update service is running",
            "details": None,
        })
    elif success:
        findings.append({
            "category": "Windows Updates",
            "status": "warning",
            "description": "Windows Update service is not running",
            "details": None,
        })
    
    # Check for pending updates using COM (more reliable)
    success, output = run_powershell(
        "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count",
        timeout=30
    )
    
    if success:
        try:
            pending = int(output.strip())
            if pending > 0:
                status = "warning" if pending < 10 else "critical"
                findings.append({
                    "category": "Windows Updates",
                    "status": status,
                    "description": f"{pending} pending Windows updates available",
                    "details": {"pending_updates": pending},
                })
            else:
                findings.append({
                    "category": "Windows Updates",
                    "status": "ok",
                    "description": "System is up to date",
                    "details": None,
                })
        except ValueError:
            pass
    
    return findings
