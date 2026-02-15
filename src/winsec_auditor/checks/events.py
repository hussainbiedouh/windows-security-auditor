"""Event log analysis checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_events() -> list["SecurityFinding"]:
    """Analyze Windows event logs for security threats."""
    findings: list["SecurityFinding"] = []
    threats_detected = False
    
    # Check for failed login attempts (brute force detection)
    success, output = run_powershell(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | "
        "Group-Object -Property {$_.Properties[5].Value} | "
        "Where-Object {$_.Count -gt 5} | "
        "Select-Object Name, Count | Format-List",
        timeout=30
    )
    
    if success and output.strip():
        failed_attempts = [l for l in output.split('\n') if l.strip().startswith('Name') or l.strip().startswith('Count')]
        if failed_attempts:
            threats_detected = True
            # Count unique sources
            sources = len([l for l in failed_attempts if l.strip().startswith('Name')])
            findings.append({
                "category": "Event Log Analysis",
                "status": "warning",
                "description": f"Potential brute force attack: {sources} account(s) with multiple failed logins in last 24h",
                "details": {"failed_sources": sources, "event_id": 4625},
            })
    
    # Check for account lockouts
    success, output = run_powershell(
        "(Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count",
        timeout=30
    )
    
    if success:
        try:
            lockout_count = int(output.strip())
            if lockout_count > 0:
                threats_detected = True
                status = "warning" if lockout_count < 3 else "critical"
                findings.append({
                    "category": "Event Log Analysis",
                    "status": status,
                    "description": f"Account lockouts detected: {lockout_count} in last 24h",
                    "details": {"lockout_count": lockout_count, "event_id": 4740},
                })
        except ValueError:
            pass
    
    # Check for suspicious service installations
    success, output = run_powershell(
        "(Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4697; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count",
        timeout=30
    )
    
    if success:
        try:
            service_count = int(output.strip())
            if service_count > 0:
                threats_detected = True
                findings.append({
                    "category": "Event Log Analysis",
                    "status": "warning",
                    "description": f"New service installations detected: {service_count} in last 24h",
                    "details": {"service_installs": service_count, "event_id": 4697},
                })
        except ValueError:
            pass
    
    # Check for PowerShell suspicious activity
    success, output = run_powershell(
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Message -match 'DownloadString|DownloadFile|IEX|Invoke-Expression|Net.WebClient|FromBase64String'} | "
        "Measure-Object | Select-Object Count | Format-List",
        timeout=30
    )
    
    if success and output.strip():
        try:
            for line in output.split('\n'):
                if 'Count' in line and ':' in line:
                    count = int(line.split(':', 1)[-1].strip())
                    if count > 0:
                        threats_detected = True
                        status = "warning" if count < 3 else "critical"
                        findings.append({
                            "category": "Event Log Analysis",
                            "status": status,
                            "description": f"Suspicious PowerShell activity detected: {count} events in last 24h",
                            "details": {"powershell_events": count, "event_id": 4104},
                        })
                    break
        except (ValueError, IndexError):
            pass
    
    # Check for privilege escalation attempts
    success, output = run_powershell(
        "(Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Message -match 'administrator'}).Count",
        timeout=30
    )
    
    if success:
        try:
            priv_count = int(output.strip())
            if priv_count > 10:  # Unusually high number
                findings.append({
                    "category": "Event Log Analysis",
                    "status": "warning",
                    "description": f"High number of privilege use events in last hour: {priv_count}",
                    "details": {"privilege_events": priv_count, "event_id": 4672},
                })
        except ValueError:
            pass
    
    # If no threats were detected, add a positive finding
    if not threats_detected:
        findings.append({
            "category": "Event Log Analysis",
            "status": "ok",
            "description": "No security threats detected in recent event logs",
            "details": None,
        })
    
    return findings
