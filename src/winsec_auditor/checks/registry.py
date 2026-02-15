"""Registry security checks."""

import winreg
from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_registry() -> list["SecurityFinding"]:
    """Check important registry security settings."""
    findings: list["SecurityFinding"] = []
    
    # Check UAC (User Account Control)
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "EnableLUA")
                if value == 1:
                    findings.append({
                        "category": "Registry Security",
                        "status": "ok",
                        "description": "UAC (User Account Control) is enabled",
                        "details": {"uac_enabled": True},
                    })
                else:
                    findings.append({
                        "category": "Registry Security",
                        "status": "critical",
                        "description": "UAC (User Account Control) is disabled - security risk",
                        "details": {"uac_enabled": False},
                    })
            except FileNotFoundError:
                findings.append({
                    "category": "Registry Security",
                    "status": "warning",
                    "description": "UAC registry key not found",
                    "details": None,
                })
    except Exception as e:
        findings.append({
            "category": "Registry Security",
            "status": "warning",
            "description": f"Error checking UAC setting: {e}",
            "details": None,
        })
    
    # Check UAC level
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                # 2 = Always notify, 5 = Notify only when apps try to make changes, 0 = Never notify
                if value == 2:
                    findings.append({
                        "category": "Registry Security",
                        "status": "ok",
                        "description": "UAC is set to 'Always notify' - highest security",
                        "details": {"uac_level": "always_notify"},
                    })
                elif value == 5:
                    findings.append({
                        "category": "Registry Security",
                        "status": "warning",
                        "description": "UAC is set to 'Notify only when apps try to make changes'",
                        "details": {"uac_level": "notify_apps"},
                    })
                elif value == 0:
                    findings.append({
                        "category": "Registry Security",
                        "status": "critical",
                        "description": "UAC is set to 'Never notify' - security risk",
                        "details": {"uac_level": "never_notify"},
                    })
            except FileNotFoundError:
                pass
    except Exception:
        pass
    
    # Check PowerShell execution policy
    success, output = run_powershell(
        "Get-ExecutionPolicy",
        timeout=10
    )
    
    if success:
        policy = output.strip().lower()
        
        if policy == 'restricted':
            findings.append({
                "category": "Registry Security",
                "status": "ok",
                "description": f"PowerShell execution policy is restrictive: {policy}",
                "details": {"execution_policy": policy},
            })
        elif policy == 'allsigned':
            findings.append({
                "category": "Registry Security",
                "status": "ok",
                "description": f"PowerShell execution policy requires signed scripts: {policy}",
                "details": {"execution_policy": policy},
            })
        elif policy == 'remotesigned':
            findings.append({
                "category": "Registry Security",
                "status": "warning",
                "description": f"PowerShell execution policy allows local scripts: {policy}",
                "details": {"execution_policy": policy},
            })
        elif policy in ['unrestricted', 'bypass']:
            findings.append({
                "category": "Registry Security",
                "status": "critical",
                "description": f"PowerShell execution policy is too permissive: {policy}",
                "details": {"execution_policy": policy},
            })
    else:
        findings.append({
            "category": "Registry Security",
            "status": "warning",
            "description": "Could not determine PowerShell execution policy",
            "details": None,
        })
    
    # Check for auto-login (security risk)
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "AutoAdminLogon")
                if value == "1":
                    findings.append({
                        "category": "Registry Security",
                        "status": "critical",
                        "description": "Auto-login is enabled - major security risk",
                        "details": {"auto_login": True},
                    })
            except FileNotFoundError:
                pass
    except Exception:
        pass
    
    # Check Windows Defender settings
    try:
        key_path = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "DisableRealtimeMonitoring")
                if value == 1:
                    findings.append({
                        "category": "Registry Security",
                        "status": "critical",
                        "description": "Windows Defender real-time protection is disabled",
                        "details": {"defender_disabled": True},
                    })
            except FileNotFoundError:
                pass
    except Exception:
        pass
    
    return findings
