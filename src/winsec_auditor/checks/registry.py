"""Registry security checks."""

import winreg
from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# UAC registry key path
UAC_KEY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def _check_uac_enabled(findings: list["SecurityFinding"]) -> None:
    """Check if UAC is enabled and add appropriate finding.
    
    Args:
        findings: List to append findings to.
    """
    success, value = _read_registry_value(UAC_KEY_PATH, "EnableLUA")
    if success:
        if value == 1:
            findings.append({
                "category": "Registry Security",
                "status": "ok",
                "description": "UAC (User Account Control) is enabled",
                "details": {"uac_enabled": True},
            })
        elif value == 0:
            findings.append({
                "category": "Registry Security",
                "status": "critical",
                "description": "UAC (User Account Control) is disabled - security risk",
                "details": {"uac_enabled": False},
            })
        else:
            findings.append({
                "category": "Registry Security",
                "status": "warning",
                "description": "UAC registry key not found",
                "details": None,
            })
    else:
        findings.append({
            "category": "Registry Security",
            "status": "warning",
            "description": "Could not read UAC registry setting",
            "details": None,
        })


def _check_uac_level(findings: list["SecurityFinding"]) -> None:
    """Check UAC notification level and add appropriate finding.
    
    Args:
        findings: List to append findings to.
    """
    success, value = _read_registry_value(UAC_KEY_PATH, "ConsentPromptBehaviorAdmin")
    if success and value is not None:
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


def _read_registry_value(key_path: str, value_name: str) -> tuple[bool, int | str | None]:
    """Read a registry value safely.

    Args:
        key_path: Registry key path.
        value_name: Name of the value to read.

    Returns:
        Tuple of (success, value). Value is None if not found or error.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, value_name)
                return True, value
            except FileNotFoundError:
                return True, None
    except Exception:
        return False, None


def check_registry() -> list["SecurityFinding"]:
    """Check important registry security settings."""
    findings: list["SecurityFinding"] = []

    # Check UAC (User Account Control) enabled
    _check_uac_enabled(findings)

    # Check UAC level
    _check_uac_level(findings)
    
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
