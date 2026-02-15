"""User accounts checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell, run_command

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_users() -> list["SecurityFinding"]:
    """Check user accounts on the system."""
    findings: list["SecurityFinding"] = []
    
    success, output = run_powershell(
        "Get-LocalUser | Select-Object Name, Enabled, LastLogon, SID, PrincipalSource | Format-List",
        timeout=30
    )
    
    if success and output.strip():
        lines = output.strip().split('\n')
        users_data = []
        current_user = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('Name') and ':' in line:
                if current_user and 'Name' in current_user:
                    users_data.append(current_user)
                current_user = {'Name': line.split(':', 1)[1].strip()}
            elif line.startswith('Enabled') and ':' in line:
                current_user['Enabled'] = line.split(':', 1)[1].strip().upper() == 'TRUE'
            elif line.startswith('LastLogon') and ':' in line:
                last_logon = line.split(':', 1)[1].strip()
                current_user['LastLogon'] = last_logon if last_logon else 'Never'
            elif line.startswith('SID') and ':' in line:
                current_user['SID'] = line.split(':', 1)[1].strip()
        
        if current_user and 'Name' in current_user:
            users_data.append(current_user)
        
        total_users = len(users_data)
        active_users = [u for u in users_data if u.get('Enabled', False)]
        inactive_users = [u for u in users_data if not u.get('Enabled', False)]
        
        findings.append({
            "category": "User Accounts",
            "status": "info",
            "description": f"Total user accounts: {total_users}",
            "details": {"total": total_users},
        })
        
        findings.append({
            "category": "User Accounts",
            "status": "info",
            "description": f"Active accounts: {len(active_users)}",
            "details": {"active": len(active_users)},
        })
        
        if inactive_users:
            findings.append({
                "category": "User Accounts",
                "status": "info",
                "description": f"Disabled accounts: {len(inactive_users)}",
                "details": {"disabled": len(inactive_users)},
            })
        
        # Check for admin accounts
        success, admin_output = run_powershell(
            "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, PrincipalSource",
            timeout=10
        )
        
        if success:
            admin_count = len([l for l in admin_output.split('\n') if l.strip() and 'Name' in l])
            if admin_count > 0:
                findings.append({
                    "category": "User Accounts",
                    "status": "warning" if admin_count > 2 else "info",
                    "description": f"{admin_count} accounts have administrator privileges",
                    "details": {"admin_count": admin_count},
                })
        
        # Check for guest account
        guest_users = [u for u in users_data if u.get('Name', '').lower() == 'guest']
        if guest_users and guest_users[0].get('Enabled', False):
            findings.append({
                "category": "User Accounts",
                "status": "critical",
                "description": "Guest account is enabled - security risk",
                "details": None,
            })
        elif guest_users:
            findings.append({
                "category": "User Accounts",
                "status": "ok",
                "description": "Guest account is disabled",
                "details": None,
            })
        
        # Check current active sessions
        success, session_output = run_command(["qwinsta"], timeout=10)
        if success:
            active_sessions = []
            for line in session_output.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        username = parts[0].strip().replace('>', '')
                        if username.lower() not in ['services', '.', 'console'] and username:
                            active_sessions.append(username)
            
            if active_sessions:
                findings.append({
                    "category": "User Accounts",
                    "status": "info",
                    "description": f"Active sessions: {', '.join(set(active_sessions))}",
                    "details": {"sessions": list(set(active_sessions))},
                })
    else:
        findings.append({
            "category": "User Accounts",
            "status": "warning",
            "description": "Could not retrieve user accounts",
            "details": None,
        })
    
    return findings
