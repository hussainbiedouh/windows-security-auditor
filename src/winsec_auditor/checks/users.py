"""User accounts checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell, run_command, parse_user_accounts, parse_local_group_members
from winsec_auditor.config import config

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# Fields that should be masked or excluded based on detail level
SENSITIVE_FIELDS = {
    "SID",  # Security Identifier - masked to last 4 chars
    "PasswordLastSet",
    "PasswordExpires",
    "PasswordChangeableDate",
    "LastLogon",  # May contain sensitive timing info
    "PrincipalSource",  # Internal details
}


def mask_sid(sid: str | None) -> str:
    """
    Mask a Security Identifier (SID) for privacy.
    
    Shows only the last 4 characters to allow identification
    without exposing the full SID structure.
    
    Args:
        sid: The full SID string
        
    Returns:
        Masked SID showing only last 4 characters
    """
    if not sid:
        return "****"
    
    sid = sid.strip()
    if len(sid) > 4:
        return f"...{sid[-4:]}"
    return "****"


def sanitize_user_data(
    user: dict,
    detail_level: str = None
) -> dict:
    """
    Sanitize user data based on detail level.
    
    Args:
        user: Raw user data dictionary
        detail_level: Level of detail to include ('minimal', 'standard', 'full')
            If None, uses config.default_detail_level
        
    Returns:
        Sanitized user data dictionary
        
    Raises:
        ValueError: If detail_level is invalid
    """
    # Use config default if not specified
    if detail_level is None:
        detail_level = config.default_detail_level
    
    detail_level = config.validate_detail_level(detail_level)
    
    if detail_level == "minimal":
        # Only return basic counts, no individual details
        return {
            "count": 1,
            "masked": True,
        }
    
    if detail_level == "full":
        # Return all data (not recommended for production/logging)
        return user.copy()
    
    # Standard level - sanitize sensitive fields
    safe_details = {
        "Name": user.get("Name", "Unknown"),
        "Enabled": user.get("Enabled", False),
    }
    
    # Mask the SID instead of exposing full value
    if "SID" in user:
        safe_details["SID"] = mask_sid(user.get("SID"))
    
    # Include LastLogon only if it exists and is not empty
    last_logon = user.get("LastLogon")
    if last_logon and last_logon.strip() and last_logon.lower() != "never":
        safe_details["LastLogon"] = "Present"  # Don't expose exact timestamp
    elif last_logon:
        safe_details["LastLogon"] = "Never"
    
    return safe_details


def check_users(detail_level: str = None) -> list["SecurityFinding"]:
    """
    Check user accounts on the system.
    
    Args:
        detail_level: Level of detail to include in findings:
            - 'minimal': Only show counts
            - 'standard': Show names and status, mask SIDs (default)
            - 'full': Show all details including SIDs
            If None, uses config.default_detail_level
            
    Returns:
        List of security findings with sanitized user data
    """
    findings: list["SecurityFinding"] = []
    
    # Use config default if not specified
    if detail_level is None:
        detail_level = config.default_detail_level
    
    # Validate detail level
    try:
        detail_level = config.validate_detail_level(detail_level)
    except ValueError as e:
        findings.append({
            "category": "User Accounts",
            "status": "error",
            "description": str(e),
            "details": {"valid_options": ["minimal", "standard", "full"]},
        })
        return findings
    
    try:
        success, output = run_powershell(
            "Get-LocalUser | Select-Object Name, Enabled, LastLogon, SID, PrincipalSource | Format-List",
            timeout=30
        )
        
        if not success:
            findings.append({
                "category": "User Accounts",
                "status": "warning",
                "description": "Could not retrieve user accounts",
                "details": None,
            })
            return findings
        
        if not output.strip():
            findings.append({
                "category": "User Accounts",
                "status": "warning",
                "description": "No user accounts found",
                "details": None,
            })
            return findings
        
        # Parse user data using utility function
        raw_users = parse_user_accounts(output)
        
        # Convert Enabled string to boolean
        users_data = []
        for user in raw_users:
            user_data = {
                'Name': user.get('Name', 'Unknown'),
                'Enabled': user.get('Enabled', '').upper() == 'TRUE',
                'LastLogon': user.get('LastLogon', 'Never') or 'Never',
                'SID': user.get('SID', ''),
                'PrincipalSource': user.get('PrincipalSource', ''),
            }
            users_data.append(user_data)
        
        total_users = len(users_data)
        active_users = [u for u in users_data if u.get('Enabled', False)]
        inactive_users = [u for u in users_data if not u.get('Enabled', False)]
        
        # Summary findings (no sensitive data)
        findings.append({
            "category": "User Accounts",
            "status": "info",
            "description": f"Total user accounts: {total_users}",
            "details": {
                "total": total_users,
                "detail_level": detail_level,
            },
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
        
        # Include sanitized user list if not minimal detail level
        if detail_level != "minimal":
            sanitized_users = [
                sanitize_user_data(u, detail_level) for u in users_data
            ]
            findings.append({
                "category": "User Accounts",
                "status": "info",
                "description": f"User accounts list ({detail_level} detail level)",
                "details": {
                    "users": sanitized_users,
                    "masked_fields": ["SID"] if detail_level == "standard" else [],
                    "note": "SIDs are masked for security. Use detail_level='full' to see complete data."
                },
            })
        
        # Check for admin accounts
        success, admin_output = run_powershell(
            "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, PrincipalSource",
            timeout=10
        )
        
        if success:
            admin_members = [l.strip() for l in admin_output.split('\n') 
                           if l.strip() and 'Name' in l and '----' not in l]
            admin_count = len(admin_members)
            
            if admin_count > 0:
                # Sanitize admin member names if needed
                sanitized_admins = []
                if detail_level == "minimal":
                    sanitized_admins = [f"Admin_{i+1}" for i in range(admin_count)]
                else:
                    # Extract just the username part for standard level
                    for member in admin_members:
                        if ':' in member:
                            name = member.split(':', 1)[1].strip()
                            # Don't expose full domain\username format, just username
                            if '\\' in name:
                                name = name.split('\\', 1)[1]
                            sanitized_admins.append(name)
                
                findings.append({
                    "category": "User Accounts",
                    "status": "warning" if admin_count > 2 else "info",
                    "description": f"{admin_count} accounts have administrator privileges",
                    "details": {
                        "admin_count": admin_count,
                        "admins": sanitized_admins if detail_level != "minimal" else None,
                    },
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
    
    except Exception as e:
        findings.append({
            "category": "User Accounts",
            "status": "error",
            "description": f"Error checking user accounts: {str(e)}",
            "details": {"error_type": type(e).__name__},
        })
    
    return findings


def check_admin_privileges(detail_level: str = None) -> list["SecurityFinding"]:
    """
    Check administrator privileges and group membership.
    
    Args:
        detail_level: Level of detail to include in findings:
            - 'minimal': Only show counts
            - 'standard': Show names, mask sensitive data (default)
            - 'full': Show all details
            If None, uses config.default_detail_level
            
    Returns:
        List of security findings with sanitized admin data
    """
    findings: list["SecurityFinding"] = []
    
    # Use config default if not specified
    if detail_level is None:
        detail_level = config.default_detail_level
    
    try:
        detail_level = config.validate_detail_level(detail_level)
    except ValueError as e:
        findings.append({
            "category": "Admin Privileges",
            "status": "error",
            "description": str(e),
            "details": {"valid_options": ["minimal", "standard", "full"]},
        })
        return findings
    
    try:
        # Check Administrators group
        success, output = run_powershell(
            "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, SID, PrincipalSource | Format-List",
            timeout=10
        )
        
        if not success:
            findings.append({
                "category": "Admin Privileges",
                "status": "warning",
                "description": "Could not retrieve administrator group members",
                "details": None,
            })
            return findings
        
        # Parse admin members using utility function
        admins = parse_local_group_members(output)
        
        admin_count = len(admins)
        
        if admin_count == 0:
            findings.append({
                "category": "Admin Privileges",
                "status": "warning",
                "description": "No administrator accounts found",
                "details": None,
            })
            return findings
        
        # Sanitize admin data based on detail level
        if detail_level == "minimal":
            sanitized_admins = [{"id": i+1} for i in range(admin_count)]
        elif detail_level == "standard":
            sanitized_admins = []
            for admin in admins:
                safe_admin = {"Name": admin.get("Name", "Unknown")}
                if "SID" in admin:
                    safe_admin["SID"] = mask_sid(admin.get("SID"))
                sanitized_admins.append(safe_admin)
        else:  # full
            sanitized_admins = admins
        
        # Generate findings
        status = "warning" if admin_count > 2 else "info"
        findings.append({
            "category": "Admin Privileges",
            "status": status,
            "description": f"Found {admin_count} administrator account(s)",
            "details": {
                "admin_count": admin_count,
                "admins": sanitized_admins,
                "detail_level": detail_level,
                "security_note": "Multiple admin accounts increase attack surface"
            },
        })
        
        # Check for built-in Administrator account specifically
        builtin_admin = [a for a in admins 
                        if 'Administrator' in a.get('Name', '') 
                        or a.get('SID', '').endswith('-500')]
        
        if builtin_admin:
            admin_name = builtin_admin[0].get('Name', 'Administrator')
            findings.append({
                "category": "Admin Privileges",
                "status": "info",
                "description": f"Built-in Administrator account detected: {admin_name}",
                "details": {
                    "account": admin_name if detail_level == "full" else "Administrator",
                    "sid": mask_sid(builtin_admin[0].get('SID')) if detail_level != "full" else builtin_admin[0].get('SID'),
                    "recommendation": "Consider disabling built-in Administrator and using separate admin accounts"
                },
            })
    
    except Exception as e:
        findings.append({
            "category": "Admin Privileges",
            "status": "error",
            "description": f"Error checking admin privileges: {str(e)}",
            "details": {"error_type": type(e).__name__},
        })
    
    return findings
