"""Autorun/startup programs checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# Suspicious paths that might indicate malware
SUSPICIOUS_PATHS = [
    "appdata\\local\\temp",
    "appdata\\roaming\\temp",
    "windows\\temp",
    "temp\\",
    "startup\\",
    "downloads\\",
]

# Suspicious keywords in startup entries
SUSPICIOUS_KEYWORDS = [
    "svchost", "lsass", "csrss", "crss",  # Process name impersonation
    "update.exe", "patch.exe", "install.exe",  # Generic names
    "tmp", "temp",  # Running from temp
]


def is_suspicious_path(path: str) -> bool:
    """Check if a path looks suspicious."""
    path_lower = path.lower()
    return any(susp in path_lower for susp in SUSPICIOUS_PATHS)


def has_suspicious_keywords(name: str, command: str) -> bool:
    """Check for suspicious keywords in name or command."""
    combined = f"{name} {command}".lower()
    return any(kw in combined for kw in SUSPICIOUS_KEYWORDS)


def check_autorun() -> list["SecurityFinding"]:
    """Check startup/autorun programs."""
    findings: list["SecurityFinding"] = []
    
    success, output = run_powershell(
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name, Command, Location, User | "
        "Format-List",
        timeout=30
    )
    
    if success and output.strip():
        lines = output.strip().split('\n')
        entries = []
        current_entry = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('Name') and ':' in line:
                if current_entry and 'Name' in current_entry:
                    entries.append(current_entry)
                current_entry = {'Name': line.split(':', 1)[1].strip()}
            elif line.startswith('Command') and ':' in line:
                current_entry['Command'] = line.split(':', 1)[1].strip()
            elif line.startswith('Location') and ':' in line:
                current_entry['Location'] = line.split(':', 1)[1].strip()
            elif line.startswith('User') and ':' in line:
                current_entry['User'] = line.split(':', 1)[1].strip()
        
        # Add the last entry
        if current_entry and 'Name' in current_entry:
            entries.append(current_entry)
        
        startup_count = len(entries)
        
        if startup_count == 0:
            findings.append({
                "category": "Autorun Programs",
                "status": "ok",
                "description": "No startup programs found",
                "details": None,
            })
        else:
            findings.append({
                "category": "Autorun Programs",
                "status": "info",
                "description": f"Startup programs: {startup_count} found",
                "details": {"count": startup_count},
            })
        
        # Analyze each entry
        suspicious_count = 0
        for entry in entries[:10]:  # Analyze first 10
            name = entry.get('Name', 'Unknown')
            command = entry.get('Command', '')
            location = entry.get('Location', 'Unknown')
            user = entry.get('User', 'Unknown')
            
            # Check for suspicious paths
            if is_suspicious_path(command):
                suspicious_count += 1
                findings.append({
                    "category": "Autorun Programs",
                    "status": "warning",
                    "description": f"Suspicious startup location: {name} from {command[:60]}...",
                    "details": {
                        "name": name,
                        "command": command,
                        "location": location,
                        "user": user,
                    },
                })
            # Check for suspicious keywords
            elif has_suspicious_keywords(name, command):
                suspicious_count += 1
                findings.append({
                    "category": "Autorun Programs",
                    "status": "warning",
                    "description": f"Suspicious startup entry: {name}",
                    "details": {
                        "name": name,
                        "command": command,
                        "location": location,
                        "user": user,
                    },
                })
        
        if suspicious_count > 0:
            findings.append({
                "category": "Autorun Programs",
                "status": "warning",
                "description": f"Found {suspicious_count} potentially suspicious startup entries",
                "details": {"suspicious_count": suspicious_count},
            })
        elif startup_count > 0:
            findings.append({
                "category": "Autorun Programs",
                "status": "ok",
                "description": "No suspicious startup entries detected",
                "details": None,
            })
    else:
        findings.append({
            "category": "Autorun Programs",
            "status": "warning",
            "description": "Could not retrieve autorun programs",
            "details": None,
        })
    
    return findings
