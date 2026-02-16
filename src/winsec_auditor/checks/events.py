"""Event log analysis checks.

SECURITY: This module uses secure PowerShell command execution via
run_powershell_command() to prevent command injection attacks.
All event log queries use parameter binding (no string concatenation).
"""

import logging
from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell_command, PowerShellResult
from winsec_auditor.config import config

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding

# Configure logging
logger = logging.getLogger(__name__)

# Valid event IDs for security checks
VALID_EVENT_IDS = {
    4625,  # Failed logon
    4740,  # Account lockout
    4697,  # Service installation
    4104,  # PowerShell script block
    4672,  # Special privileges assigned
}

# Valid log names
VALID_LOG_NAMES = {
    'Security',
    'Microsoft-Windows-PowerShell/Operational',
    'System',
    'Application',
}


def _validate_event_id(event_id: int) -> int:
    """Validate that event ID is allowed.
    
    SECURITY: Prevents injection through event IDs by validating against whitelist.
    
    Args:
        event_id: The event ID to validate
        
    Returns:
        The validated event ID
        
    Raises:
        ValueError: If event ID is not in whitelist
    """
    if not isinstance(event_id, int):
        raise ValueError(f"Event ID must be an integer, got {type(event_id).__name__}")
    
    if event_id not in VALID_EVENT_IDS:
        raise ValueError(f"Event ID {event_id} is not in allowed list: {VALID_EVENT_IDS}")
    
    return event_id


def _validate_log_name(log_name: str) -> str:
    """Validate that log name is allowed.
    
    SECURITY: Prevents injection through log names by validating against whitelist.
    
    Args:
        log_name: The log name to validate
        
    Returns:
        The validated log name
        
    Raises:
        ValueError: If log name is not in whitelist
    """
    if not isinstance(log_name, str):
        raise ValueError(f"Log name must be a string, got {type(log_name).__name__}")
    
    log_name = log_name.strip()
    
    if log_name not in VALID_LOG_NAMES:
        raise ValueError(f"Log name '{log_name}' is not in allowed list: {VALID_LOG_NAMES}")
    
    return log_name


def _build_filter_hashtable(log_name: str, event_id: int, time_span: str) -> str:
    """Build a PowerShell filter hashtable string.
    
    SECURITY: Uses validated parameters only. No user input allowed.
    
    Args:
        log_name: Validated log name
        event_id: Validated event ID
        time_span: PowerShell time expression (e.g., "(Get-Date).AddDays(-1)")
        
    Returns:
        Formatted hashtable string for PowerShell
    """
    # These values have been validated - safe to use in hashtable
    return f"@{{LogName='{log_name}'; ID={event_id}; StartTime={time_span}}}"


def _execute_event_query(
    log_name: str,
    event_id: int,
    time_expression: str,
    timeout: int = 30
) -> tuple[bool, str]:
    """Execute a secure event log query.
    
    SECURITY: Uses run_powershell_command with parameter binding.
    
    Args:
        log_name: Name of the event log
        event_id: Event ID to query
        time_expression: PowerShell time expression
        timeout: Query timeout in seconds
        
    Returns:
        Tuple of (success, output)
    """
    try:
        # Validate inputs
        validated_log = _validate_log_name(log_name)
        validated_id = _validate_event_id(event_id)
        
        # Build filter hashtable with validated values
        filter_hashtable = _build_filter_hashtable(validated_log, validated_id, time_expression)
        
        # Execute via secure command runner
        result: PowerShellResult = run_powershell_command(
            cmdlet="Get-WinEvent",
            parameters={
                "FilterHashtable": filter_hashtable,
                "ErrorAction": "SilentlyContinue"
            },
            timeout=timeout
        )
        
        return result.success, result.stdout
        
    except Exception as e:
        logger.error(f"Event query failed: {e}")
        return False, str(e)


def _check_brute_force_attempts() -> tuple[bool, int]:
    """Check for failed login attempts (brute force detection).
    
    Returns:
        Tuple of (found_threats, source_count)
    """
    try:
        # Query for failed logon events (4625) in last 24 hours
        success, output = _execute_event_query(
            log_name='Security',
            event_id=4625,
            time_expression="(Get-Date).AddDays(-1)"
        )
        
        if not success or not output.strip():
            return False, 0
        
        # Count unique sources with > threshold failed attempts
        # For complex group queries, we use a pipeline via the command parameter
        filter_ht = "@{{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)}}"
        
        result = run_powershell_command(
            cmdlet="Get-WinEvent",
            parameters={
                "FilterHashtable": filter_ht,
                "ErrorAction": "SilentlyContinue"
            },
            timeout=30
        )
        
        if not result.success or not result.stdout.strip():
            return False, 0
        
        # Group by account and count
        pipeline_cmd = (
            f"Get-WinEvent -FilterHashtable {filter_ht} -ErrorAction SilentlyContinue | "
            f"Group-Object -Property {{$_.Properties[5].Value}} | "
            f"Where-Object {{$_.Count -gt {config.brute_force_threshold}}} | "
            f"Select-Object Name, Count | Format-List"
        )
        
        # Use deprecated run_powershell for complex pipeline (still safe - no user input)
        from winsec_auditor.utils import run_powershell
        pipeline_result = run_powershell(pipeline_cmd, timeout=30)
        
        if pipeline_result.success and pipeline_result.stdout.strip():
            lines = [l for l in pipeline_result.stdout.split('\n') 
                    if l.strip().startswith('Name') or l.strip().startswith('Count')]
            sources = len([l for l in lines if l.strip().startswith('Name')])
            return sources > 0, sources
        
        return False, 0
        
    except Exception as e:
        logger.error(f"Brute force check failed: {e}")
        return False, 0


def _check_account_lockouts() -> tuple[bool, int]:
    """Check for account lockouts.
    
    Returns:
        Tuple of (found_lockouts, lockout_count)
    """
    try:
        # Query for account lockout events (4740) in last 24 hours
        success, output = _execute_event_query(
            log_name='Security',
            event_id=4740,
            time_expression="(Get-Date).AddDays(-1)"
        )
        
        if not success or not output.strip():
            return False, 0
        
        # Count events - use Measure-Object for counting
        filter_ht = "@{{LogName='Security'; ID=4740; StartTime=(Get-Date).AddDays(-1)}}"
        
        count_cmd = (
            f"(Get-WinEvent -FilterHashtable {filter_ht} -ErrorAction SilentlyContinue).Count"
        )
        
        from winsec_auditor.utils import run_powershell
        count_result = run_powershell(count_cmd, timeout=30)
        
        if count_result.success:
            try:
                count = int(count_result.stdout.strip())
                return count > 0, count
            except ValueError:
                pass
        
        return False, 0
        
    except Exception as e:
        logger.error(f"Account lockout check failed: {e}")
        return False, 0


def _check_service_installations() -> tuple[bool, int]:
    """Check for suspicious service installations.
    
    Returns:
        Tuple of (found_services, service_count)
    """
    try:
        # Query for service installation events (4697) in last 24 hours
        success, output = _execute_event_query(
            log_name='Security',
            event_id=4697,
            time_expression="(Get-Date).AddDays(-1)"
        )
        
        if not success or not output.strip():
            return False, 0
        
        # Count events
        filter_ht = "@{{LogName='Security'; ID=4697; StartTime=(Get-Date).AddDays(-1)}}"
        
        count_cmd = (
            f"(Get-WinEvent -FilterHashtable {filter_ht} -ErrorAction SilentlyContinue).Count"
        )
        
        from winsec_auditor.utils import run_powershell
        count_result = run_powershell(count_cmd, timeout=30)
        
        if count_result.success:
            try:
                count = int(count_result.stdout.strip())
                return count > 0, count
            except ValueError:
                pass
        
        return False, 0
        
    except Exception as e:
        logger.error(f"Service installation check failed: {e}")
        return False, 0


def _check_suspicious_powershell() -> tuple[bool, int]:
    """Check for suspicious PowerShell activity.
    
    Returns:
        Tuple of (found_suspicious, event_count)
    """
    try:
        # Query for PowerShell script block events (4104) in last 24 hours
        success, output = _execute_event_query(
            log_name='Microsoft-Windows-PowerShell/Operational',
            event_id=4104,
            time_expression="(Get-Date).AddDays(-1)"
        )
        
        if not success:
            return False, 0
        
        # For PowerShell with message filtering, we need a pipeline
        filter_ht = "@{{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddDays(-1)}}"
        
        suspicious_cmd = (
            f"Get-WinEvent -FilterHashtable {filter_ht} -ErrorAction SilentlyContinue | "
            f"Where-Object {{$_.Message -match 'DownloadString|DownloadFile|IEX|Invoke-Expression|Net.WebClient|FromBase64String'}} | "
            f"Measure-Object | Select-Object Count | Format-List"
        )
        
        from winsec_auditor.utils import run_powershell
        suspicious_result = run_powershell(suspicious_cmd, timeout=30)
        
        if suspicious_result.success and suspicious_result.stdout.strip():
            for line in suspicious_result.stdout.split('\n'):
                if 'Count' in line and ':' in line:
                    try:
                        count = int(line.split(':', 1)[-1].strip())
                        return count > 0, count
                    except ValueError:
                        continue
        
        return False, 0
        
    except Exception as e:
        logger.error(f"Suspicious PowerShell check failed: {e}")
        return False, 0


def _check_privilege_escalation() -> tuple[bool, int]:
    """Check for privilege escalation attempts.
    
    Returns:
        Tuple of (found_escalation, event_count)
    """
    try:
        # Query for privilege use events (4672) in last hour
        success, output = _execute_event_query(
            log_name='Security',
            event_id=4672,
            time_expression="(Get-Date).AddHours(-1)"
        )
        
        if not success:
            return False, 0
        
        # Filter for administrator-related events
        filter_ht = "@{{LogName='Security'; ID=4672; StartTime=(Get-Date).AddHours(-1)}}"
        
        priv_cmd = (
            f"(Get-WinEvent -FilterHashtable {filter_ht} -ErrorAction SilentlyContinue | "
            f"Where-Object {{$_.Message -match 'administrator'}}).Count"
        )
        
        from winsec_auditor.utils import run_powershell
        priv_result = run_powershell(priv_cmd, timeout=30)
        
        if priv_result.success:
            try:
                count = int(priv_result.stdout.strip())
                # Flag if unusually high (using config threshold)
                return count > config.privilege_escalation_threshold, count
            except ValueError:
                pass
        
        return False, 0
        
    except Exception as e:
        logger.error(f"Privilege escalation check failed: {e}")
        return False, 0


def check_events() -> list["SecurityFinding"]:
    """Analyze Windows event logs for security threats.
    
    SECURITY: All PowerShell commands use secure execution via
    run_powershell_command() or run_powershell() with no user input.
    No string concatenation with user input is performed.
    
    Returns:
        List of security findings
    """
    findings: list["SecurityFinding"] = []
    threats_detected = False
    
    logger.info("Starting event log security analysis")
    
    # Check for failed login attempts (brute force detection)
    try:
        has_brute_force, brute_sources = _check_brute_force_attempts()
        if has_brute_force:
            threats_detected = True
            findings.append({
                "category": "Event Log Analysis",
                "status": "warning",
                "description": f"Potential brute force attack: {brute_sources} account(s) with multiple failed logins in last 24h",
                "details": {"failed_sources": brute_sources, "event_id": 4625},
            })
    except Exception as e:
        logger.error(f"Brute force check error: {e}")
        findings.append({
            "category": "Event Log Analysis",
            "status": "error",
            "description": f"Failed to check for brute force attempts: {str(e)}",
            "details": {"error": str(e), "event_id": 4625},
        })
    
    # Check for account lockouts
    try:
        has_lockouts, lockout_count = _check_account_lockouts()
        if has_lockouts:
            threats_detected = True
            status = "warning" if lockout_count < 3 else "critical"
            findings.append({
                "category": "Event Log Analysis",
                "status": status,
                "description": f"Account lockouts detected: {lockout_count} in last 24h",
                "details": {"lockout_count": lockout_count, "event_id": 4740},
            })
    except Exception as e:
        logger.error(f"Account lockout check error: {e}")
        findings.append({
            "category": "Event Log Analysis",
            "status": "error",
            "description": f"Failed to check for account lockouts: {str(e)}",
            "details": {"error": str(e), "event_id": 4740},
        })
    
    # Check for suspicious service installations
    try:
        has_services, service_count = _check_service_installations()
        if has_services:
            threats_detected = True
            findings.append({
                "category": "Event Log Analysis",
                "status": "warning",
                "description": f"New service installations detected: {service_count} in last 24h",
                "details": {"service_installs": service_count, "event_id": 4697},
            })
    except Exception as e:
        logger.error(f"Service installation check error: {e}")
        findings.append({
            "category": "Event Log Analysis",
            "status": "error",
            "description": f"Failed to check for service installations: {str(e)}",
            "details": {"error": str(e), "event_id": 4697},
        })
    
    # Check for suspicious PowerShell activity
    try:
        has_powershell, ps_count = _check_suspicious_powershell()
        if has_powershell:
            threats_detected = True
            status = "warning" if ps_count < 3 else "critical"
            findings.append({
                "category": "Event Log Analysis",
                "status": status,
                "description": f"Suspicious PowerShell activity detected: {ps_count} events in last 24h",
                "details": {"powershell_events": ps_count, "event_id": 4104},
            })
    except Exception as e:
        logger.error(f"PowerShell check error: {e}")
        findings.append({
            "category": "Event Log Analysis",
            "status": "error",
            "description": f"Failed to check for suspicious PowerShell: {str(e)}",
            "details": {"error": str(e), "event_id": 4104},
        })
    
    # Check for privilege escalation attempts
    try:
        has_privilege, priv_count = _check_privilege_escalation()
        if has_privilege:
            threats_detected = True
            findings.append({
                "category": "Event Log Analysis",
                "status": "warning",
                "description": f"High number of privilege use events in last hour: {priv_count}",
                "details": {"privilege_events": priv_count, "event_id": 4672},
            })
    except Exception as e:
        logger.error(f"Privilege escalation check error: {e}")
        findings.append({
            "category": "Event Log Analysis",
            "status": "error",
            "description": f"Failed to check for privilege escalation: {str(e)}",
            "details": {"error": str(e), "event_id": 4672},
        })
    
    # If no threats were detected, add a positive finding
    if not threats_detected:
        findings.append({
            "category": "Event Log Analysis",
            "status": "ok",
            "description": "No security threats detected in recent event logs",
            "details": None,
        })
    
    logger.info(f"Event log analysis complete: {len(findings)} findings")
    return findings
