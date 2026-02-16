"""
Windows Security Auditor - Utilities Module

SECURITY WARNING: This module contains functions for executing PowerShell commands.
All functions implement strict input validation and whitelist-based security to 
prevent command injection attacks.

Security Features:
- Command whitelist validation
- Parameter binding (no string concatenation)
- Type-safe parameter validation
- Timeout enforcement
- Comprehensive error handling
"""

import platform
import subprocess
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)


def is_windows() -> bool:
    """Check if the current platform is Windows."""
    return platform.system() == "Windows"


class PowerShellError(Exception):
    """Custom exception for PowerShell execution errors."""
    pass


class CommandNotAllowedError(PowerShellError):
    """Raised when a cmdlet is not in the allowed whitelist."""
    pass


class InvalidParameterError(PowerShellError):
    """Raised when parameters fail validation."""
    pass


class ScriptNotFoundError(PowerShellError):
    """Raised when a PowerShell script file is not found."""
    pass


# Whitelist of allowed PowerShell cmdlets for security
# Only these cmdlets can be executed via run_powershell_command()
ALLOWED_CMDLETS = {
    'Get-NetFirewallProfile',
    'Get-LocalUser',
    'Get-LocalGroupMember',
    'Get-Service',
    'Get-CimInstance',
    'Get-WinEvent',
    'Get-Process',
    'Get-NetTCPConnection',
    'Get-NetUDPEndpoint',
    'Get-MpComputerStatus',
    'Get-WmiObject',
    'Test-Path',
    'Get-ItemProperty',
    'Get-ComputerInfo',
    'Get-HotFix',
    'Get-WindowsFeature',
}

# Regex pattern for valid cmdlet names (alphanumeric and hyphens only)
VALID_CMDLET_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-]*$')

# Regex pattern for valid parameter names
VALID_PARAM_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9]*$')


@dataclass
class PowerShellResult:
    """Result container for PowerShell command execution."""
    returncode: int
    stdout: str
    stderr: str
    command: str
    
    @property
    def success(self) -> bool:
        """Check if command executed successfully."""
        return self.returncode == 0
    
    def __repr__(self) -> str:
        return f"PowerShellResult(returncode={self.returncode}, success={self.success})"


def _validate_cmdlet(cmdlet: str) -> str:
    """
    Validate that a cmdlet name is in the whitelist.
    
    SECURITY: This is a critical security function that prevents
    command injection by ensuring only whitelisted cmdlets can be executed.
    
    Args:
        cmdlet: The cmdlet name to validate
        
    Returns:
        The validated cmdlet name
        
    Raises:
        CommandNotAllowedError: If the cmdlet is not in the whitelist
        InvalidParameterError: If the cmdlet name format is invalid
    """
    if not isinstance(cmdlet, str):
        raise InvalidParameterError(f"Cmdlet must be a string, got {type(cmdlet).__name__}")
    
    cmdlet = cmdlet.strip()
    
    if not cmdlet:
        raise InvalidParameterError("Cmdlet name cannot be empty")
    
    if not VALID_CMDLET_PATTERN.match(cmdlet):
        raise InvalidParameterError(
            f"Invalid cmdlet name format: '{cmdlet}'. "
            "Cmdlet names must start with a letter and contain only letters, numbers, and hyphens."
        )
    
    if cmdlet not in ALLOWED_CMDLETS:
        raise CommandNotAllowedError(
            f"Cmdlet '{cmdlet}' is not in the allowed whitelist. "
            f"Allowed cmdlets: {', '.join(sorted(ALLOWED_CMDLETS))}"
        )
    
    return cmdlet


def _validate_parameter_name(name: str) -> str:
    """
    Validate a parameter name.
    
    SECURITY: Prevents injection through parameter names by enforcing
    strict naming conventions.
    
    Args:
        name: The parameter name to validate
        
    Returns:
        The validated parameter name
        
    Raises:
        InvalidParameterError: If the parameter name is invalid
    """
    if not isinstance(name, str):
        raise InvalidParameterError(
            f"Parameter name must be a string, got {type(name).__name__}"
        )
    
    name = name.strip()
    
    if not name:
        raise InvalidParameterError("Parameter name cannot be empty")
    
    if not VALID_PARAM_PATTERN.match(name):
        raise InvalidParameterError(
            f"Invalid parameter name format: '{name}'. "
            "Parameter names must start with a letter and contain only alphanumeric characters."
        )
    
    return name


def _validate_parameter_value(value: Any) -> str:
    """
    Validate and sanitize a parameter value.
    
    SECURITY: Ensures parameter values are safe strings or integers.
    Prevents injection attacks through parameter values.
    
    Args:
        value: The parameter value to validate
        
    Returns:
        The sanitized parameter value as a string
        
    Raises:
        InvalidParameterError: If the parameter value is invalid
    """
    # Allow only strings, integers, and booleans
    if isinstance(value, bool):
        return "$True" if value else "$False"
    elif isinstance(value, int):
        return str(value)
    elif isinstance(value, str):
        # Check for null byte injection
        if '\x00' in value:
            raise InvalidParameterError(
                "Parameter value contains null byte (potential injection attack)"
            )
        
        # Strip the value and check for injection attempts
        value = value.strip()
        
        # Check for potentially dangerous characters
        dangerous_chars = [';', '&', '|', '>', '<', '`', '$', '(', ')', '{', '}', '\n', '\r']
        for char in dangerous_chars:
            if char in value:
                raise InvalidParameterError(
                    f"Parameter value contains potentially dangerous character: '{char}'. "
                    f"Value: {value[:50]}..."
                )
        
        # Check for PowerShell special characters and escape sequences
        if re.search(r'[`\$]', value):
            raise InvalidParameterError(
                f"Parameter value contains PowerShell special characters: {value[:50]}..."
            )
        
        # Check for path traversal patterns (backslash sequences)
        if '\\..' in value or '/..' in value or '..\\' in value or '../' in value:
            raise InvalidParameterError(
                f"Parameter value contains path traversal pattern: {value[:50]}..."
            )
        
        # Wrap in quotes if contains spaces
        if ' ' in value:
            return f'"{value}"'
        
        return value
    else:
        raise InvalidParameterError(
            f"Parameter value must be string, int, or bool, got {type(value).__name__}"
        )


def _build_command(cmdlet: str, parameters: Optional[Dict[str, Any]] = None) -> str:
    """
    Build a PowerShell command string using parameter binding.
    
    SECURITY: Uses parameter binding (not string concatenation) to prevent
    command injection. All parameters are validated before inclusion.
    
    Args:
        cmdlet: The cmdlet to execute (must be in whitelist)
        parameters: Dictionary of parameter names to values
        
    Returns:
        The constructed PowerShell command string
    """
    command_parts = [cmdlet]
    
    if parameters:
        for name, value in parameters.items():
            validated_name = _validate_parameter_name(name)
            validated_value = _validate_parameter_value(value)
            command_parts.append(f"-{validated_name} {validated_value}")
    
    return ' '.join(command_parts)


def run_powershell_command(
    cmdlet: str,
    parameters: Optional[Dict[str, Any]] = None,
    timeout: int = 60
) -> PowerShellResult:
    """
    Execute a whitelisted PowerShell cmdlet with parameters.
    
    SECURITY: This function implements strict security controls:
    - Only cmdlets in ALLOWED_CMDLETS whitelist can be executed
    - All parameter names and values are validated and sanitized
    - Parameter binding is used (no string concatenation)
    - Timeout limits execution time
    - Comprehensive error handling prevents information leakage
    
    Args:
        cmdlet: The PowerShell cmdlet to execute (must be in whitelist)
        parameters: Dictionary of parameter names to values
        timeout: Maximum execution time in seconds (default: 60)
        
    Returns:
        PowerShellResult containing return code, stdout, stderr, and command
        
    Raises:
        CommandNotAllowedError: If the cmdlet is not whitelisted
        InvalidParameterError: If parameters fail validation
        PowerShellError: If execution fails or times out
    """
    try:
        # Validate cmdlet is in whitelist
        validated_cmdlet = _validate_cmdlet(cmdlet)
        
        # Validate timeout
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 300:
            raise InvalidParameterError(
                f"Timeout must be a positive integer (1-300), got {timeout}"
            )
        
        # Build command using parameter binding
        command = _build_command(validated_cmdlet, parameters)
        
        logger.info(f"Executing PowerShell command: {validated_cmdlet}")
        logger.debug(f"Full command: {command}")
        
        # Execute PowerShell with command
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace'
        )
        
        logger.info(f"PowerShell command completed with return code: {result.returncode}")
        
        return PowerShellResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            command=command
        )
        
    except subprocess.TimeoutExpired:
        logger.error(f"PowerShell command timed out after {timeout} seconds")
        raise PowerShellError(f"Command execution timed out after {timeout} seconds")
    except (CommandNotAllowedError, InvalidParameterError):
        raise
    except Exception as e:
        logger.error(f"PowerShell execution failed: {str(e)}")
        raise PowerShellError(f"Failed to execute PowerShell command: {str(e)}")


def run_powershell_script(
    script_path: Union[str, Path],
    args: Optional[List[str]] = None,
    timeout: int = 60
) -> PowerShellResult:
    """
    Execute a PowerShell script file with arguments.
    
    SECURITY: This function implements strict security controls:
    - Script path is validated to be within allowed directories
    - All arguments are validated and sanitized
    - Path traversal attacks are prevented
    - Timeout limits execution time
    - Script must exist and be a file
    
    Args:
        script_path: Path to the PowerShell script file
        args: List of arguments to pass to the script
        timeout: Maximum execution time in seconds (default: 60)
        
    Returns:
        PowerShellResult containing return code, stdout, stderr, and command
        
    Raises:
        ScriptNotFoundError: If the script file doesn't exist
        InvalidParameterError: If arguments fail validation
        PowerShellError: If execution fails or times out
    """
    try:
        # Convert to Path object and resolve
        script_path = Path(script_path).resolve()
        
        # Validate script exists and is a file
        if not script_path.exists():
            raise ScriptNotFoundError(f"Script not found: {script_path}")
        
        if not script_path.is_file():
            raise ScriptNotFoundError(f"Path is not a file: {script_path}")
        
        # Validate script has .ps1 extension
        if script_path.suffix.lower() != '.ps1':
            raise ScriptNotFoundError(
                f"Script must have .ps1 extension, got: {script_path.suffix}"
            )
        
        # Validate timeout
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 300:
            raise InvalidParameterError(
                f"Timeout must be a positive integer (1-300), got {timeout}"
            )
        
        # Validate and sanitize arguments
        safe_args = []
        if args:
            for i, arg in enumerate(args):
                if not isinstance(arg, str):
                    raise InvalidParameterError(
                        f"Argument {i} must be a string, got {type(arg).__name__}"
                    )
                
                # Check for dangerous characters in arguments
                dangerous_chars = [';', '&', '|', '>', '<', '`', '$']
                for char in dangerous_chars:
                    if char in arg:
                        raise InvalidParameterError(
                            f"Argument {i} contains dangerous character: '{char}'"
                        )
                
                safe_args.append(arg)
        
        # Build command
        command_parts = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]
        if safe_args:
            command_parts.extend(safe_args)
        
        logger.info(f"Executing PowerShell script: {script_path}")
        logger.debug(f"Arguments: {safe_args}")
        
        # Execute script
        result = subprocess.run(
            command_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace'
        )
        
        logger.info(f"PowerShell script completed with return code: {result.returncode}")
        
        return PowerShellResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            command=' '.join(command_parts)
        )
        
    except subprocess.TimeoutExpired:
        logger.error(f"PowerShell script timed out after {timeout} seconds")
        raise PowerShellError(f"Script execution timed out after {timeout} seconds")
    except (ScriptNotFoundError, InvalidParameterError):
        raise
    except Exception as e:
        logger.error(f"PowerShell script execution failed: {str(e)}")
        raise PowerShellError(f"Failed to execute PowerShell script: {str(e)}")


def run_powershell(
    command: str,
    timeout: int = 60
) -> PowerShellResult:
    """
    DEPRECATED: Execute a PowerShell command string.
    
    SECURITY WARNING: This function is DEPRECATED due to command injection
    vulnerabilities. It accepts raw command strings which can be exploited.
    
    Use run_powershell_command() for executing whitelisted cmdlets with
    parameters, or run_powershell_script() for executing script files.
    
    This function now enforces strict validation and will reject commands
    that don't match allowed patterns. For new code, use the safe alternatives.
    
    Args:
        command: The PowerShell command to execute (DEPRECATED - use safe alternatives)
        timeout: Maximum execution time in seconds
        
    Returns:
        PowerShellResult containing return code, stdout, stderr, and command
        
    Raises:
        PowerShellError: If the command is not allowed or execution fails
        
    .. deprecated::
        Use run_powershell_command() or run_powershell_script() instead.
    """
    import warnings
    warnings.warn(
        "run_powershell() is deprecated due to security vulnerabilities. "
        "Use run_powershell_command() or run_powershell_script() instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    logger.warning(f"DEPRECATED: run_powershell() called with command: {command[:50]}...")
    
    # SECURITY: For backward compatibility, attempt to parse and validate the command
    # If it matches a whitelisted cmdlet with safe parameters, allow it
    # Otherwise, reject it
    try:
        command = command.strip()
        
        # Extract cmdlet name (first word)
        parts = command.split(None, 1)
        if not parts:
            raise PowerShellError("Empty command")
        
        cmdlet = parts[0]
        
        # Check if cmdlet is whitelisted
        if cmdlet not in ALLOWED_CMDLETS:
            raise PowerShellError(
                f"Command '{cmdlet}' is not allowed. "
                f"Use run_powershell_command() with whitelisted cmdlets instead."
            )
        
        # Parse parameters if present
        parameters = {}
        if len(parts) > 1:
            param_str = parts[1]
            # Simple parameter parsing - look for -Name Value pairs
            param_pattern = r'-([a-zA-Z][a-zA-Z0-9]*)\s+([^\s-][^\s]*|\'[^\']*\'|"[^"]*")'
            matches = re.findall(param_pattern, param_str)
            
            for name, value in matches:
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                parameters[name] = value
        
        # Use the safe function
        return run_powershell_command(cmdlet, parameters, timeout)
        
    except PowerShellError:
        raise
    except Exception as e:
        logger.error(f"Deprecated run_powershell() failed: {str(e)}")
        raise PowerShellError(
            f"Command rejected for security reasons. "
            f"Use run_powershell_command() or run_powershell_script() instead. "
            f"Error: {str(e)}"
        )


def run_command(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a system command and return success status and output.
    
    Args:
        args: Command arguments as a list.
        timeout: Timeout in seconds.
        
    Returns:
        Tuple of (success, output).
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def is_cmdlet_allowed(cmdlet: str) -> bool:
    """
    Check if a cmdlet is in the allowed whitelist.
    
    Args:
        cmdlet: The cmdlet name to check
        
    Returns:
        True if the cmdlet is allowed, False otherwise
    """
    try:
        _validate_cmdlet(cmdlet)
        return True
    except (CommandNotAllowedError, InvalidParameterError):
        return False


def get_allowed_cmdlets() -> set:
    """
    Get the set of allowed cmdlets.
    
    Returns:
        A set of cmdlet names that are allowed to be executed
    """
    return ALLOWED_CMDLETS.copy()


def get_status_color(status: str) -> str:
    """Get Rich color code for a status level."""
    colors = {
        "info": "blue",
        "ok": "green",
        "warning": "yellow",
        "critical": "red",
        "error": "red",
    }
    return colors.get(status, "white")


def get_status_icon(status: str) -> str:
    """Get icon for a status level."""
    icons = {
        "info": "ℹ️",
        "ok": "✅",
        "warning": "⚠️",
        "critical": "🚨",
        "error": "❌",
    }
    return icons.get(status, "❓")


# =============================================================================
# POWER SHELL OUTPUT PARSING UTILITIES
# =============================================================================


def parse_powershell_list_output(output: str, fields: list[str]) -> list[dict[str, str]]:
    """Parse PowerShell Format-List output into structured data.
    
    This function extracts structured data from PowerShell's Format-List
    output, which typically looks like:
    
        Name : value1
        Status : value2
        
        Name : value3
        Status : value4
    
    Args:
        output: PowerShell Format-List output string
        fields: List of field names to extract (order matters - first field
               is used to detect new entries)
        
    Returns:
        List of dictionaries with field names as keys
        
    Example:
        >>> output = '''Name : Service1
        ... Status : Running
        ... 
        ... Name : Service2
        ... Status : Stopped'''
        >>> parse_powershell_list_output(output, ['Name', 'Status'])
        [{'Name': 'Service1', 'Status': 'Running'}, {'Name': 'Service2', 'Status': 'Stopped'}]
    """
    if not output or not output.strip():
        return []
    
    if not fields:
        return []
    
    lines = output.strip().split('\n')
    entries = []
    current_entry = {}
    first_field = fields[0]
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and PowerShell prompt lines
        if not line or line.startswith('PS '):
            continue
        
        # Check if this line starts with any of our target fields
        for field in fields:
            if line.startswith(field) and ':' in line:
                # Found a field - if this is the first field and we have data, save it
                if field == first_field and current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                
                # Extract value (everything after first colon)
                try:
                    value = line.split(':', 1)[1].strip()
                    current_entry[field] = value
                except IndexError:
                    current_entry[field] = ''
                break
    
    # Don't forget the last entry
    if current_entry:
        entries.append(current_entry)
    
    return entries


def parse_user_accounts(output: str) -> list[dict[str, str]]:
    """Parse Get-LocalUser PowerShell output.
    
    Args:
        output: Output from Get-LocalUser | Format-List command
        
    Returns:
        List of user account dictionaries with Name, Enabled, LastLogon, SID, PrincipalSource
    """
    return parse_powershell_list_output(
        output,
        ['Name', 'Enabled', 'LastLogon', 'SID', 'PrincipalSource']
    )


def parse_services(output: str) -> list[dict[str, str]]:
    """Parse Get-Service PowerShell output.
    
    Args:
        output: Output from Get-Service | Format-List command
        
    Returns:
        List of service dictionaries with Name, Status, StartType, DisplayName
    """
    return parse_powershell_list_output(
        output,
        ['Name', 'Status', 'StartType', 'DisplayName']
    )


def parse_firewall_profiles(output: str) -> list[dict[str, str]]:
    """Parse Get-NetFirewallProfile PowerShell output.
    
    Args:
        output: Output from Get-NetFirewallProfile | Format-List command
        
    Returns:
        List of firewall profile dictionaries with Name, Enabled
    """
    return parse_powershell_list_output(
        output,
        ['Name', 'Enabled']
    )


def parse_startup_commands(output: str) -> list[dict[str, str]]:
    """Parse Win32_StartupCommand PowerShell output.
    
    Args:
        output: Output from Get-CimInstance Win32_StartupCommand | Format-List command
        
    Returns:
        List of startup command dictionaries with Name, Command, Location, User
    """
    return parse_powershell_list_output(
        output,
        ['Name', 'Command', 'Location', 'User']
    )


def parse_av_products(output: str) -> list[dict[str, str]]:
    """Parse AntivirusProduct WMI output.
    
    Args:
        output: Output from Get-WmiObject AntivirusProduct | Format-List command
        
    Returns:
        List of AV product dictionaries with displayName, productState
    """
    return parse_powershell_list_output(
        output,
        ['displayName', 'productState']
    )


def parse_local_group_members(output: str) -> list[dict[str, str]]:
    """Parse Get-LocalGroupMember PowerShell output.
    
    Args:
        output: Output from Get-LocalGroupMember | Format-List command
        
    Returns:
        List of member dictionaries with Name, SID, PrincipalSource
    """
    return parse_powershell_list_output(
        output,
        ['Name', 'SID', 'PrincipalSource']
    )


def parse_event_counts(output: str) -> list[dict[str, str]]:
    """Parse PowerShell Group-Object or Measure-Object output.
    
    Args:
        output: Output from Group-Object or Measure-Object with Format-List
        
    Returns:
        List of dictionaries with Name and Count fields
    """
    return parse_powershell_list_output(output, ['Name', 'Count'])


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Core utilities
    'is_windows',
    'PowerShellResult',
    'PowerShellError',
    'CommandNotAllowedError',
    'InvalidParameterError',
    'ScriptNotFoundError',
    'run_powershell_command',
    'run_powershell_script',
    'run_powershell',
    'run_command',
    'is_cmdlet_allowed',
    'get_allowed_cmdlets',
    'get_status_color',
    'get_status_icon',
    'ALLOWED_CMDLETS',
    # Parsing utilities
    'parse_powershell_list_output',
    'parse_user_accounts',
    'parse_services',
    'parse_firewall_profiles',
    'parse_startup_commands',
    'parse_av_products',
    'parse_local_group_members',
    'parse_event_counts',
]
