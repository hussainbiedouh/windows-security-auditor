"""Utility functions for the Windows Security Auditor."""

import platform
import subprocess
from typing import Optional


def is_windows() -> bool:
    """Check if the current platform is Windows."""
    return platform.system() == "Windows"


def run_powershell(command: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a PowerShell command and return success status and output.
    
    Args:
        command: The PowerShell command to run.
        timeout: Timeout in seconds.
        
    Returns:
        Tuple of (success, output).
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


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
