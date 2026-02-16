"""System information checks."""

import platform
from datetime import datetime
from typing import TYPE_CHECKING

import psutil

from winsec_auditor.utils import is_windows

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_system() -> list["SecurityFinding"]:
    """Check basic system information."""
    findings: list["SecurityFinding"] = []
    
    if not is_windows():
        findings.append({
            "category": "System Information",
            "status": "error",
            "description": "This tool is designed for Windows systems only",
            "details": None,
        })
        return findings
    
    # Operating System
    findings.append({
        "category": "System Information",
        "status": "info",
        "description": f"Operating System: {platform.system()} {platform.release()}",
        "details": {"version": platform.version(), "machine": platform.machine()},
    })
    
    # Architecture
    findings.append({
        "category": "System Information",
        "status": "info",
        "description": f"Architecture: {platform.architecture()[0]}",
        "details": None,
    })
    
    # Processor
    findings.append({
        "category": "System Information",
        "status": "info",
        "description": f"Processor: {platform.processor()}",
        "details": None,
    })
    
    # Disk usage
    try:
        disk_usage = psutil.disk_usage('C:')
        total_gb = disk_usage.total / (1024**3)
        free_gb = disk_usage.free / (1024**3)
        used_percent = disk_usage.percent
        
        status = "ok" if used_percent < 90 else "warning" if used_percent < 95 else "critical"
        
        findings.append({
            "category": "System Information",
            "status": status,
            "description": f"Disk Space (C:): {free_gb:.1f} GB free of {total_gb:.1f} GB ({used_percent}% used)",
            "details": {
                "total_gb": round(total_gb, 2),
                "free_gb": round(free_gb, 2),
                "used_percent": used_percent,
            },
        })
    except Exception as e:
        findings.append({
            "category": "System Information",
            "status": "warning",
            "description": f"Could not retrieve disk usage: {e}",
            "details": None,
        })
    
    # Memory usage
    try:
        memory = psutil.virtual_memory()
        total_gb = memory.total / (1024**3)
        available_gb = memory.available / (1024**3)
        used_percent = memory.percent
        
        status = "ok" if used_percent < 80 else "warning" if used_percent < 90 else "critical"
        
        findings.append({
            "category": "System Information",
            "status": status,
            "description": f"Memory: {available_gb:.1f} GB available of {total_gb:.1f} GB ({used_percent}% used)",
            "details": {
                "total_gb": round(total_gb, 2),
                "available_gb": round(available_gb, 2),
                "used_percent": used_percent,
            },
        })
    except Exception as e:
        findings.append({
            "category": "System Information",
            "status": "warning",
            "description": f"Could not retrieve memory usage: {e}",
            "details": None,
        })
    
    # Boot time
    try:
        boot_time = psutil.boot_time()
        boot_datetime = datetime.fromtimestamp(boot_time)
        uptime = datetime.now() - boot_datetime
        
        findings.append({
            "category": "System Information",
            "status": "info",
            "description": f"System Uptime: {uptime.days} days, {uptime.seconds//3600} hours",
            "details": {"boot_time": boot_datetime.isoformat()},
        })
    except Exception:
        pass
    
    return findings
