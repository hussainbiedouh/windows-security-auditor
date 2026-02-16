"""Network security checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_command
from winsec_auditor.config import config

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_network() -> list["SecurityFinding"]:
    """Check network security settings."""
    findings: list["SecurityFinding"] = []
    
    # Get listening ports
    success, output = run_command(["netstat", "-an"], timeout=10)
    
    if success:
        lines = output.split('\n')
        listening_entries = [line for line in lines if 'LISTENING' in line or 'LISTEN' in line]
        
        # Extract listening ports
        listening_ports = []
        for line in listening_entries:
            parts = line.split()
            if len(parts) >= 2:
                local_addr = parts[1]
                if ':' in local_addr:
                    port_str = local_addr.split(':')[-1]
                    try:
                        port = int(port_str)
                        listening_ports.append(port)
                    except ValueError:
                        continue
        
        findings.append({
            "category": "Network Security",
            "status": "info",
            "description": f"Listening ports: {len(listening_ports)} total",
            "details": {"total_listening": len(listening_ports)},
        })
        
        # Check for risky ports using config
        risky_found = []
        for port, description in config.risky_ports_with_desc:
            if port in listening_ports:
                risky_found.append((port, description))
        
        if risky_found:
            for port, desc in risky_found[:config.max_risky_ports_report]:  # Use config
                findings.append({
                    "category": "Network Security",
                    "status": "warning",
                    "description": f"Potentially risky port {port} is listening ({desc})",
                    "details": {"port": port, "description": desc},
                })
        else:
            findings.append({
                "category": "Network Security",
                "status": "ok",
                "description": "No common risky ports detected",
                "details": None,
            })
    else:
        findings.append({
            "category": "Network Security",
            "status": "warning",
            "description": "Could not retrieve network listening ports",
            "details": None,
        })
    
    # Check established connections
    success, output = run_command(["netstat", "-an"], timeout=10)
    
    if success:
        established = [line for line in output.split('\n') if 'ESTABLISHED' in line]
        
        findings.append({
            "category": "Network Security",
            "status": "info",
            "description": f"Active connections: {len(established)}",
            "details": {"established_connections": len(established)},
        })
        
        # Check for suspicious number of connections
        if len(established) > config.high_connection_threshold:
            findings.append({
                "category": "Network Security",
                "status": "warning",
                "description": f"Unusually high number of active connections: {len(established)}",
                "details": {"connection_count": len(established)},
            })
    
    return findings
