"""Network security checks."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_command

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


# Potentially risky ports
RISKY_PORTS = [
    (20, "FTP Data"),
    (21, "FTP Control"),
    (23, "Telnet - insecure protocol"),
    (25, "SMTP - potential spam relay"),
    (110, "POP3 - insecure email"),
    (135, "RPC - commonly attacked"),
    (137, "NetBIOS Name Service"),
    (138, "NetBIOS Datagram Service"),
    (139, "NetBIOS Session Service"),
    (445, "SMB - commonly attacked"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "SQL Server - if exposed"),
    (3389, "RDP - commonly attacked"),
    (5900, "VNC - if exposed"),
]


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
        
        # Check for risky ports
        risky_found = []
        for port, description in RISKY_PORTS:
            if port in listening_ports:
                risky_found.append((port, description))
        
        if risky_found:
            for port, desc in risky_found[:5]:  # Report first 5
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
        if len(established) > 100:
            findings.append({
                "category": "Network Security",
                "status": "warning",
                "description": f"Unusually high number of active connections: {len(established)}",
                "details": {"connection_count": len(established)},
            })
    
    return findings
