"""Configuration settings for Windows Security Auditor.

This module provides centralized configuration management for the
Windows Security Auditor application. Settings can be loaded from:
- Environment variables (WSA_* prefix)
- JSON configuration files
- Default values (backward compatible)

Example:
    >>> from winsec_auditor.config import config
    >>> config.max_autorun_entries
    50
    >>> config.risky_ports
    [21, 23, 25, ...]
"""

from dataclasses import dataclass, field
from typing import Optional
import os
import json
import logging

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Application configuration with security and analysis settings.
    
    All values have backward-compatible defaults that match the original
    hardcoded values in the codebase.
    
    Attributes:
        # Analysis limits
        max_autorun_entries: Maximum startup entries to analyze (was 10)
        max_event_log_entries: Maximum event log entries to retrieve (was 10)
        max_network_connections: Maximum network connections to report
        
        # Security thresholds
        privilege_escalation_threshold: Events threshold for privilege escalation (was 10)
        brute_force_threshold: Failed attempts threshold for brute force (was 5)
        suspicious_powershell_threshold: Events threshold for suspicious PowerShell (was 3)
        
        # Risky ports
        risky_ports: List of ports considered risky
        risky_ports_with_desc: List of (port, description) tuples
        
        # Detail levels
        default_detail_level: Default detail level for sensitive data
        
        # Timeouts
        powershell_timeout: Timeout for PowerShell commands (seconds)
        command_timeout: Timeout for system commands (seconds)
        
        # Output
        output_encoding: Output encoding for command results
        max_description_length: Maximum length for descriptions
        
        # Service checks
        max_risky_services_report: Maximum risky services to report
        system_services_warning_threshold: Threshold for "high" SYSTEM services
        
        # Network checks
        high_connection_threshold: Threshold for "unusually high" connections
        max_risky_ports_report: Maximum risky ports to report
    """
    
    # Analysis limits
    max_autorun_entries: int = 50  # Was hardcoded 10
    max_event_log_entries: int = 100  # Was hardcoded 10
    max_network_connections: int = 100
    
    # Security thresholds
    privilege_escalation_threshold: int = 10  # Was magic number 10
    brute_force_threshold: int = 5  # Was magic number 5
    suspicious_powershell_threshold: int = 3  # Was magic number 3
    
    # Risky ports (was hardcoded in network.py)
    risky_ports: list[int] = field(default_factory=lambda: [
        20, 21, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 443,
        445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443
    ])
    
    # Risky ports with descriptions (detailed config)
    risky_ports_with_desc: list[tuple[int, str]] = field(default_factory=lambda: [
        (20, "FTP Data"),
        (21, "FTP Control - insecure file transfer"),
        (23, "Telnet - insecure protocol"),
        (25, "SMTP - potential spam relay"),
        (53, "DNS - if improperly configured"),
        (80, "HTTP - unencrypted web traffic"),
        (110, "POP3 - insecure email protocol"),
        (135, "RPC - commonly attacked service"),
        (137, "NetBIOS Name Service - legacy protocol"),
        (138, "NetBIOS Datagram Service - legacy protocol"),
        (139, "NetBIOS Session Service - commonly attacked"),
        (143, "IMAP - insecure email protocol"),
        (443, "HTTPS - check certificate validity"),
        (445, "SMB - commonly attacked, check for eternalblue"),
        (993, "IMAPS - secure IMAP"),
        (995, "POP3S - secure POP3"),
        (1433, "SQL Server - if exposed to internet"),
        (1723, "PPTP VPN - considered insecure"),
        (3306, "MySQL - if exposed to internet"),
        (3389, "RDP - commonly attacked, check for bluekeep"),
        (5900, "VNC - if exposed to internet"),
        (8080, "HTTP Alternate - often used for proxies"),
        (8443, "HTTPS Alternate - often used for admin interfaces"),
    ])
    
    # Detail levels (for users.py sanitization)
    default_detail_level: str = "standard"  # Options: minimal, standard, full
    
    # Timeouts
    powershell_timeout: int = 30
    command_timeout: int = 10
    
    # Output
    output_encoding: str = "utf-8"
    max_description_length: int = 200
    
    # Service checks
    max_risky_services_report: int = 3  # Was hardcoded 3
    system_services_warning_threshold: int = 50  # Was magic number 50
    
    # Network checks
    high_connection_threshold: int = 100  # Was magic number 100
    max_risky_ports_report: int = 5  # Was hardcoded 5
    
    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables.
        
        Environment variables use the WSA_ prefix:
        - WSA_MAX_AUTORUN: max_autorun_entries
        - WSA_MAX_EVENTS: max_event_log_entries
        - WSA_PRIV_THRESHOLD: privilege_escalation_threshold
        - WSA_BRUTE_THRESHOLD: brute_force_threshold
        - WSA_PS_THRESHOLD: suspicious_powershell_threshold
        - WSA_DETAIL_LEVEL: default_detail_level
        - WSA_PS_TIMEOUT: powershell_timeout
        - WSA_CMD_TIMEOUT: command_timeout
        - WSA_HIGH_CONN_THRESHOLD: high_connection_threshold
        
        Returns:
            Config instance with values from environment
        """
        config = cls()
        
        # Integer settings
        int_vars = {
            'WSA_MAX_AUTORUN': 'max_autorun_entries',
            'WSA_MAX_EVENTS': 'max_event_log_entries',
            'WSA_MAX_NETWORK_CONN': 'max_network_connections',
            'WSA_PRIV_THRESHOLD': 'privilege_escalation_threshold',
            'WSA_BRUTE_THRESHOLD': 'brute_force_threshold',
            'WSA_PS_THRESHOLD': 'suspicious_powershell_threshold',
            'WSA_PS_TIMEOUT': 'powershell_timeout',
            'WSA_CMD_TIMEOUT': 'command_timeout',
            'WSA_HIGH_CONN_THRESHOLD': 'high_connection_threshold',
            'WSA_MAX_RISKY_SERVICES': 'max_risky_services_report',
            'WSA_SYS_SERVICES_THRESHOLD': 'system_services_warning_threshold',
            'WSA_MAX_RISKY_PORTS': 'max_risky_ports_report',
        }
        
        for env_var, attr_name in int_vars.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    setattr(config, attr_name, int(value))
                    logger.debug(f"Config loaded from env: {attr_name}={value}")
                except ValueError:
                    logger.warning(f"Invalid integer value for {env_var}: {value}")
        
        # String settings
        str_vars = {
            'WSA_DETAIL_LEVEL': 'default_detail_level',
            'WSA_OUTPUT_ENCODING': 'output_encoding',
        }
        
        for env_var, attr_name in str_vars.items():
            value = os.getenv(env_var)
            if value is not None:
                setattr(config, attr_name, value)
                logger.debug(f"Config loaded from env: {attr_name}={value}")
        
        return config
    
    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from JSON file.
        
        JSON structure:
        {
            "max_autorun_entries": 50,
            "max_event_log_entries": 100,
            "risky_ports": [21, 23, 25, ...],
            ...
        }
        
        Args:
            path: Path to JSON configuration file
            
        Returns:
            Config instance loaded from file
            
        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
        """
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        logger.info(f"Configuration loaded from file: {path}")
        return cls(**data)
    
    def to_file(self, path: str) -> None:
        """Save current configuration to JSON file.
        
        Args:
            path: Path where to save the configuration
        """
        # Convert to dict, handling the dataclass fields
        data = {
            'max_autorun_entries': self.max_autorun_entries,
            'max_event_log_entries': self.max_event_log_entries,
            'max_network_connections': self.max_network_connections,
            'privilege_escalation_threshold': self.privilege_escalation_threshold,
            'brute_force_threshold': self.brute_force_threshold,
            'suspicious_powershell_threshold': self.suspicious_powershell_threshold,
            'risky_ports': self.risky_ports,
            'risky_ports_with_desc': self.risky_ports_with_desc,
            'default_detail_level': self.default_detail_level,
            'powershell_timeout': self.powershell_timeout,
            'command_timeout': self.command_timeout,
            'output_encoding': self.output_encoding,
            'max_description_length': self.max_description_length,
            'max_risky_services_report': self.max_risky_services_report,
            'system_services_warning_threshold': self.system_services_warning_threshold,
            'high_connection_threshold': self.high_connection_threshold,
            'max_risky_ports_report': self.max_risky_ports_report,
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Configuration saved to file: {path}")
    
    def validate_detail_level(self, level: str) -> str:
        """Validate and normalize detail level.
        
        Args:
            level: Detail level string to validate
            
        Returns:
            Validated detail level (lowercase)
            
        Raises:
            ValueError: If detail level is invalid
        """
        level = level.lower().strip()
        valid_levels = ('minimal', 'standard', 'full')
        
        if level not in valid_levels:
            raise ValueError(
                f"Invalid detail_level: {level}. "
                f"Must be one of: {', '.join(valid_levels)}"
            )
        
        return level


# Global config instance (lazy-loaded)
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance.
    
    This function lazily loads the configuration from environment
    variables on first call. Use this instead of direct import for
    applications that need to control when config is loaded.
    
    Returns:
        Global Config instance
    """
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(new_config: Config) -> None:
    """Set the global configuration instance.
    
    Useful for testing or when loading config from a specific file.
    
    Args:
        new_config: New Config instance to use globally
    """
    global _config
    _config = new_config
    logger.info("Global configuration updated")


# For backward compatibility, provide a module-level config
# This is loaded from environment on first access through from_env()
config = Config.from_env()


__all__ = [
    'Config',
    'config',
    'get_config',
    'set_config',
]
