# Windows Security Auditor Configuration

This document describes the configuration system for the Windows Security Auditor.

## Overview

The configuration system allows you to customize the behavior of the security auditor through environment variables or JSON configuration files. All settings have sensible defaults that maintain backward compatibility with the original hardcoded values.

## Quick Start

### Using Environment Variables

```bash
# Set maximum autorun entries to analyze
set WSA_MAX_AUTORUN=100

# Set detail level to 'minimal' (less sensitive data exposure)
set WSA_DETAIL_LEVEL=minimal

# Run the auditor
python -m winsec_auditor
```

### Using JSON Configuration File

Create a `config.json` file:

```json
{
  "max_autorun_entries": 100,
  "max_event_log_entries": 200,
  "default_detail_level": "standard",
  "risky_ports": [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]
}
```

Load it in your code:

```python
from winsec_auditor.config import Config, set_config

config = Config.from_file('config.json')
set_config(config)
```

## Configuration Options

### Analysis Limits

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `max_autorun_entries` | `WSA_MAX_AUTORUN` | 50 | Maximum startup entries to analyze (was hardcoded 10) |
| `max_event_log_entries` | `WSA_MAX_EVENTS` | 100 | Maximum event log entries to retrieve (was hardcoded 10) |
| `max_network_connections` | `WSA_MAX_NETWORK_CONN` | 100 | Maximum network connections to report |

### Security Thresholds

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `privilege_escalation_threshold` | `WSA_PRIV_THRESHOLD` | 10 | Event threshold for privilege escalation detection (was magic number 10) |
| `brute_force_threshold` | `WSA_BRUTE_THRESHOLD` | 5 | Failed attempts threshold for brute force detection (was magic number 5) |
| `suspicious_powershell_threshold` | `WSA_PS_THRESHOLD` | 3 | Events threshold for suspicious PowerShell detection (was magic number 3) |

### Detail Levels

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `default_detail_level` | `WSA_DETAIL_LEVEL` | `standard` | Default detail level for sensitive data: `minimal`, `standard`, or `full` |

Detail levels:
- **minimal**: Only show counts, no individual account details (maximum privacy)
- **standard**: Show account names and status, mask SIDs (balanced privacy/functionality)
- **full**: Show all details including SIDs (not recommended for production/logging)

### Timeouts

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `powershell_timeout` | `WSA_PS_TIMEOUT` | 30 | Timeout for PowerShell commands (seconds) |
| `command_timeout` | `WSA_CMD_TIMEOUT` | 10 | Timeout for system commands (seconds) |

### Network Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `high_connection_threshold` | `WSA_HIGH_CONN_THRESHOLD` | 100 | Threshold for "unusually high" connections warning (was magic number 100) |
| `max_risky_ports_report` | `WSA_MAX_RISKY_PORTS` | 5 | Maximum risky ports to report |

### Risky Ports

The `risky_ports` list defines which ports are considered potentially dangerous when listening:

```python
# Default risky ports
[20, 21, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 443,
 445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443]
```

### Service Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `max_risky_services_report` | `WSA_MAX_RISKY_SERVICES` | 3 | Maximum risky services to report |
| `system_services_warning_threshold` | `WSA_SYS_SERVICES_THRESHOLD` | 50 | Threshold for "high" SYSTEM services warning (was magic number 50) |

## Parsing Utilities

The refactoring extracted common PowerShell output parsing into reusable utilities in `utils.py`:

### Available Parsers

- `parse_powershell_list_output(output, fields)` - Generic Format-List parser
- `parse_user_accounts(output)` - Parse Get-LocalUser output
- `parse_services(output)` - Parse Get-Service output
- `parse_firewall_profiles(output)` - Parse Get-NetFirewallProfile output
- `parse_startup_commands(output)` - Parse Win32_StartupCommand output
- `parse_av_products(output)` - Parse AntivirusProduct WMI output
- `parse_local_group_members(output)` - Parse Get-LocalGroupMember output

### Example Usage

```python
from winsec_auditor.utils import parse_user_accounts, parse_services

# Parse user accounts
output = run_powershell_command(
    cmdlet="Get-LocalUser",
    parameters={"Name": "Administrator"}
)
users = parse_user_accounts(output.stdout)
for user in users:
    print(f"User: {user['Name']}, Enabled: {user['Enabled']}")

# Parse services
output = run_powershell_command(cmdlet="Get-Service")
services = parse_services(output.stdout)
```

## Files Modified

### New Files
- `src/winsec_auditor/config.py` - Configuration system
- `tests/test_config.py` - Configuration tests

### Modified Files
- `src/winsec_auditor/utils.py` - Added parsing utilities
- `src/winsec_auditor/checks/users.py` - Uses `parse_user_accounts()` and config
- `src/winsec_auditor/checks/services.py` - Uses `parse_services()` and config
- `src/winsec_auditor/checks/autorun.py` - Uses `parse_startup_commands()` and config
- `src/winsec_auditor/checks/firewall.py` - Uses `parse_firewall_profiles()` and config
- `src/winsec_auditor/checks/network.py` - Uses config for thresholds and ports
- `src/winsec_auditor/checks/events.py` - Uses config for thresholds
- `src/winsec_auditor/checks/security_sw.py` - Uses `parse_av_products()` and config
- `tests/test_utils.py` - Added parsing utility tests

## Backward Compatibility

All changes maintain backward compatibility:

1. **Default values** match the original hardcoded values
2. **Optional parameters** - Existing code continues to work without changes
3. **Environment variables** are optional - defaults are used if not set
4. **Detail level defaults** to `standard` which matches original behavior

## Security Considerations

### Detail Levels

When logging or reporting in production environments, use `detail_level='minimal'` or `'standard'` to avoid exposing sensitive information like full SIDs.

```python
from winsec_auditor.checks.users import check_users

# For production/logging
findings = check_users(detail_level='minimal')

# For detailed analysis
findings = check_users(detail_level='full')
```

### Configuration Validation

All configuration values are validated:
- Integer values must be positive
- Detail levels must be one of: `minimal`, `standard`, `full`
- Invalid environment variables are ignored with a warning

## Troubleshooting

### Configuration Not Loading

1. Check environment variable names use the `WSA_` prefix
2. Verify integer values don't contain non-numeric characters
3. Ensure detail level is lowercase: `minimal`, `standard`, or `full`

### Changes Not Taking Effect

1. Restart the application after changing environment variables
2. Verify the configuration file path is correct
3. Check that the JSON file is valid (use a JSON validator)

## Migration Guide

### From Hardcoded Values

**Before (Hardcoded):**
```python
# In checks/autorun.py
for entry in entries[:10]:  # Hardcoded limit
```

**After (Configurable):**
```python
from winsec_auditor.config import config

for entry in entries[:config.max_autorun_entries]:  # Configurable
```

### From Manual Parsing

**Before (Manual):**
```python
lines = output.strip().split('\n')
users = []
current_user = {}
for line in lines:
    if line.startswith('Name') and ':' in line:
        if current_user:
            users.append(current_user)
        current_user = {'Name': line.split(':', 1)[1].strip()}
    # ... more parsing
```

**After (Utility):**
```python
from winsec_auditor.utils import parse_user_accounts

users = parse_user_accounts(output)
```

## Performance Considerations

- Parsing utilities use efficient string operations
- Configuration is loaded once at startup (lazy-loaded)
- No performance impact on existing functionality
