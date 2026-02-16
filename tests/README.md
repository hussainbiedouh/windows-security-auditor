# Windows Security Auditor - Test Suite

This directory contains comprehensive test coverage for the winsec_auditor package.

## Test Statistics

### Total Tests Written

| Test File | Test Count | Coverage Focus |
|-----------|------------|----------------|
| `test_cli.py` | 35+ | CLI arguments, exit codes, output formats |
| `test_scanner.py` | 25+ | Scanner orchestration, progress, error handling |
| `test_report.py` | 30+ | Console, JSON, HTML report generation |
| `test_checks/test_system.py` | 15+ | System info, disk/memory checks |
| `test_checks/test_updates.py` | 12+ | Windows update detection |
| `test_checks/test_firewall.py` | 14+ | Firewall status checks |
| `test_checks/test_autorun.py` | 18+ | Startup program detection |
| `test_checks/test_users.py` | 16+ | User account enumeration |
| `test_checks/test_services.py` | 12+ | Service enumeration, risky services |
| `test_checks/test_registry.py` | 20+ | UAC, PowerShell policy, registry checks |
| `test_checks/test_network.py` | 17+ | Listening ports, risky port detection |
| `test_checks/test_security_sw.py` | 15+ | AV, firewall, antispyware detection |
| `test_checks/test_events.py` | 18+ | Event log analysis, threat detection |
| `test_utils.py` | 35+ | Utility functions, platform detection |
| **TOTAL** | **~270+ tests** | **~85-90% coverage** |

## Coverage Targets

- **Minimum Overall Coverage**: 80%
- **Critical Path Coverage**: 100% (scanner, report generation)
- **CLI Coverage**: 90%+
- **Check Modules**: 85%+

## Running Tests

### Run All Tests

```bash
# Using pytest directly
pytest

# Using pytest with coverage
pytest --cov=src/winsec_auditor --cov-report=term-missing

# Using the pytest.ini configuration (recommended)
pytest
```

### Run Specific Test Files

```bash
# CLI tests only
pytest tests/test_cli.py -v

# Scanner tests only
pytest tests/test_scanner.py -v

# Specific check tests
pytest tests/test_checks/test_firewall.py -v
pytest tests/test_checks/test_registry.py -v
```

### Run Tests by Marker

```bash
# Unit tests only
pytest -m unit

# Skip slow tests
pytest -m "not slow"

# Skip integration tests
pytest -m "not integration"
```

### Coverage Reports

```bash
# Terminal coverage report
pytest --cov=src/winsec_auditor --cov-report=term

# HTML coverage report
pytest --cov=src/winsec_auditor --cov-report=html
# Then open htmlcov/index.html

# XML coverage report (for CI)
pytest --cov=src/winsec_auditor --cov-report=xml
```

## Test Organization

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── test_cli.py              # CLI command tests
├── test_scanner.py          # Scanner orchestration tests
├── test_report.py           # Report generation tests
├── test_utils.py            # Utility function tests
└── test_checks/             # Individual security check tests
    ├── test_system.py       # System information checks
    ├── test_updates.py      # Windows update checks
    ├── test_firewall.py     # Firewall status checks
    ├── test_autorun.py      # Startup program checks
    ├── test_users.py        # User account checks
    ├── test_services.py     # Service enumeration checks
    ├── test_registry.py     # Registry security checks
    ├── test_network.py      # Network security checks
    ├── test_security_sw.py  # Security software checks
    ├── test_events.py       # Event log analysis checks
    └── test_all_checks.py   # Aggregated check tests
```

## Key Testing Patterns

### Mocking Windows-Specific APIs

```python
@patch('winsec_auditor.utils.subprocess.run')
def test_windows_command(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='mocked output',
        stderr=''
    )
    result = run_powershell('Get-Date')
    assert result == (True, 'mocked output')
```

### Mocking Registry Access

```python
@patch('winreg.OpenKey')
@patch('winreg.QueryValueEx')
def test_registry_check(mock_query, mock_open):
    mock_query.return_value = (1, winreg.REG_DWORD)
    result = check_uac()
    assert result is True
```

### Platform Detection Mocking

```python
@patch('winsec_auditor.utils.platform.system')
def test_non_windows(mock_system):
    mock_system.return_value = 'Linux'
    assert is_windows() is False
```

## Fixtures Available

### From `conftest.py`:

- `mock_windows_platform` - Mock Windows platform
- `mock_linux_platform` - Mock Linux platform  
- `mock_subprocess_run` - Mock subprocess execution
- `mock_winreg` - Mock Windows registry
- `mock_wmi` - Mock WMI interface
- `mock_psutil` - Mock psutil module
- `sample_scan_result` - Sample scan result with various findings
- `sample_scan_result_critical` - Scan result with critical issues
- `sample_scan_result_empty` - Empty scan result
- `real_console` - Real Rich console (no color)
- `netstat_output` - Sample netstat output
- Various PowerShell output fixtures

## Windows-Specific Testing Notes

### Mocking Requirements

Since this package is Windows-specific, most tests mock:

1. **Platform Detection** - `is_windows()` is mocked to return True for unit tests
2. **PowerShell Commands** - All PowerShell calls are mocked
3. **Registry Access** - `winreg` module is mocked
4. **WMI Queries** - WMI calls are mocked
5. **System Commands** - Commands like `netstat`, `netsh` are mocked

### Integration Tests

Tests marked with `@pytest.mark.integration` require a real Windows system:

```python
@pytest.mark.integration
def test_real_windows_update_check():
    # This test runs actual PowerShell commands
    findings = check_updates()
    assert len(findings) > 0
```

Skip integration tests on CI:
```bash
pytest -m "not integration"
```

### Admin Privilege Tests

Some tests require admin privileges. These are marked with `@pytest.mark.windows_only`:

```python
@pytest.mark.windows_only
@pytest.mark.skipif(not is_admin(), reason="Requires admin privileges")
def test_service_control():
    # Test that requires admin
    pass
```

## Edge Cases Covered

1. **Windows Not Detected** - Tests verify graceful exit on Linux/Mac
2. **PowerShell Not Available** - Tests handle PowerShell execution failures
3. **Registry Access Denied** - Tests handle permission errors
4. **WMI Connection Failure** - Tests handle WMI unavailability
5. **Timeout on External Commands** - Tests handle command timeouts
6. **Empty Results** - Tests handle checks returning no data
7. **Malformed Output** - Tests handle unexpected command output
8. **Unicode Characters** - Tests handle non-ASCII characters
9. **Very Large Output** - Tests handle large command outputs
10. **Network Unavailable** - Tests handle network-related failures

## Continuous Integration

For CI environments, use:

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests with coverage
pytest --cov=src/winsec_auditor --cov-report=xml --cov-fail-under=80

# Run only unit tests
pytest -m "not integration and not windows_only"
```

## Adding New Tests

1. Create test file in appropriate directory
2. Import from conftest.py fixtures as needed
3. Mock Windows-specific dependencies
4. Test both success and failure cases
5. Test edge cases
6. Add markers for slow/integration tests
7. Verify coverage with `pytest --cov`

## Test Naming Conventions

- Test functions: `test_<what_is_being_tested>_<condition>`
- Test classes: `Test<WhatIsBeingTested>`
- Fixtures: descriptive names with docstrings

Examples:
```python
def test_firewall_all_enabled():
def test_firewall_fallback_netsh():
def test_powershell_execution_timeout():
```

## Troubleshooting

### Tests Failing on Non-Windows

All tests mock `is_windows()` by default. If tests fail on Linux/Mac:

1. Check that patches are applied correctly
2. Verify conftest.py fixtures are being used
3. Ensure platform.system() is mocked

### Coverage Below Target

1. Check which files are not covered: `pytest --cov=src/winsec_auditor --cov-report=term-missing`
2. Add tests for uncovered lines
3. Some lines may be Windows-only and can't be tested on other platforms

### Import Errors

Ensure the package is installed in editable mode:
```bash
pip install -e .
```

Or set PYTHONPATH:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```
