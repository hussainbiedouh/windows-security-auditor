"""Pytest configuration and fixtures."""

import sys
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console


# =============================================================================
# Mock Fixtures for Windows APIs
# =============================================================================

@pytest.fixture
def mock_windows_platform():
    """Mock Windows platform detection."""
    with patch('winsec_auditor.utils.platform.system') as mock:
        mock.return_value = 'Windows'
        yield mock


@pytest.fixture
def mock_linux_platform():
    """Mock Linux platform detection."""
    with patch('winsec_auditor.utils.platform.system') as mock:
        mock.return_value = 'Linux'
        yield mock


@pytest.fixture
def mock_mac_platform():
    """Mock macOS platform detection."""
    with patch('winsec_auditor.utils.platform.system') as mock:
        mock.return_value = 'Darwin'
        yield mock


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run for command testing."""
    with patch('winsec_auditor.utils.subprocess.run') as mock:
        mock.return_value = MagicMock(
            returncode=0,
            stdout="mock output",
            stderr=""
        )
        yield mock


@pytest.fixture
def mock_subprocess_timeout():
    """Mock subprocess.run to simulate timeout."""
    with patch('winsec_auditor.utils.subprocess.run') as mock:
        mock.side_effect = TimeoutError("Command timed out")
        yield mock


@pytest.fixture
def mock_winreg():
    """Mock Windows registry module."""
    winreg_mock = MagicMock()
    winreg_mock.HKEY_LOCAL_MACHINE = 2147483650  # HKEY_LOCAL_MACHINE value
    winreg_mock.REG_DWORD = 4
    winreg_mock.REG_SZ = 1
    winreg_mock.OpenKey = MagicMock()
    winreg_mock.QueryValueEx = MagicMock(return_value=(1, 4))
    winreg_mock.FileNotFoundError = FileNotFoundError
    
    # Patch winreg in all modules that use it
    modules_to_patch = [
        'winsec_auditor.checks.registry.winreg',
    ]
    
    patches = [patch(mod, winreg_mock) for mod in modules_to_patch]
    for p in patches:
        p.start()
    
    yield winreg_mock
    
    for p in patches:
        p.stop()


@pytest.fixture
def mock_wmi():
    """Mock WMI module."""
    wmi_mock = MagicMock()
    wmi_instance = MagicMock()
    wmi_mock.WMI.return_value = wmi_instance
    
    # Mock Win32_Service
    mock_service = MagicMock()
    mock_service.Name = 'TestService'
    mock_service.DisplayName = 'Test Service'
    mock_service.State = 'Running'
    mock_service.StartName = 'LocalSystem'
    wmi_instance.Win32_Service.return_value = [mock_service]
    
    # Mock Win32_QuickFixEngineering
    mock_update = MagicMock()
    mock_update.HotFixID = 'KB123456'
    mock_update.Description = 'Update'
    mock_update.InstalledOn = '2024-01-01'
    wmi_instance.Win32_QuickFixEngineering.return_value = [mock_update]
    
    with patch.dict('sys.modules', {'wmi': wmi_mock}):
        yield wmi_mock


@pytest.fixture
def mock_psutil():
    """Mock psutil module."""
    psutil_mock = MagicMock()
    
    # Mock disk usage
    disk_usage = MagicMock()
    disk_usage.total = 500_000_000_000  # 500 GB
    disk_usage.free = 250_000_000_000   # 250 GB
    disk_usage.used = 250_000_000_000
    disk_usage.percent = 50.0
    psutil_mock.disk_usage.return_value = disk_usage
    
    # Mock virtual memory
    virtual_memory = MagicMock()
    virtual_memory.total = 16_000_000_000  # 16 GB
    virtual_memory.available = 8_000_000_000  # 8 GB
    virtual_memory.used = 8_000_000_000
    virtual_memory.percent = 50.0
    psutil_mock.virtual_memory.return_value = virtual_memory
    
    # Mock boot time
    psutil_mock.boot_time.return_value = 1704067200  # 2024-01-01 00:00:00
    
    # Mock net_connections
    mock_conn = MagicMock()
    mock_conn.status = 'LISTEN'
    mock_conn.laddr = MagicMock()
    mock_conn.laddr.port = 80
    mock_conn.laddr.ip = '0.0.0.0'
    mock_conn.raddr = None
    mock_conn.pid = 1234
    psutil_mock.net_connections.return_value = [mock_conn]
    
    # Mock process
    mock_process = MagicMock()
    mock_process.name.return_value = 'test_process.exe'
    psutil_mock.Process.return_value = mock_process
    
    with patch.dict('sys.modules', {'psutil': psutil_mock}):
        yield psutil_mock


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture
def sample_finding_ok():
    """Sample OK finding."""
    return {
        "category": "Test Category",
        "status": "ok",
        "description": "Test passed successfully",
        "details": {"test": True}
    }


@pytest.fixture
def sample_finding_warning():
    """Sample warning finding."""
    return {
        "category": "Test Category",
        "status": "warning",
        "description": "Warning: something needs attention",
        "details": {"issue": "test_warning"}
    }


@pytest.fixture
def sample_finding_critical():
    """Sample critical finding."""
    return {
        "category": "Test Category",
        "status": "critical",
        "description": "Critical security issue found",
        "details": {"severity": "high"}
    }


@pytest.fixture
def sample_finding_info():
    """Sample info finding."""
    return {
        "category": "Test Category",
        "status": "info",
        "description": "System information: test data",
        "details": None
    }


@pytest.fixture
def sample_finding_error():
    """Sample error finding."""
    return {
        "category": "Test Category",
        "status": "error",
        "description": "Error occurred during check",
        "details": None
    }


@pytest.fixture
def sample_scan_result():
    """Sample complete scan result."""
    return {
        "timestamp": "2024-01-15T10:30:00",
        "scan_type": "basic",
        "findings": [
            {
                "category": "System Information",
                "status": "info",
                "description": "OS: Windows 10",
                "details": {"version": "10.0.19045"}
            },
            {
                "category": "System Information",
                "status": "ok",
                "description": "Disk usage normal",
                "details": {"used_percent": 50}
            },
            {
                "category": "Firewall",
                "status": "ok",
                "description": "All firewall profiles enabled",
                "details": {"enabled_profiles": 3}
            },
            {
                "category": "Updates",
                "status": "warning",
                "description": "5 pending updates",
                "details": {"pending": 5}
            }
        ],
        "summary": {
            "total": 4,
            "info": 1,
            "ok": 2,
            "warning": 1,
            "critical": 0,
            "error": 0
        }
    }


@pytest.fixture
def sample_scan_result_critical():
    """Sample scan result with critical issues."""
    return {
        "timestamp": "2024-01-15T10:30:00",
        "scan_type": "full",
        "findings": [
            {
                "category": "User Accounts",
                "status": "critical",
                "description": "Guest account is enabled - security risk",
                "details": None
            },
            {
                "category": "Registry Security",
                "status": "critical",
                "description": "UAC is disabled",
                "details": {"uac_enabled": False}
            },
            {
                "category": "Security Software",
                "status": "critical",
                "description": "No antivirus detected",
                "details": {"antivirus": None}
            }
        ],
        "summary": {
            "total": 3,
            "info": 0,
            "ok": 0,
            "warning": 0,
            "critical": 3,
            "error": 0
        }
    }


@pytest.fixture
def sample_scan_result_empty():
    """Sample empty scan result."""
    return {
        "timestamp": "2024-01-15T10:30:00",
        "scan_type": "basic",
        "findings": [],
        "summary": {
            "total": 0,
            "info": 0,
            "ok": 0,
            "warning": 0,
            "critical": 0,
            "error": 0
        }
    }


# =============================================================================
# Console and UI Fixtures
# =============================================================================

@pytest.fixture
def mock_console():
    """Mock Rich console."""
    console = MagicMock(spec=Console)
    console.print = MagicMock()
    return console


@pytest.fixture
def real_console():
    """Real Rich console (no color for testing)."""
    return Console(color_system=None, force_terminal=False)


# =============================================================================
# PowerShell Output Fixtures
# =============================================================================

@pytest.fixture
def ps_output_firewall_enabled():
    """Sample PowerShell output for enabled firewall."""
    return """
Name : Domain
Enabled : True
Name : Private
Enabled : True
Name : Public
Enabled : True
"""


@pytest.fixture
def ps_output_firewall_disabled():
    """Sample PowerShell output for disabled firewall."""
    return """
Name : Domain
Enabled : False
Name : Private
Enabled : False
Name : Public
Enabled : False
"""


@pytest.fixture
def ps_output_firewall_mixed():
    """Sample PowerShell output for mixed firewall state."""
    return """
Name : Domain
Enabled : True
Name : Private
Enabled : True
Name : Public
Enabled : False
"""


@pytest.fixture
def ps_output_updates():
    """Sample PowerShell output for Windows updates."""
    return """
HotFixID Description InstalledOn
-------- ----------- -----------
KB5034441 Security Update 1/9/2024
KB5033243 Update 12/12/2023
KB5032190 Security Update 11/14/2023
"""


@pytest.fixture
def ps_output_users():
    """Sample PowerShell output for user accounts."""
    return """
Name : Administrator
Enabled : True
LastLogon : 1/15/2024 8:30:15 AM
SID : S-1-5-21-1234567890-1234567890-1234567890-500
PrincipalSource : Local

Name : Guest
Enabled : False
LastLogon :
SID : S-1-5-21-1234567890-1234567890-1234567890-501
PrincipalSource : Local

Name : TestUser
Enabled : True
LastLogon : 1/14/2024 3:45:22 PM
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
PrincipalSource : Local
"""


@pytest.fixture
def ps_output_services():
    """Sample PowerShell output for services."""
    return """
Name : Spooler
DisplayName : Print Spooler
StartType : Automatic

Name : wuauserv
DisplayName : Windows Update
StartType : Automatic

Name : termservice
DisplayName : Remote Desktop Services
StartType : Manual
"""


@pytest.fixture
def ps_output_startup():
    """Sample PowerShell output for startup programs."""
    return """
Name : OneDrive
Command : "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background
Location : HKU\\S-1-5-21-...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
User : DESKTOP-ABC123\\TestUser

Name : Discord
Command : C:\\Users\\TestUser\\AppData\\Local\\Discord\\Update.exe
Location : HKU\\S-1-5-21-...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
User : DESKTOP-ABC123\\TestUser
"""


# =============================================================================
# Network Output Fixtures
# =============================================================================

@pytest.fixture
def netstat_output():
    """Sample netstat output."""
    return """
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    127.0.0.1:80           0.0.0.0:0              LISTENING
  TCP    192.168.1.100:12345    192.168.1.1:443        ESTABLISHED
  TCP    192.168.1.100:12346    8.8.8.8:53             ESTABLISHED
"""


# =============================================================================
# pytest Configuration
# =============================================================================

def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests (require real Windows system)")
    config.addinivalue_line("markers", "slow: Slow-running tests")
    config.addinivalue_line("markers", "windows_only: Tests that only work on Windows")
