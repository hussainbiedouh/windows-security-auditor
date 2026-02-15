"""Tests for registry check module."""

import sys
from unittest.mock import patch, MagicMock

import pytest

# Mock winreg before importing registry module
winreg_mock = MagicMock()
winreg_mock.HKEY_LOCAL_MACHINE = 2147483650
winreg_mock.REG_DWORD = 4
winreg_mock.OpenKey = MagicMock()
winreg_mock.QueryValueEx = MagicMock()
winreg_mock.FileNotFoundError = FileNotFoundError

sys.modules['winreg'] = winreg_mock

from winsec_auditor.checks import registry


class TestRegistryChecks:
    """Test registry security checks."""
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_uac_enabled(self, mock_ps, mock_query, mock_open):
        """Test UAC enabled detection."""
        mock_query.return_value = (1, 4)  # UAC enabled
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        uac = [f for f in findings if 'UAC' in f['description'] and 'enabled' in f['description'].lower()]
        ok = [f for f in uac if f['status'] == 'ok']
        assert len(ok) == 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_uac_disabled(self, mock_ps, mock_query, mock_open):
        """Test UAC disabled detection."""
        mock_query.return_value = (0, 4)  # UAC disabled
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        uac = [f for f in findings if 'UAC' in f['description']]
        critical = [f for f in uac if f['status'] == 'critical']
        assert len(critical) == 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_uac_key_not_found(self, mock_ps, mock_query, mock_open):
        """Test handling of missing UAC key."""
        mock_query.side_effect = FileNotFoundError("Key not found")
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        uac = [f for f in findings if 'UAC' in f['description']]
        warning = [f for f in uac if f['status'] == 'warning']
        assert len(warning) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_uac_always_notify(self, mock_ps, mock_query, mock_open):
        """Test UAC level - Always notify (2)."""
        mock_query.side_effect = [
            (1, 4),  # EnableLUA = 1
            (2, 4),  # ConsentPromptBehaviorAdmin = 2
        ]
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        level = [f for f in findings if 'Always notify' in f['description']]
        assert len(level) == 1
        assert level[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_uac_notify_apps_only(self, mock_ps, mock_query, mock_open):
        """Test UAC level - Notify apps only (5)."""
        mock_query.side_effect = [
            (1, 4),  # EnableLUA = 1
            (5, 4),  # ConsentPromptBehaviorAdmin = 5
        ]
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        level = [f for f in findings if 'apps try to make changes' in f['description']]
        assert len(level) == 1
        assert level[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_uac_never_notify(self, mock_ps, mock_query, mock_open):
        """Test UAC level - Never notify (0)."""
        mock_query.side_effect = [
            (1, 4),  # EnableLUA = 1
            (0, 4),  # ConsentPromptBehaviorAdmin = 0
        ]
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        level = [f for f in findings if 'Never notify' in f['description']]
        assert len(level) == 1
        assert level[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_powershell_restricted(self, mock_ps, mock_query, mock_open):
        """Test PowerShell execution policy - Restricted."""
        mock_query.return_value = (1, 4)
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        ps = [f for f in findings if 'PowerShell' in f['description']]
        ok = [f for f in ps if f['status'] == 'ok']
        assert len(ok) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_powershell_allsigned(self, mock_ps, mock_query, mock_open):
        """Test PowerShell execution policy - AllSigned."""
        mock_query.return_value = (1, 4)
        mock_ps.return_value = (True, "AllSigned")
        
        findings = registry.check_registry()
        
        ps = [f for f in findings if 'PowerShell' in f['description']]
        ok = [f for f in ps if f['status'] == 'ok' and 'signed' in f['description'].lower()]
        assert len(ok) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_powershell_remotesigned(self, mock_ps, mock_query, mock_open):
        """Test PowerShell execution policy - RemoteSigned."""
        mock_query.return_value = (1, 4)
        mock_ps.return_value = (True, "RemoteSigned")
        
        findings = registry.check_registry()
        
        ps = [f for f in findings if 'PowerShell' in f['description']]
        warning = [f for f in ps if f['status'] == 'warning']
        assert len(warning) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_powershell_unrestricted(self, mock_ps, mock_query, mock_open):
        """Test PowerShell execution policy - Unrestricted."""
        mock_query.return_value = (1, 4)
        mock_ps.return_value = (True, "Unrestricted")
        
        findings = registry.check_registry()
        
        ps = [f for f in findings if 'PowerShell' in f['description']]
        critical = [f for f in ps if f['status'] == 'critical']
        assert len(critical) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_powershell_bypass(self, mock_ps, mock_query, mock_open):
        """Test PowerShell execution policy - Bypass."""
        mock_query.return_value = (1, 4)
        mock_ps.return_value = (True, "Bypass")
        
        findings = registry.check_registry()
        
        ps = [f for f in findings if 'PowerShell' in f['description']]
        critical = [f for f in ps if f['status'] == 'critical']
        assert len(critical) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_powershell_failure(self, mock_ps, mock_query, mock_open):
        """Test handling of PowerShell execution policy check failure."""
        mock_query.return_value = (1, 4)
        mock_ps.return_value = (False, "PowerShell not found")
        
        findings = registry.check_registry()
        
        ps = [f for f in findings if 'PowerShell' in f['description']]
        warning = [f for f in ps if f['status'] == 'warning']
        assert len(warning) >= 1
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_auto_login_enabled(self, mock_ps, mock_query, mock_open):
        """Test auto-login detection (security risk)."""
        def mock_query_values(key_path, value_name):
            if value_name == "EnableLUA":
                return (1, 4)
            elif value_name == "AutoAdminLogon":
                return ("1", 1)
            return (0, 4)
        
        mock_query.side_effect = mock_query_values
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        auto = [f for f in findings if 'auto-login' in f['description'].lower()]
        assert len(auto) == 1
        assert auto[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_defender_disabled(self, mock_ps, mock_query, mock_open):
        """Test Windows Defender disabled detection."""
        def mock_query_values(key_path, value_name):
            if value_name == "EnableLUA":
                return (1, 4)
            elif value_name == "DisableRealtimeMonitoring":
                return (1, 4)  # Disabled
            return (0, 4)
        
        mock_query.side_effect = mock_query_values
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        defender = [f for f in findings if 'Defender' in f['description']]
        assert len(defender) == 1
        assert defender[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.registry.winreg.OpenKey')
    @patch('winsec_auditor.checks.registry.winreg.QueryValueEx')
    @patch('winsec_auditor.checks.registry.run_powershell')
    def test_registry_open_error(self, mock_ps, mock_query, mock_open):
        """Test handling of registry open error."""
        mock_open.side_effect = PermissionError("Access denied")
        mock_ps.return_value = (True, "Restricted")
        
        findings = registry.check_registry()
        
        # Should handle gracefully
        assert len(findings) >= 1
