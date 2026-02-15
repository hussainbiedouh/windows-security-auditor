"""Tests for firewall check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import firewall


class TestFirewallChecks:
    """Test firewall checks."""
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    def test_firewall_all_enabled(self, mock_run):
        """Test when all firewall profiles are enabled."""
        mock_run.return_value = (True, "Name : Domain\nEnabled : True\nName : Private\nEnabled : True\nName : Public\nEnabled : True")
        
        findings = firewall.check_firewall()
        
        # Should have individual profile findings and summary
        domain_ok = [f for f in findings if 'Domain' in f['description'] and f['status'] == 'ok']
        private_ok = [f for f in findings if 'Private' in f['description'] and f['status'] == 'ok']
        public_ok = [f for f in findings if 'Public' in f['description'] and f['status'] == 'ok']
        
        assert len(domain_ok) == 1
        assert len(private_ok) == 1
        assert len(public_ok) == 1
        
        # Should have overall summary
        all_enabled = [f for f in findings if 'all' in f['description'].lower() and f['status'] == 'ok']
        assert len(all_enabled) == 1
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    def test_firewall_all_disabled(self, mock_run):
        """Test when all firewall profiles are disabled."""
        mock_run.return_value = (True, "Name : Domain\nEnabled : False\nName : Private\nEnabled : False\nName : Public\nEnabled : False")
        
        findings = firewall.check_firewall()
        
        # Should have warning for each profile
        warnings = [f for f in findings if f['status'] == 'warning' and 'Profile' in f['description']]
        assert len(warnings) == 3
        
        # Should have critical overall finding
        critical = [f for f in findings if f['status'] == 'critical']
        assert len(critical) == 1
        assert 'unprotected' in critical[0]['description'].lower()
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    def test_firewall_mixed(self, mock_run):
        """Test mixed firewall state."""
        mock_run.return_value = (True, "Name : Domain\nEnabled : True\nName : Private\nEnabled : True\nName : Public\nEnabled : False")
        
        findings = firewall.check_firewall()
        
        # Should have 2 OK and 1 warning
        ok_count = len([f for f in findings if f['status'] == 'ok' and 'Profile' in f['description']])
        warning_count = len([f for f in findings if f['status'] == 'warning' and 'Profile' in f['description']])
        
        assert ok_count == 2
        assert warning_count == 1
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    def test_firewall_partial_disabled(self, mock_run):
        """Test when only some profiles are disabled."""
        mock_run.return_value = (True, "Name : Domain\nEnabled : True\nName : Private\nEnabled : False\nName : Public\nEnabled : False")
        
        findings = firewall.check_firewall()
        
        # Should not have critical since at least one is enabled
        critical = [f for f in findings if f['status'] == 'critical']
        assert len(critical) == 0
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    @patch('winsec_auditor.checks.firewall.run_command')
    def test_firewall_fallback_netsh(self, mock_cmd, mock_run):
        """Test firewall check fallback to netsh."""
        mock_run.return_value = (False, "")  # PowerShell fails
        mock_cmd.return_value = (True, "Domain Profile: ON\nPrivate Profile: ON\nPublic Profile: OFF")
        
        findings = firewall.check_firewall()
        
        # Should have used netsh fallback
        assert len(findings) > 0
        mock_cmd.assert_called_once()
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    @patch('winsec_auditor.checks.firewall.run_command')
    def test_firewall_netsh_all_on(self, mock_cmd, mock_run):
        """Test netsh fallback with all profiles ON."""
        mock_run.return_value = (False, "")
        mock_cmd.return_value = (True, "Domain Profile: ON\nPrivate Profile: ON\nPublic Profile: ON")
        
        findings = firewall.check_firewall()
        
        ok_findings = [f for f in findings if f['status'] == 'ok']
        assert len(ok_findings) >= 3
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    @patch('winsec_auditor.checks.firewall.run_command')
    def test_firewall_netsh_all_off(self, mock_cmd, mock_run):
        """Test netsh fallback with all profiles OFF."""
        mock_run.return_value = (False, "")
        mock_cmd.return_value = (True, "Domain Profile: OFF\nPrivate Profile: OFF\nPublic Profile: OFF")
        
        findings = firewall.check_firewall()
        
        critical = [f for f in findings if f['status'] == 'critical']
        assert len(critical) >= 1
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    @patch('winsec_auditor.checks.firewall.run_command')
    def test_firewall_both_methods_fail(self, mock_cmd, mock_run):
        """Test when both PowerShell and netsh fail."""
        mock_run.return_value = (False, "PowerShell error")
        mock_cmd.return_value = (False, "netsh error")
        
        findings = firewall.check_firewall()
        
        error_finding = [f for f in findings if f['status'] == 'error']
        assert len(error_finding) == 1
        assert 'could not' in error_finding[0]['description'].lower()
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    def test_firewall_empty_output(self, mock_run):
        """Test handling of empty PowerShell output."""
        mock_run.return_value = (True, "")
        
        findings = firewall.check_firewall()
        
        # Should fall back or return error
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.firewall.run_powershell')
    def test_firewall_parse_details(self, mock_run):
        """Test that profile details are parsed correctly."""
        mock_run.return_value = (True, "Name : Domain\nEnabled : True\nName : Private\nEnabled : True\nName : Public\nEnabled : True")
        
        findings = firewall.check_firewall()
        
        # Check that profile details have correct structure
        profile_findings = [f for f in findings if 'Profile' in f['description']]
        for finding in profile_findings:
            if finding['details'] is not None:
                assert 'profile' in finding['details']
                assert 'enabled' in finding['details']
