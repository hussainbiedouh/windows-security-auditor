"""Tests for events check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import events


class TestEventsChecks:
    """Test event log analysis checks."""
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_no_threats_detected(self, mock_run):
        """Test when no threats are detected."""
        mock_run.return_value = (True, "")  # No events found
        
        findings = events.check_events()
        
        no_threats = [f for f in findings if 'no security threats' in f['description'].lower()]
        assert len(no_threats) == 1
        assert no_threats[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_brute_force_detected(self, mock_run):
        """Test brute force attack detection."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Count : 10
"""),  # Failed logins
            (True, "0"),  # No lockouts
            (True, "0"),  # No service installs
            (True, ""),   # No PowerShell threats
            (True, "0"),  # No privilege escalation
        ]
        
        findings = events.check_events()
        
        brute = [f for f in findings if 'brute force' in f['description'].lower()]
        assert len(brute) == 1
        assert brute[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_account_lockouts_detected(self, mock_run):
        """Test account lockout detection."""
        mock_run.side_effect = [
            (True, ""),   # No brute force
            (True, "3"),  # 3 lockouts
            (True, "0"),  # No service installs
            (True, ""),   # No PowerShell threats
            (True, "0"),  # No privilege escalation
        ]
        
        findings = events.check_events()
        
        lockouts = [f for f in findings if 'lockout' in f['description'].lower()]
        assert len(lockouts) == 1
        assert lockouts[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_account_lockouts_critical(self, mock_run):
        """Test critical account lockout level."""
        mock_run.side_effect = [
            (True, ""),
            (True, "5"),  # 5 lockouts (critical level)
            (True, "0"),
            (True, ""),
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        lockouts = [f for f in findings if 'lockout' in f['description'].lower()]
        assert len(lockouts) == 1
        assert lockouts[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_service_installations_detected(self, mock_run):
        """Test new service installation detection."""
        mock_run.side_effect = [
            (True, ""),   # No brute force
            (True, "0"),  # No lockouts
            (True, "2"),  # 2 service installs
            (True, ""),   # No PowerShell threats
            (True, "0"),  # No privilege escalation
        ]
        
        findings = events.check_events()
        
        services = [f for f in findings if 'service' in f['description'].lower()]
        assert len(services) == 1
        assert services[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_suspicious_powershell_detected(self, mock_run):
        """Test suspicious PowerShell activity detection."""
        mock_run.side_effect = [
            (True, ""),   # No brute force
            (True, "0"),  # No lockouts
            (True, "0"),  # No service installs
            (True, """
Count : 2
"""),           # 2 suspicious PowerShell events
            (True, "0"),  # No privilege escalation
        ]
        
        findings = events.check_events()
        
        ps = [f for f in findings if 'powershell' in f['description'].lower()]
        assert len(ps) == 1
        assert 'suspicious' in ps[0]['description'].lower()
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_suspicious_powershell_critical(self, mock_run):
        """Test critical suspicious PowerShell level."""
        mock_run.side_effect = [
            (True, ""),
            (True, "0"),
            (True, "0"),
            (True, """
Count : 5
"""),           # 5 suspicious PowerShell events (critical)
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        ps = [f for f in findings if 'powershell' in f['description'].lower()]
        assert len(ps) == 1
        assert ps[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_privilege_escalation_high(self, mock_run):
        """Test high privilege use detection."""
        mock_run.side_effect = [
            (True, ""),
            (True, "0"),
            (True, "0"),
            (True, ""),
            (True, "20"),  # 20 privilege events (unusually high)
        ]
        
        findings = events.check_events()
        
        priv = [f for f in findings if 'privilege' in f['description'].lower()]
        assert len(priv) == 1
        assert priv[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_multiple_threats_detected(self, mock_run):
        """Test detection of multiple threat types."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Count : 10
"""),  # Brute force
            (True, "2"),  # Lockouts
            (True, "1"),  # Service installs
            (True, ""),   # No PowerShell
            (True, "0"),  # Normal privilege use
        ]
        
        findings = events.check_events()
        
        # Should not have "no threats" message
        no_threats = [f for f in findings if 'no security threats' in f['description'].lower()]
        assert len(no_threats) == 0
        
        # Should have findings for each threat type
        threats = [f for f in findings if f['status'] in ['warning', 'critical']]
        assert len(threats) == 3
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_failed_login_parse_error(self, mock_run):
        """Test handling of failed login parse error."""
        mock_run.side_effect = [
            (True, "garbage data"),  # Can't parse
            (True, "0"),
            (True, "0"),
            (True, ""),
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        # Should not crash, should report no threats or continue
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_lockout_parse_error(self, mock_run):
        """Test handling of lockout count parse error."""
        mock_run.side_effect = [
            (True, ""),
            (True, "not a number"),  # Can't parse
            (True, "0"),
            (True, ""),
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_service_install_parse_error(self, mock_run):
        """Test handling of service install count parse error."""
        mock_run.side_effect = [
            (True, ""),
            (True, "0"),
            (True, "not a number"),  # Can't parse
            (True, ""),
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_powershell_parse_error(self, mock_run):
        """Test handling of PowerShell event count parse error."""
        mock_run.side_effect = [
            (True, ""),
            (True, "0"),
            (True, "0"),
            (True, "Count : not_a_number"),  # Can't parse
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_privilege_parse_error(self, mock_run):
        """Test handling of privilege event count parse error."""
        mock_run.side_effect = [
            (True, ""),
            (True, "0"),
            (True, "0"),
            (True, ""),
            (True, "not a number"),  # Can't parse
        ]
        
        findings = events.check_events()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_all_powershell_failures(self, mock_run):
        """Test when all PowerShell calls fail."""
        mock_run.side_effect = [
            (False, "Error 1"),
            (False, "Error 2"),
            (False, "Error 3"),
            (False, "Error 4"),
            (False, "Error 5"),
        ]
        
        findings = events.check_events()
        
        # Should handle gracefully - may report no threats since detection failed
        assert isinstance(findings, list)
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_findings_have_event_id(self, mock_run):
        """Test that findings include event IDs."""
        mock_run.side_effect = [
            (True, """
Name : Admin
Count : 10
"""),  # Brute force
            (True, "0"),
            (True, "0"),
            (True, ""),
            (True, "0"),
        ]
        
        findings = events.check_events()
        
        brute = [f for f in findings if 'brute force' in f['description'].lower()][0]
        assert brute['details'] is not None
        assert 'event_id' in brute['details']
        assert brute['details']['event_id'] == 4625  # Failed logon event ID
    
    @patch('winsec_auditor.checks.events.run_powershell')
    def test_low_privilege_events_normal(self, mock_run):
        """Test that low privilege event count is normal."""
        mock_run.side_effect = [
            (True, ""),
            (True, "0"),
            (True, "0"),
            (True, ""),
            (True, "5"),  # 5 privilege events (normal)
        ]
        
        findings = events.check_events()
        
        # Should not report high privilege use
        priv = [f for f in findings if 'privilege' in f['description'].lower()]
        assert len(priv) == 0
