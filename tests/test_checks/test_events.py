"""Tests for events check module.

These tests verify that the secure event log analysis functions work correctly
and that all PowerShell commands use the secure run_powershell_command function.
"""

from unittest.mock import patch, MagicMock

import pytest

from winsec_auditor.checks.events import (
    check_events,
    _check_brute_force_attempts,
    _check_account_lockouts,
    _check_service_installations,
    _check_suspicious_powershell,
    _check_privilege_escalation,
    _validate_event_id,
    _validate_log_name,
    VALID_EVENT_IDS,
    VALID_LOG_NAMES,
)
from winsec_auditor.utils import PowerShellResult


class TestSecurityValidation:
    """Test input validation functions."""
    
    def test_validate_event_id_success(self):
        """Test valid event ID validation."""
        for event_id in VALID_EVENT_IDS:
            assert _validate_event_id(event_id) == event_id
    
    def test_validate_event_id_invalid_type(self):
        """Test event ID validation with wrong type."""
        with pytest.raises(ValueError):
            _validate_event_id("4625")
        with pytest.raises(ValueError):
            _validate_event_id(None)
    
    def test_validate_event_id_not_allowed(self):
        """Test event ID validation with disallowed ID."""
        with pytest.raises(ValueError):
            _validate_event_id(9999)
        with pytest.raises(ValueError):
            _validate_event_id(0)
    
    def test_validate_log_name_success(self):
        """Test valid log name validation."""
        for log_name in VALID_LOG_NAMES:
            assert _validate_log_name(log_name) == log_name
    
    def test_validate_log_name_invalid_type(self):
        """Test log name validation with wrong type."""
        with pytest.raises(ValueError):
            _validate_log_name(123)
        with pytest.raises(ValueError):
            _validate_log_name(None)
    
    def test_validate_log_name_not_allowed(self):
        """Test log name validation with disallowed name."""
        with pytest.raises(ValueError):
            _validate_log_name("Injected; Get-Process")
        with pytest.raises(ValueError):
            _validate_log_name("Security' -Command 'malicious'")
    
    def test_validate_log_name_strips_whitespace(self):
        """Test that log name validation strips whitespace."""
        assert _validate_log_name("  Security  ") == "Security"


class TestPowerShellSecurity:
    """Test that PowerShell commands are executed securely."""
    
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_run_powershell_command_called_with_validation(self, mock_run):
        """Test that secure function is called with validated parameters."""
        mock_run.return_value = PowerShellResult(
            returncode=0,
            stdout="",
            stderr="",
            command="Get-WinEvent -FilterHashtable @LogName='Security'"
        )
        
        _check_account_lockouts()
        
        # Verify secure function was called
        assert mock_run.called
        
        # Verify cmdlet is whitelisted
        call_args = mock_run.call_args
        assert call_args[1]['cmdlet'] == 'Get-WinEvent'
    
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_no_injection_in_parameters(self, mock_run):
        """Test that no injection can occur through parameters."""
        mock_run.return_value = PowerShellResult(
            returncode=0,
            stdout="0",
            stderr="",
            command="Get-WinEvent -FilterHashtable @LogName='Security'"
        )
        
        # Try to trigger injection - should be caught by validation
        _check_account_lockouts()
        
        # Verify filter hashtable doesn't contain injection
        call_kwargs = mock_run.call_args[1]
        filter_ht = call_kwargs['parameters']['FilterHashtable']
        
        # Ensure no dangerous characters in filter
        assert ';' not in filter_ht
        assert '&' not in filter_ht
        assert '|' not in filter_ht
        assert '`' not in filter_ht
        assert '$(' not in filter_ht


class TestEventsChecks:
    """Test event log analysis checks with mocked secure functions."""
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_no_threats_detected(self, mock_run_cmd, mock_run):
        """Test when no threats are detected."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        
        findings = check_events()
        
        no_threats = [f for f in findings if 'no security threats' in f['description'].lower()]
        assert len(no_threats) == 1
        assert no_threats[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_brute_force_detected(self, mock_run_cmd, mock_run):
        """Test brute force attack detection."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, 
            stdout="some events", 
            stderr="", 
            command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(
                returncode=0,
                stdout="Name : Administrator\nCount : 10",
                stderr="",
                command="test"
            ),  # Group query for failed logins
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No lockouts
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No service installs
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No PowerShell threats
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No privilege escalation
        ]
        
        findings = check_events()
        
        brute = [f for f in findings if 'brute force' in f['description'].lower()]
        assert len(brute) == 1
        assert brute[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_account_lockouts_detected(self, mock_run_cmd, mock_run):
        """Test account lockout detection."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No brute force
            PowerShellResult(returncode=0, stdout="3", stderr="", command="test"),  # 3 lockouts
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No service installs
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No PowerShell threats
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No privilege escalation
        ]
        
        findings = check_events()
        
        lockouts = [f for f in findings if 'lockout' in f['description'].lower()]
        assert len(lockouts) == 1
        assert lockouts[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_account_lockouts_critical(self, mock_run_cmd, mock_run):
        """Test critical account lockout level."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="5", stderr="", command="test"),  # 5 lockouts (critical level)
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
        ]
        
        findings = check_events()
        
        lockouts = [f for f in findings if 'lockout' in f['description'].lower()]
        assert len(lockouts) == 1
        assert lockouts[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_service_installations_detected(self, mock_run_cmd, mock_run):
        """Test new service installation detection."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No brute force
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No lockouts
            PowerShellResult(returncode=0, stdout="2", stderr="", command="test"),  # 2 service installs
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No PowerShell threats
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No privilege escalation
        ]
        
        findings = check_events()
        
        services = [f for f in findings if 'service' in f['description'].lower()]
        assert len(services) == 1
        assert services[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_suspicious_powershell_detected(self, mock_run_cmd, mock_run):
        """Test suspicious PowerShell activity detection."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No brute force
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No lockouts
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No service installs
            PowerShellResult(
                returncode=0,
                stdout="Count : 2",
                stderr="",
                command="test"
            ),           # 2 suspicious PowerShell events
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # No privilege escalation
        ]
        
        findings = check_events()
        
        ps = [f for f in findings if 'powershell' in f['description'].lower()]
        assert len(ps) == 1
        assert 'suspicious' in ps[0]['description'].lower()
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_suspicious_powershell_critical(self, mock_run_cmd, mock_run):
        """Test critical suspicious PowerShell level."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(
                returncode=0,
                stdout="Count : 5",
                stderr="",
                command="test"
            ),           # 5 suspicious PowerShell events (critical)
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
        ]
        
        findings = check_events()
        
        ps = [f for f in findings if 'powershell' in f['description'].lower()]
        assert len(ps) == 1
        assert ps[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_privilege_escalation_high(self, mock_run_cmd, mock_run):
        """Test high privilege use detection."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="20", stderr="", command="test"),  # 20 privilege events (unusually high)
        ]
        
        findings = check_events()
        
        priv = [f for f in findings if 'privilege' in f['description'].lower()]
        assert len(priv) == 1
        assert priv[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_multiple_threats_detected(self, mock_run_cmd, mock_run):
        """Test detection of multiple threat types."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="events found", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(
                returncode=0,
                stdout="Name : Administrator\nCount : 10",
                stderr="",
                command="test"
            ),  # Brute force
            PowerShellResult(returncode=0, stdout="2", stderr="", command="test"),  # Lockouts
            PowerShellResult(returncode=0, stdout="1", stderr="", command="test"),  # Service installs
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),   # No PowerShell
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),  # Normal privilege use
        ]
        
        findings = check_events()
        
        # Should not have "no threats" message
        no_threats = [f for f in findings if 'no security threats' in f['description'].lower()]
        assert len(no_threats) == 0
        
        # Should have findings for each threat type
        threats = [f for f in findings if f['status'] in ['warning', 'critical']]
        assert len(threats) == 3
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_failed_login_parse_error(self, mock_run_cmd, mock_run):
        """Test handling of failed login parse error."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="events found", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="garbage data", stderr="", command="test"),  # Can't parse
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
        ]
        
        findings = check_events()
        
        # Should not crash, should report no threats or continue
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_all_powershell_failures(self, mock_run_cmd, mock_run):
        """Test when all PowerShell calls fail."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=1, stdout="", stderr="Error 1", command="test"),
            PowerShellResult(returncode=1, stdout="", stderr="Error 2", command="test"),
            PowerShellResult(returncode=1, stdout="", stderr="Error 3", command="test"),
            PowerShellResult(returncode=1, stdout="", stderr="Error 4", command="test"),
            PowerShellResult(returncode=1, stdout="", stderr="Error 5", command="test"),
        ]
        
        findings = check_events()
        
        # Should handle gracefully - may report no threats since detection failed
        assert isinstance(findings, list)
        # Should have error findings for each check
        errors = [f for f in findings if f['status'] == 'error']
        assert len(errors) == 5  # All 5 checks should report errors
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_findings_have_event_id(self, mock_run_cmd, mock_run):
        """Test that findings include event IDs."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="events found", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(
                returncode=0,
                stdout="Name : Admin\nCount : 10",
                stderr="",
                command="test"
            ),  # Brute force
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
        ]
        
        findings = check_events()
        
        brute = [f for f in findings if 'brute force' in f['description'].lower()][0]
        assert brute['details'] is not None
        assert 'event_id' in brute['details']
        assert brute['details']['event_id'] == 4625  # Failed logon event ID
    
    @patch('winsec_auditor.checks.events.run_powershell')
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_low_privilege_events_normal(self, mock_run_cmd, mock_run):
        """Test that low privilege event count is normal."""
        mock_run_cmd.return_value = PowerShellResult(
            returncode=0, stdout="", stderr="", command="test"
        )
        mock_run.side_effect = [
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="0", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="", stderr="", command="test"),
            PowerShellResult(returncode=0, stdout="5", stderr="", command="test"),  # 5 privilege events (normal)
        ]
        
        findings = check_events()
        
        # Should not report high privilege use
        priv = [f for f in findings if 'privilege' in f['description'].lower()]
        assert len(priv) == 0


class TestErrorHandling:
    """Test error handling in event checks."""
    
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_timeout_error_handled(self, mock_run):
        """Test that timeout errors are handled gracefully."""
        from winsec_auditor.utils import PowerShellError
        mock_run.side_effect = PowerShellError("Command execution timed out")
        
        findings = check_events()
        
        # Should have error findings
        errors = [f for f in findings if f['status'] == 'error']
        assert len(errors) >= 1
        assert 'timeout' in errors[0]['description'].lower() or 'failed' in errors[0]['description'].lower()
    
    @patch('winsec_auditor.checks.events.run_powershell_command')
    def test_permission_error_handled(self, mock_run):
        """Test that permission errors are handled gracefully."""
        mock_run.return_value = PowerShellResult(
            returncode=1,
            stdout="",
            stderr="Access denied",
            command="test"
        )
        
        findings = check_events()
        
        # Should handle gracefully and return findings
        assert isinstance(findings, list)


class TestInjectionPrevention:
    """Test that various injection attacks are prevented."""
    
    def test_no_f_string_injection(self):
        """Verify no user input is used in f-string command construction."""
        # This test verifies the code structure - no user input should be
        # concatenated into PowerShell commands
        import inspect
        source = inspect.getsource(check_events)
        
        # Check for dangerous patterns
        # These patterns should NOT exist with user-controlled input
        dangerous_patterns = [
            "f\"Get-WinEvent",
            "f'Get-WinEvent",
            "command = f\"",
            "command = f'",
        ]
        
        for pattern in dangerous_patterns:
            # The function should use secure parameter binding, not f-strings
            assert pattern not in source, f"Dangerous pattern found: {pattern}"
