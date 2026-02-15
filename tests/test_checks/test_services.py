"""Tests for services check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import services


class TestServicesChecks:
    """Test services checks."""
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_running_services_count(self, mock_run):
        """Test running services count."""
        mock_run.side_effect = [
            (True, "50"),  # Count
            (True, ""),
            (True, ""),
        ]
        
        findings = services.check_services()
        
        count = [f for f in findings if 'running' in f['description'].lower() and 'count' in str(f.get('details', {})).lower()]
        assert len(count) == 1
        assert count[0]['status'] == 'info'
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_running_services_count_parse_error(self, mock_run):
        """Test handling of count parse error."""
        mock_run.side_effect = [
            (True, "not a number"),
            (True, ""),
            (True, ""),
        ]
        
        findings = services.check_services()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_risky_service_detection(self, mock_run):
        """Test detection of potentially risky services."""
        mock_run.side_effect = [
            (True, "10"),  # Count
            (True, """
Name : Telnet
DisplayName : Telnet Service
StartType : Manual

Name : Spooler
DisplayName : Print Spooler
StartType : Automatic
"""),
            (True, ""),
        ]
        
        findings = services.check_services()
        
        risky = [f for f in findings if 'risky' in f['description'].lower() or 'telnet' in f['description'].lower()]
        assert len(risky) >= 1
        assert risky[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_no_risky_services(self, mock_run):
        """Test when no risky services found."""
        mock_run.side_effect = [
            (True, "10"),
            (True, """
Name : Spooler
DisplayName : Print Spooler
StartType : Automatic

Name : wuauserv
DisplayName : Windows Update
StartType : Automatic
"""),
            (True, ""),
        ]
        
        findings = services.check_services()
        
        # Should only have count, no warnings
        warnings = [f for f in findings if f['status'] == 'warning']
        assert len(warnings) == 0
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_system_services_count(self, mock_run):
        """Test counting services running as SYSTEM."""
        mock_run.side_effect = [
            (True, "30"),  # Count
            (True, ""),
            (True, """
Name : Service1
DisplayName : Service 1

Name : Service2
DisplayName : Service 2
""" * 30),  # 30 SYSTEM services
        ]
        
        findings = services.check_services()
        
        # Should not warn since less than 50
        high_system = [f for f in findings if 'system' in f['description'].lower() and 'high' in f['description'].lower()]
        assert len(high_system) == 0
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_high_system_services_warning(self, mock_run):
        """Test warning for unusually high SYSTEM services."""
        mock_run.side_effect = [
            (True, "75"),  # Count
            (True, ""),
            (True, """
Name : Service1
DisplayName : Service 1
""" * 60),  # 60 SYSTEM services (high)
        ]
        
        findings = services.check_services()
        
        high_system = [f for f in findings if 'system' in f['description'].lower() and 'high' in f['description'].lower()]
        assert len(high_system) == 1
        assert high_system[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_multiple_risky_services_limited(self, mock_run):
        """Test that only first 3 risky services are reported."""
        mock_run.side_effect = [
            (True, "10"),
            (True, """
Name : Telnet
DisplayName : Telnet Service
StartType : Manual

Name : TFTP
DisplayName : TFTP Client
StartType : Manual

Name : FTP
DisplayName : FTP Service
StartType : Manual

Name : RemoteRegistry
DisplayName : Remote Registry
StartType : Automatic
"""),
            (True, ""),
        ]
        
        findings = services.check_services()
        
        risky = [f for f in findings if 'unnecessary' in f['description'].lower()]
        # Should be limited to 3
        assert len(risky) <= 3
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_risky_service_details(self, mock_run):
        """Test that risky service details are correct."""
        mock_run.side_effect = [
            (True, "10"),
            (True, """
Name : Telnet
DisplayName : Telnet Service
StartType : Manual
"""),
            (True, ""),
        ]
        
        findings = services.check_services()
        
        risky = [f for f in findings if 'unnecessary' in f['description'].lower()][0]
        assert risky['details'] is not None
        assert 'name' in risky['details']
        assert 'display_name' in risky['details']
        assert 'start_type' in risky['details']
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_powershell_all_failures(self, mock_run):
        """Test when all PowerShell calls fail."""
        mock_run.side_effect = [
            (False, "Error 1"),
            (False, "Error 2"),
            (False, "Error 3"),
        ]
        
        findings = services.check_services()
        
        # Should handle gracefully and return empty or minimal findings
        assert isinstance(findings, list)
    
    @patch('winsec_auditor.checks.services.run_powershell')
    def test_partial_powershell_failure(self, mock_run):
        """Test when some PowerShell calls fail."""
        mock_run.side_effect = [
            (True, "50"),  # Count succeeds
            (False, "Error"),  # Details fails
            (False, "Error"),  # SYSTEM check fails
        ]
        
        findings = services.check_services()
        
        # Should have count finding
        count = [f for f in findings if 'running' in f['description'].lower()]
        assert len(count) == 1
