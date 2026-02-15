"""Tests for updates check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import updates


class TestUpdatesChecks:
    """Test Windows updates checks."""
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_updates_found(self, mock_run):
        """Test when updates are found."""
        # First call for update count, second for service, third for pending
        mock_run.side_effect = [
            (True, "HotFixID Description\n-------- -----------\nKB123456 Update\n"),
            (True, "Status Running"),
            (True, "0"),  # No pending updates
        ]
        
        findings = updates.check_updates()
        
        assert len(findings) >= 2
        assert any('installed' in f['description'].lower() for f in findings)
        assert any('service' in f['description'].lower() for f in findings)
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_pending_updates_warning(self, mock_run):
        """Test pending updates detection (warning level)."""
        mock_run.side_effect = [
            (True, "HotFixID\nKB123456"),
            (True, "Status Running"),
            (True, "5"),  # 5 pending updates (warning level)
        ]
        
        findings = updates.check_updates()
        
        pending_finding = [f for f in findings if 'pending' in f['description'].lower()]
        assert len(pending_finding) == 1
        assert pending_finding[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_pending_updates_critical(self, mock_run):
        """Test pending updates detection (critical level)."""
        mock_run.side_effect = [
            (True, "HotFixID\nKB123456"),
            (True, "Status Running"),
            (True, "15"),  # 15 pending updates (critical level)
        ]
        
        findings = updates.check_updates()
        
        pending_finding = [f for f in findings if 'pending' in f['description'].lower()]
        assert len(pending_finding) == 1
        assert pending_finding[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_up_to_date(self, mock_run):
        """Test when system is up to date."""
        mock_run.side_effect = [
            (True, "HotFixID\nKB123456"),
            (True, "Status Running"),
            (True, "0"),  # No pending updates
        ]
        
        findings = updates.check_updates()
        
        up_to_date = [f for f in findings if 'up to date' in f['description'].lower()]
        assert len(up_to_date) == 1
        assert up_to_date[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_service_not_running(self, mock_run):
        """Test when Windows Update service is not running."""
        mock_run.side_effect = [
            (True, "HotFixID\nKB123456"),
            (True, "Status Stopped"),
            (True, "0"),
        ]
        
        findings = updates.check_updates()
        
        service_finding = [f for f in findings if 'service' in f['description'].lower()]
        warning_service = [f for f in service_finding if f['status'] == 'warning']
        assert len(warning_service) >= 1
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_could_not_retrieve_updates(self, mock_run):
        """Test when updates cannot be retrieved."""
        mock_run.side_effect = [
            (False, ""),  # First call fails
            (True, "Status Running"),
            (True, "0"),
        ]
        
        findings = updates.check_updates()
        
        warning = [f for f in findings if 'could not' in f['description'].lower()]
        assert len(warning) >= 1
        assert warning[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_empty_update_list(self, mock_run):
        """Test when update list is empty."""
        mock_run.side_effect = [
            (True, ""),  # Empty output
            (True, "Status Running"),
            (True, "0"),
        ]
        
        findings = updates.check_updates()
        
        warning = [f for f in findings if 'could not' in f['description'].lower()]
        assert len(warning) >= 1
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_pending_parse_error(self, mock_run):
        """Test handling of pending updates parse error."""
        mock_run.side_effect = [
            (True, "HotFixID\nKB123456"),
            (True, "Status Running"),
            (True, "not_a_number"),  # Invalid number
        ]
        
        findings = updates.check_updates()
        
        # Should not crash, just skip pending check
        assert len(findings) >= 2  # At least installed and service
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_all_powershell_failures(self, mock_run):
        """Test when all PowerShell calls fail."""
        mock_run.side_effect = [
            (False, "Error 1"),
            (False, "Error 2"),
            (False, "Error 3"),
        ]
        
        findings = updates.check_updates()
        
        # Should return at least warning findings
        assert len(findings) >= 1
        assert all(f['category'] == 'Windows Updates' for f in findings)
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_installed_count_calculation(self, mock_run):
        """Test installed updates count calculation."""
        mock_run.side_effect = [
            (True, "HotFixID  Description   InstalledOn\n--------  -----------   -----------\nKB5034441 Security      1/9/2024\nKB5033243 Update        12/12/2023\nKB5032190 Security      11/14/2023"),
            (True, "Status Running"),
            (True, "0"),
        ]
        
        findings = updates.check_updates()
        
        installed = [f for f in findings if 'installed' in f['description'].lower()][0]
        assert '3' in installed['description'] or '1' in installed['description']
        assert installed['details'] is not None
        assert 'count' in installed['details']
    
    @patch('winsec_auditor.checks.updates.run_powershell')
    def test_timeout_handling(self, mock_run):
        """Test timeout handling in PowerShell calls."""
        mock_run.side_effect = [
            (False, "Command timed out"),
            (False, "Command timed out"),
            (False, "Command timed out"),
        ]
        
        findings = updates.check_updates()
        
        # Should handle timeout gracefully
        assert len(findings) >= 1
