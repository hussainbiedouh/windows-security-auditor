"""Tests for users check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import users


class TestUsersChecks:
    """Test user account checks."""
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_user_accounts_enumeration(self, mock_cmd, mock_run):
        """Test user account enumeration."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Enabled : True
LastLogon : 1/15/2024 8:30:15 AM
SID : S-1-5-21-1234567890-1234567890-1234567890-500

Name : Guest
Enabled : False
LastLogon :
SID : S-1-5-21-1234567890-1234567890-1234567890-501

Name : TestUser
Enabled : True
LastLogon : 1/14/2024 3:45:22 PM
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
"""),
            (True, "Name\nAdministrator"),  # Admin group
        ]
        mock_cmd.return_value = (True, " SESSIONNAME USERNAME\n console Administrator")
        
        findings = users.check_users()
        
        # Should have total users, active users
        total = [f for f in findings if 'total' in f['description'].lower()]
        active = [f for f in findings if 'active' in f['description'].lower()]
        
        assert len(total) == 1
        assert '3' in total[0]['description']  # 3 users
        assert len(active) == 1
        assert '2' in active[0]['description']  # 2 active
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_disabled_accounts(self, mock_cmd, mock_run):
        """Test detection of disabled accounts."""
        mock_run.side_effect = [
            (True, """
Name : User1
Enabled : True

Name : User2
Enabled : False

Name : User3
Enabled : False
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users()
        
        disabled = [f for f in findings if 'disabled' in f['description'].lower()]
        assert len(disabled) == 1
        assert '2' in disabled[0]['description']  # 2 disabled
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_guest_account_enabled(self, mock_cmd, mock_run):
        """Test critical finding when guest account is enabled."""
        mock_run.side_effect = [
            (True, """
Name : Guest
Enabled : True
LastLogon : 1/15/2024 8:30:15 AM
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users()
        
        guest = [f for f in findings if 'guest' in f['description'].lower()]
        critical = [f for f in guest if f['status'] == 'critical']
        assert len(critical) == 1
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_guest_account_disabled(self, mock_cmd, mock_run):
        """Test OK finding when guest account is disabled."""
        mock_run.side_effect = [
            (True, """
Name : Guest
Enabled : False
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users()
        
        guest = [f for f in findings if 'guest' in f['description'].lower()]
        ok = [f for f in guest if f['status'] == 'ok']
        assert len(ok) == 1
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_multiple_admins_warning(self, mock_cmd, mock_run):
        """Test warning when multiple admin accounts."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Enabled : True

Name : User1
Enabled : True
"""),
            (True, """
Name : Administrator
Name : User1
Name : User2
"""),  # 3 admins
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users()
        
        admin = [f for f in findings if 'administrator' in f['description'].lower()]
        warning = [f for f in admin if f['status'] == 'warning']
        assert len(warning) == 1
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_single_admin_info(self, mock_cmd, mock_run):
        """Test info when single admin account."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Enabled : True
"""),
            (True, "Name\nAdministrator"),  # 1 admin
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users()
        
        admin = [f for f in findings if 'administrator' in f['description'].lower()]
        info = [f for f in admin if f['status'] == 'info']
        assert len(info) == 1
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_active_sessions(self, mock_cmd, mock_run):
        """Test active session detection."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Enabled : True
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, """
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
 console           Administrator             1  Active
                   TestUser                  2  Active
""")
        
        findings = users.check_users()
        
        sessions = [f for f in findings if 'session' in f['description'].lower()]
        assert len(sessions) == 1
        assert 'Administrator' in sessions[0]['description']
    
    @patch('winsec_auditor.checks.users.run_powershell')
    def test_powershell_failure(self, mock_run):
        """Test handling of PowerShell failure."""
        mock_run.return_value = (False, "PowerShell error")
        
        findings = users.check_users()
        
        warning = [f for f in findings if f['status'] == 'warning']
        assert len(warning) == 1
        assert 'could not' in warning[0]['description'].lower()
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_no_accounts(self, mock_cmd, mock_run):
        """Test with no user accounts found."""
        mock_run.side_effect = [
            (True, ""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users()
        
        # Should return at least a warning
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_qwinsta_failure(self, mock_cmd, mock_run):
        """Test when qwinsta command fails."""
        mock_run.side_effect = [
            (True, """
Name : Administrator
Enabled : True
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (False, "Command failed")
        
        findings = users.check_users()
        
        # Should still complete without error
        assert len(findings) >= 1
