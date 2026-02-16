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


class TestSanitization:
    """Test data sanitization functions."""
    
    def test_mask_sid_full(self):
        """Test SID masking with full SID."""
        sid = "S-1-5-21-1234567890-1234567890-1234567890-500"
        masked = users.mask_sid(sid)
        assert masked == "...-500"
        assert sid not in masked  # Full SID should not be present
    
    def test_mask_sid_short(self):
        """Test SID masking with short SID (4 or fewer chars)."""
        sid = "S-1"
        masked = users.mask_sid(sid)
        assert masked == "****"
    
    def test_mask_sid_five_chars(self):
        """Test SID masking with 5 character string."""
        sid = "short"
        masked = users.mask_sid(sid)
        assert masked == "...hort"  # Shows last 4 chars
    
    def test_mask_sid_none(self):
        """Test SID masking with None."""
        masked = users.mask_sid(None)
        assert masked == "****"
    
    def test_mask_sid_empty(self):
        """Test SID masking with empty string."""
        masked = users.mask_sid("")
        assert masked == "****"
        masked = users.mask_sid("   ")
        assert masked == "****"
    
    def test_sanitize_user_data_standard(self):
        """Test sanitization with standard detail level."""
        user = {
            "Name": "TestUser",
            "Enabled": True,
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "LastLogon": "1/15/2024 8:30:15 AM",
            "PrincipalSource": "Local"
        }
        
        sanitized = users.sanitize_user_data(user, "standard")
        
        assert sanitized["Name"] == "TestUser"
        assert sanitized["Enabled"] == True
        assert "SID" in sanitized
        assert sanitized["SID"] == "...1001"  # Last 4 chars only
        assert "LastLogon" in sanitized
        assert sanitized["LastLogon"] == "Present"  # Not exact timestamp
        assert "PrincipalSource" not in sanitized  # Should be excluded
    
    def test_sanitize_user_data_minimal(self):
        """Test sanitization with minimal detail level."""
        user = {
            "Name": "TestUser",
            "Enabled": True,
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-1001",
        }
        
        sanitized = users.sanitize_user_data(user, "minimal")
        
        assert sanitized == {"count": 1, "masked": True}
        assert "Name" not in sanitized
        assert "SID" not in sanitized
    
    def test_sanitize_user_data_full(self):
        """Test sanitization with full detail level."""
        user = {
            "Name": "TestUser",
            "Enabled": True,
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "LastLogon": "1/15/2024 8:30:15 AM",
        }
        
        sanitized = users.sanitize_user_data(user, "full")
        
        # Should return all data unchanged
        assert sanitized == user
        assert sanitized["SID"] == "S-1-5-21-1234567890-1234567890-1234567890-1001"
    
    def test_sanitize_user_data_invalid_level(self):
        """Test sanitization with invalid detail level."""
        user = {"Name": "TestUser"}
        
        with pytest.raises(ValueError, match="Invalid detail_level"):
            users.sanitize_user_data(user, "invalid")


class TestDetailLevels:
    """Test different detail levels in check_users."""
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_detail_level_minimal(self, mock_cmd, mock_run):
        """Test minimal detail level."""
        mock_run.side_effect = [
            (True, """
Name : TestUser
Enabled : True
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users(detail_level="minimal")
        
        # Should not include user list
        user_list = [f for f in findings if 'user accounts list' in f['description'].lower()]
        assert len(user_list) == 0
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_detail_level_standard_masks_sid(self, mock_cmd, mock_run):
        """Test standard detail level masks SIDs."""
        mock_run.side_effect = [
            (True, """
Name : TestUser
Enabled : True
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users(detail_level="standard")
        
        # Should include user list with masked SIDs
        user_list = [f for f in findings if 'user accounts list' in f['description'].lower()]
        assert len(user_list) == 1
        
        users_data = user_list[0]['details']['users']
        assert len(users_data) == 1
        assert users_data[0]['SID'] == "...1001"  # Masked
        assert "S-1-5-21" not in users_data[0]['SID']  # Full SID not exposed
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_detail_level_full_shows_all(self, mock_cmd, mock_run):
        """Test full detail level shows all data."""
        mock_run.side_effect = [
            (True, """
Name : TestUser
Enabled : True
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users(detail_level="full")
        
        # Should include user list with full SIDs
        user_list = [f for f in findings if 'user accounts list' in f['description'].lower()]
        assert len(user_list) == 1
        
        users_data = user_list[0]['details']['users']
        assert len(users_data) == 1
        assert users_data[0]['SID'] == "S-1-5-21-1234567890-1234567890-1234567890-1001"  # Full SID
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_invalid_detail_level(self, mock_cmd, mock_run):
        """Test invalid detail level returns error."""
        mock_run.side_effect = [
            (True, ""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users(detail_level="invalid")
        
        error = [f for f in findings if f['status'] == 'error']
        assert len(error) == 1
        assert 'invalid' in error[0]['description'].lower()


class TestAdminPrivileges:
    """Test admin privilege checks."""
    
    @patch('winsec_auditor.checks.users.run_powershell')
    def test_check_admin_privileges_standard(self, mock_run):
        """Test admin privileges with standard detail level."""
        mock_run.return_value = (True, """
Name : Administrator
SID : S-1-5-21-1234567890-1234567890-1234567890-500
PrincipalSource : Local

Name : User1
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
PrincipalSource : Local
""")
        
        findings = users.check_admin_privileges(detail_level="standard")
        
        # Should have admin count finding
        admin_count = [f for f in findings if 'administrator account' in f['description'].lower()]
        assert len(admin_count) == 1
        assert admin_count[0]['details']['admin_count'] == 2
        
        # SIDs should be masked
        admins = admin_count[0]['details']['admins']
        assert admins[0]['SID'] == "...-500"
        assert admins[1]['SID'] == "...1001"
    
    @patch('winsec_auditor.checks.users.run_powershell')
    def test_check_admin_privileges_minimal(self, mock_run):
        """Test admin privileges with minimal detail level."""
        mock_run.return_value = (True, """
Name : Administrator
SID : S-1-5-21-1234567890-1234567890-1234567890-500
""")
        
        findings = users.check_admin_privileges(detail_level="minimal")
        
        admin_count = [f for f in findings if 'administrator account' in f['description'].lower()]
        assert len(admin_count) == 1
        
        # Should only show count, no names or SIDs
        admins = admin_count[0]['details']['admins']
        assert admins == [{"id": 1}]
    
    @patch('winsec_auditor.checks.users.run_powershell')
    def test_check_admin_privileges_builtin_admin(self, mock_run):
        """Test detection of built-in Administrator account."""
        mock_run.return_value = (True, """
Name : Administrator
SID : S-1-5-21-1234567890-1234567890-1234567890-500
""")
        
        findings = users.check_admin_privileges(detail_level="standard")
        
        builtin = [f for f in findings if 'built-in' in f['description'].lower()]
        assert len(builtin) == 1
        
        # SID should be masked
        assert builtin[0]['details']['sid'] == "...-500"
    
    @patch('winsec_auditor.checks.users.run_powershell')
    def test_check_admin_privileges_failure(self, mock_run):
        """Test admin privileges check with PowerShell failure."""
        mock_run.return_value = (False, "PowerShell error")
        
        findings = users.check_admin_privileges()
        
        warning = [f for f in findings if f['status'] == 'warning']
        assert len(warning) == 1
        assert 'could not' in warning[0]['description'].lower()


class TestMaskedDataNotExposed:
    """Verify that sensitive data is not exposed in any output."""
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_full_sid_not_in_standard_output(self, mock_cmd, mock_run):
        """Ensure full SID is never in standard output."""
        full_sid = "S-1-5-21-1234567890-1234567890-1234567890-500"
        mock_run.side_effect = [
            (True, f"""
Name : Administrator
Enabled : True
SID : {full_sid}
"""),
            (True, f"Name : Administrator\nSID : {full_sid}"),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users(detail_level="standard")
        
        # Convert all findings to string and check for full SID
        findings_str = str(findings)
        assert full_sid not in findings_str
    
    @patch('winsec_auditor.checks.users.run_powershell')
    @patch('winsec_auditor.checks.users.run_command')
    def test_principal_source_not_exposed(self, mock_cmd, mock_run):
        """Ensure PrincipalSource is not exposed."""
        mock_run.side_effect = [
            (True, """
Name : TestUser
Enabled : True
SID : S-1-5-21-1234567890-1234567890-1234567890-1001
PrincipalSource : Local
"""),
            (True, ""),
        ]
        mock_cmd.return_value = (True, "")
        
        findings = users.check_users(detail_level="standard")
        
        findings_str = str(findings)
        assert "PrincipalSource" not in findings_str
        assert "Local" not in findings_str
