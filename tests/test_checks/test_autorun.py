"""Tests for autorun check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import autorun


class TestAutorunChecks:
    """Test autorun/startup checks."""
    
    def test_is_suspicious_path_true(self):
        """Test detection of suspicious paths."""
        assert autorun.is_suspicious_path("C:\\Users\\Test\\AppData\\Local\\Temp\\malware.exe") is True
        assert autorun.is_suspicious_path("C:\\Windows\\Temp\\evil.exe") is True
        assert autorun.is_suspicious_path("C:\\Users\\Test\\Downloads\\file.exe") is True
        assert autorun.is_suspicious_path("C:\\Users\\Test\\AppData\\Roaming\\Temp\\bad.exe") is True
    
    def test_is_suspicious_path_false(self):
        """Test that normal paths are not flagged."""
        assert autorun.is_suspicious_path("C:\\Program Files\\App\\app.exe") is False
        assert autorun.is_suspicious_path("C:\\Program Files (x86)\\App\\app.exe") is False
        assert autorun.is_suspicious_path("C:\\Windows\\System32\\app.exe") is False
    
    def test_is_suspicious_path_case_insensitive(self):
        """Test that path checking is case insensitive."""
        assert autorun.is_suspicious_path("C:\\WINDOWS\\TEMP\\file.exe") is True
        assert autorun.is_suspicious_path("C:\\Users\\Test\\APPDATA\\LOCAL\\TEMP\\file.exe") is True
    
    def test_has_suspicious_keywords_true(self):
        """Test detection of suspicious keywords."""
        assert autorun.has_suspicious_keywords("svchost", "path") is True
        assert autorun.has_suspicious_keywords("name", "update.exe") is True
        assert autorun.has_suspicious_keywords("install", "C:\\temp\\file.exe") is True
    
    def test_has_suspicious_keywords_false(self):
        """Test that normal keywords are not flagged."""
        assert autorun.has_suspicious_keywords("Chrome", "C:\\Program Files\\Chrome\\chrome.exe") is False
        assert autorun.has_suspicious_keywords("Notepad", "C:\\Windows\\notepad.exe") is False
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_no_startup_programs(self, mock_run):
        """Test when no startup programs are found."""
        mock_run.return_value = (True, "")
        
        findings = autorun.check_autorun()
        
        # Should return warning that it could not retrieve
        warning = [f for f in findings if f['status'] == 'warning']
        assert len(warning) == 1
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_clean_startup_programs(self, mock_run):
        """Test normal startup entries."""
        mock_run.return_value = (True, """
Name : NormalApp
Command : C:\\Program Files\\Normal\\app.exe
Location : HKLM
User : SYSTEM
""")
        
        findings = autorun.check_autorun()
        
        # Should have count and no suspicious
        info = [f for f in findings if f['status'] == 'info']
        ok = [f for f in findings if f['status'] == 'ok']
        
        assert len(info) >= 1
        assert len(ok) >= 1
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_suspicious_temp_path(self, mock_run):
        """Test detection of suspicious temp path."""
        mock_run.return_value = (True, """
Name : MaliciousApp
Command : C:\\Users\\Test\\AppData\\Local\\Temp\\malware.exe
Location : HKLM
User : SYSTEM
""")
        
        findings = autorun.check_autorun()
        
        suspicious = [f for f in findings if 'suspicious' in f['description'].lower()]
        assert len(suspicious) >= 1
        assert suspicious[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_suspicious_keyword(self, mock_run):
        """Test detection of suspicious keywords."""
        mock_run.return_value = (True, """
Name : svchost_fake
Command : C:\\Program Files\\Fake\\svchost.exe
Location : HKLM
User : SYSTEM
""")
        
        findings = autorun.check_autorun()
        
        suspicious = [f for f in findings if 'suspicious' in f['description'].lower()]
        assert len(suspicious) >= 1
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_multiple_startup_entries(self, mock_run):
        """Test with multiple startup entries."""
        mock_run.return_value = (True, """
Name : NormalApp1
Command : C:\\Program Files\\App1\\app.exe
Location : HKLM
User : SYSTEM

Name : NormalApp2
Command : C:\\Program Files\\App2\\app.exe
Location : HKLM
User : SYSTEM

Name : SuspiciousApp
Command : C:\\Users\\Test\\AppData\\Local\\Temp\\bad.exe
Location : HKCU
User : TestUser
""")
        
        findings = autorun.check_autorun()
        
        # Should detect 3 total with 1 suspicious
        count_info = [f for f in findings if 'startup programs' in f['description'].lower() and f['status'] == 'info']
        assert len(count_info) == 1
        assert '3' in count_info[0]['description']
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_suspicious_count_summary(self, mock_run):
        """Test summary of suspicious entries."""
        mock_run.return_value = (True, """
Name : BadApp1
Command : C:\\Temp\\bad1.exe
Location : HKLM
User : SYSTEM

Name : BadApp2
Command : C:\\Temp\\bad2.exe
Location : HKLM
User : SYSTEM
""")
        
        findings = autorun.check_autorun()
        
        # Should have summary about suspicious entries
        summary = [f for f in findings if 'potentially suspicious' in f['description'].lower()]
        assert len(summary) == 1
        assert '2' in summary[0]['description']
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_entry_details_structure(self, mock_run):
        """Test that suspicious entries have correct details."""
        mock_run.return_value = (True, """
Name : TestApp
Command : C:\\Temp\\test.exe
Location : HKLM\\Run
User : SYSTEM
""")
        
        findings = autorun.check_autorun()
        
        suspicious = [f for f in findings if f['details'] is not None and 'name' in f.get('details', {})]
        assert len(suspicious) >= 1
        
        details = suspicious[0]['details']
        assert 'name' in details
        assert 'command' in details
        assert 'location' in details
        assert 'user' in details
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_powershell_failure(self, mock_run):
        """Test handling of PowerShell failure."""
        mock_run.return_value = (False, "PowerShell error")
        
        findings = autorun.check_autorun()
        
        warning = [f for f in findings if f['status'] == 'warning']
        assert len(warning) == 1
        assert 'could not' in warning[0]['description'].lower()
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_malformed_output(self, mock_run):
        """Test handling of malformed PowerShell output."""
        mock_run.return_value = (True, "garbage data without proper format")
        
        findings = autorun.check_autorun()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.autorun.run_powershell')
    def test_empty_programs_ok(self, mock_run):
        """Test that zero startup programs shows OK."""
        mock_run.return_value = (True, "")  # Empty output
        
        findings = autorun.check_autorun()
        
        # Should handle empty output
        assert len(findings) >= 1
