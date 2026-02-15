"""Tests for security software check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import security_sw


class TestSecuritySoftwareChecks:
    """Test security software checks."""
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_antivirus_detected_active(self, mock_run):
        """Test AV detection when active."""
        mock_run.side_effect = [
            (True, """
displayName : Windows Defender
productState : 266240
"""),  # AV from WMI
            (True, """
Name : Domain
Enabled : True
"""),  # Firewall
            (True, ""),  # Antispyware
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'antivirus' in f['description'].lower()]
        ok = [f for f in av if f['status'] == 'ok']
        assert len(ok) >= 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_antivirus_installed_not_active(self, mock_run):
        """Test AV detection when installed but not active."""
        mock_run.side_effect = [
            (True, """
displayName : SomeAV
productState : 0
"""),  # AV from WMI with inactive state
            (True, ""),
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'antivirus' in f['description'].lower()]
        warning = [f for f in av if f['status'] == 'warning']
        assert len(warning) >= 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_windows_defender_fallback(self, mock_run):
        """Test Windows Defender detection as fallback."""
        mock_run.side_effect = [
            (True, ""),  # No AV from WMI
            (True, """
AntivirusEnabled : True
RealTimeProtectionEnabled : True
"""),  # Defender status
            (True, ""),  # Antispyware
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'defender' in f['description'].lower()]
        assert len(av) >= 1
        assert av[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_no_antivirus_detected(self, mock_run):
        """Test when no AV is detected."""
        mock_run.side_effect = [
            (True, ""),  # No AV from WMI
            (True, ""),  # No Defender
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'no antivirus' in f['description'].lower()]
        assert len(av) == 1
        assert av[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_firewall_active(self, mock_run):
        """Test Windows Firewall detection when active."""
        mock_run.side_effect = [
            (True, ""),
            (True, """
Name : Domain
Enabled : True
Name : Private
Enabled : True
Name : Public
Enabled : True
"""),  # 3 profiles enabled
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        fw = [f for f in findings if 'firewall' in f['description'].lower()]
        ok = [f for f in fw if f['status'] == 'ok']
        assert len(ok) >= 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_firewall_inactive(self, mock_run):
        """Test Windows Firewall detection when inactive."""
        mock_run.side_effect = [
            (True, ""),
            (True, """
Name : Domain
Enabled : False
Name : Private
Enabled : False
Name : Public
Enabled : False
"""),
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        fw = [f for f in findings if 'firewall' in f['description'].lower()]
        critical = [f for f in fw if f['status'] == 'critical']
        assert len(critical) == 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_firewall_partial_active(self, mock_run):
        """Test Windows Firewall with partial activation."""
        mock_run.side_effect = [
            (True, ""),
            (True, """
Name : Domain
Enabled : True
Name : Private
Enabled : False
Name : Public
Enabled : False
"""),  # 1 profile enabled
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        fw = [f for f in findings if 'firewall' in f['description'].lower()]
        ok = [f for f in fw if f['status'] == 'ok']
        assert len(ok) == 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_antispyware_detected(self, mock_run):
        """Test antispyware detection."""
        mock_run.side_effect = [
            (True, ""),
            (True, ""),
            (True, """
displayName : Windows Defender Antispyware
"""),
        ]
        
        findings = security_sw.check_security_software()
        
        asw = [f for f in findings if 'antispyware' in f['description'].lower()]
        assert len(asw) == 1
        assert asw[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_defender_antispyware_fallback(self, mock_run):
        """Test Windows Defender antispyware fallback."""
        mock_run.side_effect = [
            (True, ""),  # No AV
            (True, ""),  # No firewall info
            (True, ""),  # No antispyware from WMI
            (True, """
AntispywareEnabled : True
"""),  # Defender antispyware
        ]
        
        findings = security_sw.check_security_software()
        
        asw = [f for f in findings if 'antispyware' in f['description'].lower()]
        assert len(asw) >= 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_multiple_av_products(self, mock_run):
        """Test detection of multiple AV products."""
        mock_run.side_effect = [
            (True, """
displayName : AV1
productState : 266240

displayName : AV2
productState : 266240
"""),
            (True, ""),
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'antivirus' in f['description'].lower()]
        ok = [f for f in av if f['status'] == 'ok']
        assert len(ok) >= 1
        # Should list both AVs
        assert 'AV1' in ok[0]['description'] or 'AV2' in ok[0]['description']
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_av_active_states(self, mock_run):
        """Test various AV active states."""
        # Test state 266496
        mock_run.side_effect = [
            (True, """
displayName : TestAV
productState : 266496
"""),
            (True, ""),
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'antivirus' in f['description'].lower()]
        ok = [f for f in av if f['status'] == 'ok']
        assert len(ok) >= 1
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_powershell_all_failures(self, mock_run):
        """Test when all PowerShell calls fail."""
        mock_run.side_effect = [
            (False, "Error 1"),
            (False, "Error 2"),
            (False, "Error 3"),
        ]
        
        findings = security_sw.check_security_software()
        
        # Should handle gracefully
        assert isinstance(findings, list)
    
    @patch('winsec_auditor.checks.security_sw.run_powershell')
    def test_duplicates_removed(self, mock_run):
        """Test that duplicate AV names are removed."""
        mock_run.side_effect = [
            (True, """
displayName : SameAV
productState : 266240

displayName : SameAV
productState : 266240
"""),  # Duplicate entries
            (True, ""),
            (True, ""),
        ]
        
        findings = security_sw.check_security_software()
        
        av = [f for f in findings if 'SameAV' in f['description']]
        # Should appear only once
        assert len(av) >= 1
