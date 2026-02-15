"""Tests for network check module."""

from unittest.mock import patch

import pytest

from winsec_auditor.checks import network


class TestNetworkChecks:
    """Test network security checks."""
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_listening_ports_detection(self, mock_run):
        """Test listening ports detection."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
  TCP    192.168.1.100:12345    192.168.1.1:443        ESTABLISHED
""")
        
        findings = network.check_network()
        
        listening = [f for f in findings if 'listening' in f['description'].lower()]
        assert len(listening) >= 1
        assert '3' in listening[0]['description']  # 3 listening ports
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_no_risky_ports(self, mock_run):
        """Test when no risky ports are detected."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
  TCP    192.168.1.100:12345    192.168.1.1:443        ESTABLISHED
""")
        
        findings = network.check_network()
        
        ok = [f for f in findings if 'no common risky' in f['description'].lower()]
        assert len(ok) == 1
        assert ok[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_risky_port_telnet(self, mock_run):
        """Test detection of risky port 23 (Telnet)."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:23             0.0.0.0:0              LISTENING
  TCP    192.168.1.100:12345    192.168.1.1:443        ESTABLISHED
""")
        
        findings = network.check_network()
        
        risky = [f for f in findings if '23' in f['description']]
        assert len(risky) == 1
        assert risky[0]['status'] == 'warning'
        assert 'telnet' in risky[0]['description'].lower()
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_risky_port_rdp(self, mock_run):
        """Test detection of risky port 3389 (RDP)."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
""")
        
        findings = network.check_network()
        
        risky = [f for f in findings if '3389' in f['description']]
        assert len(risky) == 1
        assert risky[0]['status'] == 'warning'
        assert 'rdp' in risky[0]['description'].lower()
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_risky_port_smb(self, mock_run):
        """Test detection of risky port 445 (SMB)."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
""")
        
        findings = network.check_network()
        
        risky = [f for f in findings if '445' in f['description']]
        assert len(risky) == 1
        assert risky[0]['status'] == 'warning'
        assert 'smb' in risky[0]['description'].lower()
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_multiple_risky_ports_limited(self, mock_run):
        """Test that only first 5 risky ports are reported."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:20             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:23             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:25             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:110            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:139            0.0.0.0:0              LISTENING
""")
        
        findings = network.check_network()
        
        risky = [f for f in findings if 'risky port' in f['description'].lower()]
        assert len(risky) <= 5  # Limited to 5
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_established_connections(self, mock_run):
        """Test established connections detection."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    192.168.1.100:12345    192.168.1.1:443        ESTABLISHED
  TCP    192.168.1.100:12346    8.8.8.8:53             ESTABLISHED
  TCP    192.168.1.100:12347    1.1.1.1:443            ESTABLISHED
""")
        
        findings = network.check_network()
        
        established = [f for f in findings if 'active connections' in f['description'].lower()]
        assert len(established) == 1
        assert '3' in established[0]['description']
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_high_connections_warning(self, mock_run):
        """Test warning for unusually high connection count."""
        connections = "\n".join([
            f"  TCP    192.168.1.100:{50000+i}    192.168.1.1:443        ESTABLISHED"
            for i in range(150)  # 150 connections
        ])
        mock_run.return_value = (True, f"""
  Proto  Local Address          Foreign Address        State
{connections}
""")
        
        findings = network.check_network()
        
        high = [f for f in findings if 'unusually high' in f['description'].lower()]
        assert len(high) == 1
        assert high[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_netstat_failure(self, mock_run):
        """Test handling of netstat command failure."""
        mock_run.return_value = (False, "Command failed")
        
        findings = network.check_network()
        
        warning = [f for f in findings if f['status'] == 'warning']
        assert len(warning) >= 1
        assert 'could not' in warning[0]['description'].lower()
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_empty_netstat_output(self, mock_run):
        """Test handling of empty netstat output."""
        mock_run.return_value = (True, "")
        
        findings = network.check_network()
        
        # Should handle gracefully
        assert len(findings) >= 1
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_ipv6_listening_ports(self, mock_run):
        """Test detection of IPv6 listening ports."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    [::]:80                [::]:0                 LISTENING
  TCP    [::]:443               [::]:0                 LISTENING
""")
        
        findings = network.check_network()
        
        listening = [f for f in findings if 'listening' in f['description'].lower()]
        # Should detect IPv6 ports too
        assert len(listening) >= 1
    
    @patch('winsec_auditor.checks.network.run_command')
    def test_risky_port_details(self, mock_run):
        """Test that risky port findings have correct details."""
        mock_run.return_value = (True, """
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:23             0.0.0.0:0              LISTENING
""")
        
        findings = network.check_network()
        
        risky = [f for f in findings if 'risky port' in f['description'].lower()][0]
        assert risky['details'] is not None
        assert 'port' in risky['details']
        assert 'description' in risky['details']
        assert risky['details']['port'] == 23
