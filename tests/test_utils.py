"""Tests for utility functions."""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from winsec_auditor import utils


class TestIsWindows:
    """Test is_windows function."""
    
    @patch('winsec_auditor.utils.platform.system')
    def test_is_windows_true(self, mock_system):
        """Test detection of Windows."""
        mock_system.return_value = 'Windows'
        assert utils.is_windows() is True
    
    @patch('winsec_auditor.utils.platform.system')
    def test_is_windows_false_linux(self, mock_system):
        """Test detection of Linux."""
        mock_system.return_value = 'Linux'
        assert utils.is_windows() is False
    
    @patch('winsec_auditor.utils.platform.system')
    def test_is_windows_false_darwin(self, mock_system):
        """Test detection of macOS."""
        mock_system.return_value = 'Darwin'
        assert utils.is_windows() is False
    
    @patch('winsec_auditor.utils.platform.system')
    def test_is_windows_case_sensitive(self, mock_system):
        """Test that Windows detection is case sensitive."""
        mock_system.return_value = 'windows'  # lowercase
        assert utils.is_windows() is False
        
        mock_system.return_value = 'WINDOWS'  # uppercase
        assert utils.is_windows() is False


class TestRunPowerShell:
    """Test run_powershell function."""
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_success(self, mock_run):
        """Test successful PowerShell execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='test output',
            stderr=''
        )
        
        success, output = utils.run_powershell('Get-Date')
        
        assert success is True
        assert output == 'test output'
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_failure(self, mock_run):
        """Test failed PowerShell execution."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='error'
        )
        
        success, output = utils.run_powershell('Invalid-Command')
        
        assert success is False
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_timeout(self, mock_run):
        """Test PowerShell timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('powershell', 30)
        
        success, output = utils.run_powershell('Slow-Command', timeout=30)
        
        assert success is False
        assert 'timed out' in output.lower()
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_exception(self, mock_run):
        """Test PowerShell exception handling."""
        mock_run.side_effect = Exception("PowerShell not found")
        
        success, output = utils.run_powershell('Command')
        
        assert success is False
        assert 'powershell not found' in output.lower()
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_custom_timeout(self, mock_run):
        """Test custom timeout value."""
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        utils.run_powershell('Command', timeout=60)
        
        # Verify timeout was passed
        assert mock_run.call_args[1]['timeout'] == 60
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_command_passed_correctly(self, mock_run):
        """Test that command is passed correctly."""
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        utils.run_powershell('Get-Date')
        
        args = mock_run.call_args[0][0]
        assert args[0] == 'powershell'
        assert args[1] == '-Command'
        assert args[2] == 'Get-Date'


class TestRunCommand:
    """Test run_command function."""
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_success(self, mock_run):
        """Test successful command execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='test output',
            stderr=''
        )
        
        success, output = utils.run_command(['netstat', '-an'])
        
        assert success is True
        assert output == 'test output'
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_failure(self, mock_run):
        """Test failed command execution."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='error'
        )
        
        success, output = utils.run_command(['invalid', 'command'])
        
        assert success is False
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_timeout(self, mock_run):
        """Test command timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('netstat', 10)
        
        success, output = utils.run_command(['netstat', '-an'], timeout=10)
        
        assert success is False
        assert 'timed out' in output.lower()
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_exception(self, mock_run):
        """Test command exception handling."""
        mock_run.side_effect = FileNotFoundError("Command not found")
        
        success, output = utils.run_command(['missing', 'command'])
        
        assert success is False
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_args_passed_correctly(self, mock_run):
        """Test that args are passed correctly."""
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        utils.run_command(['netstat', '-an'])
        
        args = mock_run.call_args[0][0]
        assert args == ['netstat', '-an']
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_capture_output(self, mock_run):
        """Test that output is captured."""
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        utils.run_command(['echo', 'test'])
        
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['capture_output'] is True
        assert call_kwargs['text'] is True


class TestGetStatusColor:
    """Test get_status_color function."""
    
    def test_info(self):
        """Test info status color."""
        assert utils.get_status_color('info') == 'blue'
    
    def test_ok(self):
        """Test ok status color."""
        assert utils.get_status_color('ok') == 'green'
    
    def test_warning(self):
        """Test warning status color."""
        assert utils.get_status_color('warning') == 'yellow'
    
    def test_critical(self):
        """Test critical status color."""
        assert utils.get_status_color('critical') == 'red'
    
    def test_error(self):
        """Test error status color."""
        assert utils.get_status_color('error') == 'red'
    
    def test_invalid(self):
        """Test invalid status color."""
        assert utils.get_status_color('invalid') == 'white'
    
    def test_empty(self):
        """Test empty status color."""
        assert utils.get_status_color('') == 'white'


class TestGetStatusIcon:
    """Test get_status_icon function."""
    
    def test_info(self):
        """Test info status icon."""
        icon = utils.get_status_icon('info')
        assert icon is not None
        assert len(icon) > 0
    
    def test_ok(self):
        """Test ok status icon."""
        icon = utils.get_status_icon('ok')
        assert icon is not None
        assert len(icon) > 0
    
    def test_warning(self):
        """Test warning status icon."""
        icon = utils.get_status_icon('warning')
        assert icon is not None
        assert len(icon) > 0
    
    def test_critical(self):
        """Test critical status icon."""
        icon = utils.get_status_icon('critical')
        assert icon is not None
        assert len(icon) > 0
    
    def test_error(self):
        """Test error status icon."""
        icon = utils.get_status_icon('error')
        assert icon is not None
        assert len(icon) > 0
    
    def test_invalid(self):
        """Test invalid status icon."""
        icon = utils.get_status_icon('invalid')
        assert icon is not None
        assert len(icon) > 0
    
    def test_empty(self):
        """Test empty status icon."""
        icon = utils.get_status_icon('')
        assert icon is not None
        assert len(icon) > 0
    
    def test_all_statuses_different(self):
        """Test that all status icons are different."""
        icons = {
            'info': utils.get_status_icon('info'),
            'ok': utils.get_status_icon('ok'),
            'warning': utils.get_status_icon('warning'),
            'critical': utils.get_status_icon('critical'),
            'error': utils.get_status_icon('error'),
        }
        
        # All should be unique
        assert len(set(icons.values())) == len(icons)
