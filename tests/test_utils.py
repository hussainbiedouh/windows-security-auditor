"""Tests for utility functions."""

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from importlib.metadata import version

import pytest

from winsec_auditor import utils
from winsec_auditor.utils import (
    PowerShellResult,
    PowerShellError,
    CommandNotAllowedError,
    InvalidParameterError,
    ScriptNotFoundError,
    _validate_cmdlet,
    _validate_parameter_name,
    _validate_parameter_value,
    _build_command,
    run_powershell_command,
    run_powershell_script,
    is_cmdlet_allowed,
    get_allowed_cmdlets,
)


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
    """Test run_powershell function (deprecated - now enforces security)."""
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_whitelisted_cmdlet_allowed(self, mock_run):
        """Test that whitelisted cmdlets are allowed."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='test output',
            stderr=''
        )
        
        # Get-Service is in the whitelist
        result = utils.run_powershell('Get-Service')
        
        assert result.success is True
        assert result.stdout == 'test output'
    
    def test_non_whitelisted_cmdlet_rejected(self):
        """Test that non-whitelisted cmdlets are rejected."""
        with pytest.raises(PowerShellError) as exc:
            utils.run_powershell('Invoke-MaliciousCmdlet')
        assert 'not allowed' in str(exc.value)
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_timeout_still_works(self, mock_run):
        """Test timeout handling still works for allowed cmdlets."""
        mock_run.side_effect = subprocess.TimeoutExpired('powershell', 30)
        
        with pytest.raises(PowerShellError) as exc:
            utils.run_powershell('Get-Service', timeout=30)
        assert 'timed out' in str(exc.value).lower()


class TestValidateCmdlet:
    """Test _validate_cmdlet function (security: prevents command injection)."""
    
    def test_valid_cmdlet(self):
        """Test validation of valid cmdlet."""
        result = _validate_cmdlet('Get-Service')
        assert result == 'Get-Service'
    
    def test_valid_cmdlet_with_hyphen(self):
        """Test validation of cmdlet with hyphen."""
        result = _validate_cmdlet('Get-NetFirewallProfile')
        assert result == 'Get-NetFirewallProfile'
    
    def test_invalid_cmdlet_not_in_whitelist(self):
        """Test rejection of cmdlet not in whitelist."""
        with pytest.raises(CommandNotAllowedError) as exc:
            _validate_cmdlet('Invoke-MaliciousCmdlet')
        assert 'not in the allowed whitelist' in str(exc.value)
    
    def test_invalid_cmdlet_empty(self):
        """Test rejection of empty cmdlet name."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_cmdlet('')
        assert 'cannot be empty' in str(exc.value)
    
    def test_invalid_cmdlet_whitespace_only(self):
        """Test rejection of whitespace-only cmdlet name."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_cmdlet('   ')
        assert 'cannot be empty' in str(exc.value)
    
    def test_invalid_cmdlet_format_special_chars(self):
        """Test rejection of cmdlet with special characters."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_cmdlet('Get;rm -rf')
        assert 'Invalid cmdlet name format' in str(exc.value)
    
    def test_invalid_cmdlet_starts_with_number(self):
        """Test rejection of cmdlet starting with number."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_cmdlet('123GetService')
        assert 'Invalid cmdlet name format' in str(exc.value)
    
    def test_invalid_cmdlet_not_string(self):
        """Test rejection of non-string cmdlet."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_cmdlet(123)
        assert 'must be a string' in str(exc.value)
    
    def test_cmdlet_whitelist_contains_expected(self):
        """Test that expected cmdlets are in whitelist."""
        allowed = get_allowed_cmdlets()
        assert 'Get-Service' in allowed
        assert 'Get-LocalUser' in allowed
        assert 'Get-NetFirewallProfile' in allowed
        assert 'Get-MpComputerStatus' in allowed
    
    def test_is_cmdlet_allowed_true(self):
        """Test is_cmdlet_allowed returns True for allowed cmdlet."""
        assert is_cmdlet_allowed('Get-Service') is True
    
    def test_is_cmdlet_allowed_false(self):
        """Test is_cmdlet_allowed returns False for disallowed cmdlet."""
        assert is_cmdlet_allowed('Invoke-Shellcode') is False


class TestValidateParameterName:
    """Test _validate_parameter_name function (security: prevents parameter injection)."""
    
    def test_valid_parameter_name(self):
        """Test validation of valid parameter name."""
        result = _validate_parameter_name('Name')
        assert result == 'Name'
    
    def test_valid_parameter_name_with_number(self):
        """Test validation of parameter name with number."""
        result = _validate_parameter_name('Filter1')
        assert result == 'Filter1'
    
    def test_invalid_param_empty(self):
        """Test rejection of empty parameter name."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_name('')
        assert 'cannot be empty' in str(exc.value)
    
    def test_invalid_param_whitespace(self):
        """Test rejection of whitespace-only parameter name."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_name('   ')
        assert 'cannot be empty' in str(exc.value)
    
    def test_invalid_param_special_chars(self):
        """Test rejection of parameter with special characters."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_name('Name;rm')
        assert 'Invalid parameter name format' in str(exc.value)
    
    def test_invalid_param_starts_with_number(self):
        """Test rejection of parameter starting with number."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_name('1Filter')
        assert 'Invalid parameter name format' in str(exc.value)
    
    def test_invalid_param_not_string(self):
        """Test rejection of non-string parameter."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_name(None)
        assert 'must be a string' in str(exc.value)


class TestValidateParameterValue:
    """Test _validate_parameter_value function (security: prevents value injection)."""
    
    def test_valid_string_value(self):
        """Test validation of valid string value."""
        result = _validate_parameter_value('test')
        assert result == 'test'
    
    def test_valid_int_value(self):
        """Test validation of integer value."""
        result = _validate_parameter_value(42)
        assert result == '42'
    
    def test_valid_bool_true(self):
        """Test validation of boolean True."""
        result = _validate_parameter_value(True)
        assert result == '$True'
    
    def test_valid_bool_false(self):
        """Test validation of boolean False."""
        result = _validate_parameter_value(False)
        assert result == '$False'
    
    def test_value_with_spaces_quoted(self):
        """Test that value with spaces gets quoted."""
        result = _validate_parameter_value('hello world')
        assert result == '"hello world"'
    
    def test_invalid_dangerous_char_semicolon(self):
        """Test rejection of value with semicolon."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test;rm -rf')
        assert 'dangerous character' in str(exc.value)
    
    def test_invalid_dangerous_char_pipe(self):
        """Test rejection of value with pipe."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test|cat')
        assert 'dangerous character' in str(exc.value)
    
    def test_invalid_dangerous_char_ampersand(self):
        """Test rejection of value with ampersand."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test&cmd')
        assert 'dangerous character' in str(exc.value)
    
    def test_invalid_dangerous_char_redirect(self):
        """Test rejection of value with redirect."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test > file')
        assert 'dangerous character' in str(exc.value)
    
    def test_invalid_dangerous_char_backtick(self):
        """Test rejection of value with backtick (PowerShell subexpression)."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test`n')
        # Can be caught as either dangerous character or special character
        assert 'dangerous character' in str(exc.value) or 'PowerShell special characters' in str(exc.value)
    
    def test_invalid_dangerous_char_dollar(self):
        """Test rejection of value with dollar (variable expansion)."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test$var')
        # Can be caught as either dangerous character or special character
        assert 'dangerous character' in str(exc.value) or 'PowerShell special characters' in str(exc.value)
    
    def test_invalid_null_byte(self):
        """Test rejection of value with null byte injection."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('test\x00')
        assert 'null byte' in str(exc.value)
    
    def test_invalid_path_traversal(self):
        """Test rejection of path traversal pattern."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value('../../etc/passwd')
        assert 'path traversal pattern' in str(exc.value)
    
    def test_invalid_type(self):
        """Test rejection of invalid type."""
        with pytest.raises(InvalidParameterError) as exc:
            _validate_parameter_value([1, 2, 3])
        assert 'must be string, int, or bool' in str(exc.value)


class TestBuildCommand:
    """Test _build_command function (security: parameter binding)."""
    
    def test_cmdlet_only(self):
        """Test building command without parameters."""
        result = _build_command('Get-Service')
        assert result == 'Get-Service'
    
    def test_with_single_parameter(self):
        """Test building command with single parameter."""
        result = _build_command('Get-Service', {'Name': 'wuauserv'})
        assert result == 'Get-Service -Name wuauserv'
    
    def test_with_multiple_parameters(self):
        """Test building command with multiple parameters."""
        result = _build_command('Get-Service', {'Name': 'wuauserv', 'Status': 'Running'})
        # Order may vary due to dict
        assert 'Get-Service' in result
        assert '-Name wuauserv' in result
        assert '-Status Running' in result
    
    def test_with_quoted_value(self):
        """Test that values with spaces are quoted."""
        result = _build_command('Get-Service', {'Name': 'Windows Update'})
        assert result == 'Get-Service -Name "Windows Update"'
    
    def test_with_bool_parameter(self):
        """Test with boolean parameter."""
        result = _build_command('Test-Path', {'Path': 'C:\\', 'PathType': 'Any'})
        # Verify the cmdlet and parameters are in the result
        assert 'Test-Path' in result
        assert '-Path C:\\' in result
        assert '-PathType Any' in result


class TestRunPowerShellCommand:
    """Test run_powershell_command function (secure cmdlet execution)."""
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_success(self, mock_run):
        """Test successful command execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='output',
            stderr=''
        )
        
        result = run_powershell_command('Get-Service')
        
        assert result.returncode == 0
        assert result.stdout == 'output'
        assert result.success is True
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_failure(self, mock_run):
        """Test failed command execution."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='error'
        )
        
        result = run_powershell_command('Get-Service')
        
        assert result.returncode == 1
        assert result.success is False
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_with_parameters(self, mock_run):
        """Test command with parameters."""
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        run_powershell_command('Get-Service', {'Name': 'wuauserv'})
        
        # Verify command was built correctly
        call_args = mock_run.call_args[0][0]
        assert '-Name wuauserv' in call_args[5]
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_timeout(self, mock_run):
        """Test timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('powershell', 30)
        
        with pytest.raises(PowerShellError) as exc:
            run_powershell_command('Get-Service', timeout=30)
        
        assert 'timed out' in str(exc.value).lower()
    
    def test_invalid_cmdlet_rejected(self):
        """Test that invalid cmdlet is rejected before execution."""
        with pytest.raises(CommandNotAllowedError):
            run_powershell_command('Invoke-Malicious')
    
    def test_invalid_timeout(self):
        """Test that invalid timeout is rejected."""
        with pytest.raises(InvalidParameterError) as exc:
            run_powershell_command('Get-Service', timeout=0)
        assert 'Timeout must be a positive integer' in str(exc.value)
    
    def test_timeout_too_large(self):
        """Test that timeout over 300 is rejected."""
        with pytest.raises(InvalidParameterError) as exc:
            run_powershell_command('Get-Service', timeout=500)
        assert 'Timeout must be a positive integer' in str(exc.value)


class TestRunPowerShellScript:
    """Test run_powershell_script function (secure script execution)."""
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_success(self, mock_run):
        """Test successful script execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='output',
            stderr=''
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write('Write-Host "test"')
            script_path = f.name
        
        try:
            result = run_powershell_script(script_path)
            assert result.returncode == 0
        finally:
            Path(script_path).unlink()
    
    def test_script_not_found(self):
        """Test error when script doesn't exist."""
        with pytest.raises(ScriptNotFoundError):
            run_powershell_script('C:\\nonexistent\\script.ps1')
    
    def test_not_a_file(self):
        """Test error when path is not a file."""
        with pytest.raises(ScriptNotFoundError):
            run_powershell_script('C:\\Windows')
    
    def test_wrong_extension(self):
        """Test error when file doesn't have .ps1 extension."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            script_path = f.name
        
        try:
            with pytest.raises(ScriptNotFoundError):
                run_powershell_script(script_path)
        finally:
            Path(script_path).unlink()
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_with_args(self, mock_run):
        """Test script execution with arguments."""
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write('param($arg1) Write-Host $arg1')
            script_path = f.name
        
        try:
            run_powershell_script(script_path, args=['testarg'])
            
            call_args = mock_run.call_args[0][0]
            assert 'testarg' in call_args
        finally:
            Path(script_path).unlink()
    
    def test_arg_with_dangerous_char(self):
        """Test rejection of dangerous argument."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write('Write-Host $args')
            script_path = f.name
        
        try:
            with pytest.raises(InvalidParameterError):
                run_powershell_script(script_path, args=[';rm -rf'])
        finally:
            Path(script_path).unlink()
    
    @patch('winsec_auditor.utils.subprocess.run')
    def test_timeout(self, mock_run):
        """Test script timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired('powershell', 30)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write('Start-Sleep 60')
            script_path = f.name
        
        try:
            with pytest.raises(PowerShellError) as exc:
                run_powershell_script(script_path, timeout=1)
            assert 'timed out' in str(exc.value).lower()
        finally:
            Path(script_path).unlink()


class TestPowerShellResult:
    """Test PowerShellResult dataclass."""
    
    def test_success_property_true(self):
        """Test success property returns True for returncode 0."""
        result = PowerShellResult(returncode=0, stdout='', stderr='', command='test')
        assert result.success is True
    
    def test_success_property_false(self):
        """Test success property returns False for non-zero returncode."""
        result = PowerShellResult(returncode=1, stdout='', stderr='', command='test')
        assert result.success is False
    
    def test_repr(self):
        """Test string representation."""
        result = PowerShellResult(returncode=0, stdout='', stderr='', command='test')
        assert 'returncode=0' in repr(result)
        assert 'success=True' in repr(result)


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


class TestParsePowerShellListOutput:
    """Test parse_powershell_list_output function."""
    
    def test_single_entry(self):
        """Test parsing a single entry."""
        output = """Name : TestService
Status : Running"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Status'])
        
        assert len(result) == 1
        assert result[0]['Name'] == 'TestService'
        assert result[0]['Status'] == 'Running'
    
    def test_multiple_entries(self):
        """Test parsing multiple entries."""
        output = """Name : Service1
Status : Running

Name : Service2
Status : Stopped"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Status'])
        
        assert len(result) == 2
        assert result[0]['Name'] == 'Service1'
        assert result[0]['Status'] == 'Running'
        assert result[1]['Name'] == 'Service2'
        assert result[1]['Status'] == 'Stopped'
    
    def test_empty_output(self):
        """Test parsing empty output."""
        result = utils.parse_powershell_list_output('', ['Name'])
        assert result == []
    
    def test_whitespace_only(self):
        """Test parsing whitespace-only output."""
        result = utils.parse_powershell_list_output('   \n   \n', ['Name'])
        assert result == []
    
    def test_skip_ps_prompts(self):
        """Test skipping PowerShell prompt lines."""
        output = """PS C:\\> Get-Service
Name : TestService
Status : Running
PS C:\\> _"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Status'])
        
        assert len(result) == 1
        assert result[0]['Name'] == 'TestService'
    
    def test_partial_fields(self):
        """Test parsing with missing fields."""
        output = """Name : TestService
Status : Running
Extra : Value"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Status'])
        
        assert len(result) == 1
        assert result[0]['Name'] == 'TestService'
        assert result[0]['Status'] == 'Running'
        assert 'Extra' not in result[0]


class TestParseUserAccounts:
    """Test parse_user_accounts function."""
    
    def test_parse_users(self):
        """Test parsing user account data."""
        output = """Name : Administrator
Enabled : True
LastLogon : 1/1/2024
SID : S-1-5-21-xxx-500
PrincipalSource : Local

Name : Guest
Enabled : False
LastLogon :
SID : S-1-5-21-xxx-501
PrincipalSource : Local"""
        
        result = utils.parse_user_accounts(output)
        
        assert len(result) == 2
        assert result[0]['Name'] == 'Administrator'
        assert result[0]['Enabled'] == 'True'
        assert result[1]['Name'] == 'Guest'
        assert result[1]['Enabled'] == 'False'


class TestParseServices:
    """Test parse_services function."""
    
    def test_parse_services(self):
        """Test parsing service data."""
        output = """Name : wuauserv
Status : Running
StartType : Automatic
DisplayName : Windows Update

Name : bits
Status : Stopped
StartType : Manual
DisplayName : Background Intelligent Transfer Service"""
        
        result = utils.parse_services(output)
        
        assert len(result) == 2
        assert result[0]['Name'] == 'wuauserv'
        assert result[0]['Status'] == 'Running'
        assert result[1]['Name'] == 'bits'
        assert result[1]['StartType'] == 'Manual'


class TestParseFirewallProfiles:
    """Test parse_firewall_profiles function."""
    
    def test_parse_profiles(self):
        """Test parsing firewall profile data."""
        output = """Name : Domain
Enabled : True

Name : Private
Enabled : True

Name : Public
Enabled : False"""
        
        result = utils.parse_firewall_profiles(output)
        
        assert len(result) == 3
        assert result[0]['Name'] == 'Domain'
        assert result[0]['Enabled'] == 'True'
        assert result[2]['Name'] == 'Public'
        assert result[2]['Enabled'] == 'False'


class TestParseStartupCommands:
    """Test parse_startup_commands function."""
    
    def test_parse_startup(self):
        """Test parsing startup command data."""
        output = """Name : Program1
Command : C:\\Program Files\\App1\\app.exe
Location : HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
User : SYSTEM

Name : Program2
Command : C:\\Users\\User\\AppData\\Roaming\\app2.exe
Location : HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
User : User"""
        
        result = utils.parse_startup_commands(output)
        
        assert len(result) == 2
        assert result[0]['Name'] == 'Program1'
        assert result[0]['User'] == 'SYSTEM'
        assert result[1]['Name'] == 'Program2'
        assert result[1]['Location'] == 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'


class TestParseAVProducts:
    """Test parse_av_products function."""
    
    def test_parse_av(self):
        """Test parsing antivirus product data."""
        output = """displayName : Windows Defender
productState : 266240

displayName : Third Party AV
productState : 393472"""
        
        result = utils.parse_av_products(output)
        
        assert len(result) == 2
        assert result[0]['displayName'] == 'Windows Defender'
        assert result[0]['productState'] == '266240'
        assert result[1]['displayName'] == 'Third Party AV'
        assert result[1]['productState'] == '393472'


class TestParseLocalGroupMembers:
    """Test parse_local_group_members function."""
    
    def test_parse_members(self):
        """Test parsing local group member data."""
        output = """Name : DOMAIN\\AdminUser
SID : S-1-5-21-xxx-1000
PrincipalSource : Domain

Name : DESKTOP\\LocalAdmin
SID : S-1-5-21-xxx-1001
PrincipalSource : LocalMachine"""
        
        result = utils.parse_local_group_members(output)
        
        assert len(result) == 2
        assert result[0]['Name'] == 'DOMAIN\\AdminUser'
        assert result[0]['PrincipalSource'] == 'Domain'
        assert result[1]['Name'] == 'DESKTOP\\LocalAdmin'
        assert result[1]['PrincipalSource'] == 'LocalMachine'
    
    def test_parse_empty(self):
        """Test parsing empty group members output."""
        result = utils.parse_local_group_members('')
        assert result == []
    
    def test_parse_single_member(self):
        """Test parsing single member."""
        output = """Name : Administrator
SID : S-1-5-21-xxx-500
PrincipalSource : Local"""
        
        result = utils.parse_local_group_members(output)
        
        assert len(result) == 1
        assert result[0]['Name'] == 'Administrator'


class TestParseEventCounts:
    """Test parse_event_counts function."""
    
    def test_parse_counts(self):
        """Test parsing event count data."""
        output = """Name : Error
Count : 15

Name : Warning
Count : 30

Name : Information
Count : 100"""
        
        result = utils.parse_event_counts(output)
        
        assert len(result) == 3
        assert result[0]['Name'] == 'Error'
        assert result[0]['Count'] == '15'
        assert result[1]['Name'] == 'Warning'
        assert result[2]['Name'] == 'Information'
    
    def test_parse_empty(self):
        """Test parsing empty event counts output."""
        result = utils.parse_event_counts('')
        assert result == []


class TestEdgeCasesAndIntegration:
    """Test edge cases and integration scenarios."""
    
    def test_parse_with_colons_in_values(self):
        """Test parsing values that contain colons."""
        output = """Name : Test:Value
Status : Running"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Status'])
        
        assert len(result) == 1
        # Value after first colon only
        assert result[0]['Name'] == 'Test:Value'
    
    def test_parse_malformed_output(self):
        """Test handling of malformed output."""
        output = """Not a valid format
Just some random text
No colons here"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Status'])
        
        # Should return empty list or handle gracefully
        assert isinstance(result, list)
    
    def test_parse_single_field(self):
        """Test parsing with single field."""
        output = """Name : SingleEntry"""
        
        result = utils.parse_powershell_list_output(output, ['Name'])
        
        assert len(result) == 1
        assert result[0]['Name'] == 'SingleEntry'
    
    def test_parse_with_empty_values(self):
        """Test parsing entries with empty values."""
        output = """Name : Test
Value :

Name : Test2
Value : Something"""
        
        result = utils.parse_powershell_list_output(output, ['Name', 'Value'])
        
        assert len(result) == 2
        assert result[0]['Value'] == ''
        assert result[1]['Value'] == 'Something'
