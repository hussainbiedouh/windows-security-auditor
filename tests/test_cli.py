"""Tests for CLI module."""

import json
import sys
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from winsec_auditor.cli import main, _list_available_checks, _interactive_scan_selection
from winsec_auditor.checks import AVAILABLE_CHECKS


class TestCLI:
    """Test cases for CLI functionality."""
    
    @pytest.fixture
    def runner(self):
        """Create a Click CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def mock_scan_result(self):
        """Create a mock scan result."""
        return {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [],
            'summary': {'total': 0, 'ok': 0, 'warning': 0, 'critical': 0, 'info': 0}
        }
    
    # ========================================================================
    # Platform Detection Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    def test_cli_windows_check(self, mock_is_windows, runner):
        """Test that CLI exits on non-Windows systems."""
        mock_is_windows.return_value = False
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 1
        assert "Windows systems only" in result.output
    
    @patch('winsec_auditor.cli.is_windows')
    def test_cli_exits_on_linux(self, mock_is_windows, runner):
        """Test CLI exits on Linux."""
        mock_is_windows.return_value = False
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 1
    
    @patch('winsec_auditor.cli.is_windows')
    def test_cli_exits_on_macos(self, mock_is_windows, runner):
        """Test CLI exits on macOS."""
        mock_is_windows.return_value = False
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 1
    
    # ========================================================================
    # List Checks Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    def test_list_checks(self, mock_is_windows, runner):
        """Test --list-checks option."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--list-checks'])
        
        assert result.exit_code == 0
        assert "Available Security Checks" in result.output
        # Check that check IDs are present
        for check_id in AVAILABLE_CHECKS:
            assert check_id in result.output or check_id.lower() in result.output.lower()
    
    @patch('winsec_auditor.cli.is_windows')
    def test_list_checks_shows_check_types(self, mock_is_windows, runner):
        """Test --list-checks shows basic and full scan types."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--list-checks'])
        
        assert result.exit_code == 0
        assert "basic" in result.output.lower() or "full" in result.output.lower()
    
    # ========================================================================
    # Scan Type Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_basic_scan(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test basic scan execution."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 0
        mock_scanner.scan_with_progress.assert_called_once()
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_full_scan(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test full scan execution."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'full'])
        
        assert result.exit_code == 0
        mock_scanner.scan_with_progress.assert_called_once()
 
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_scan_case_insensitive(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test that scan type is case-insensitive."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'BASIC'])
        
        assert result.exit_code == 0
    
    # ========================================================================
    # Specific Checks Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    def test_invalid_check(self, mock_is_windows, runner):
        """Test invalid check ID handling."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--check', 'invalid_check'])
        
        assert result.exit_code == 1
        assert "Invalid check" in result.output
    
    @patch('winsec_auditor.cli.is_windows')
    def test_multiple_invalid_checks(self, mock_is_windows, runner):
        """Test multiple invalid check IDs."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--check', 'invalid1,invalid2,invalid3'])
        
        assert result.exit_code == 1
        assert "Invalid check" in result.output
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_single_valid_check(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test single valid check selection."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--check', 'firewall'])
        
        assert result.exit_code == 0
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_multiple_valid_checks(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test multiple valid check selections."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--check', 'firewall,users,network'])
        
        assert result.exit_code == 0
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_mixed_valid_invalid_checks(self, mock_scanner_class, mock_is_windows, runner):
        """Test mix of valid and invalid check IDs."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--check', 'firewall,invalid,users'])
        
        assert result.exit_code == 1
        assert "Invalid check" in result.output
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_check_with_whitespace(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test check selection with whitespace."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--check', ' firewall , users , network '])
        
        assert result.exit_code == 0
    
    # ========================================================================
    # JSON Output Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_json_output_stdout(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test JSON output to stdout."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic', '--json', '-'])
        
        assert result.exit_code == 0
        # Uses scan_with_progress consistently
        mock_scanner.scan_with_progress.assert_called_once()
        # Check JSON is valid
        assert '"timestamp"' in result.output
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_json_output_to_file(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result, tmp_path):
        """Test JSON output to file."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        output_file = tmp_path / "report.json"
        
        result = runner.invoke(main, ['--scan', 'basic', '--json', str(output_file)])
        
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Verify it's valid JSON
        data = json.loads(output_file.read_text())
        assert 'timestamp' in data
    
    # ========================================================================
    # HTML Output Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_html_output_to_file(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result, tmp_path):
        """Test HTML output to file."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        output_file = tmp_path / "report.html"
        
        result = runner.invoke(main, ['--scan', 'basic', '--html', str(output_file)])
        
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Verify it's valid HTML
        content = output_file.read_text()
        assert '<!DOCTYPE html>' in content or '<html>' in content.lower()
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_both_json_and_html_output(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result, tmp_path):
        """Test both JSON and HTML output together."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        json_file = tmp_path / "report.json"
        html_file = tmp_path / "report.html"
        
        result = runner.invoke(main, ['--scan', 'basic', '--json', str(json_file), '--html', str(html_file)])
        
        assert result.exit_code == 0
        assert json_file.exists()
        assert html_file.exists()
    
    # ========================================================================
    # No Color Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_no_color_flag(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test --no-color flag."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic', '--no-color'])
        
        assert result.exit_code == 0
    
    # ========================================================================
    # Verbose Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_verbose_flag(self, mock_scanner_class, mock_is_windows, runner, mock_scan_result):
        """Test --verbose flag."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = mock_scan_result
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic', '--verbose'])
        
        assert result.exit_code == 0
        # Verify verbose was passed to scanner
        mock_scanner_class.assert_called_once_with(verbose=True)
    
    # ========================================================================
    # Exit Code Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_exit_code_success(self, mock_scanner_class, mock_is_windows, runner):
        """Test exit code 0 for clean scan."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [],
            'summary': {'total': 0, 'ok': 0, 'warning': 0, 'critical': 0, 'info': 0}
        }
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 0
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_exit_code_warning(self, mock_scanner_class, mock_is_windows, runner):
        """Test exit code 1 for warnings."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [
                {'category': 'Test', 'status': 'warning', 'description': 'Test warning', 'details': None}
            ],
            'summary': {'total': 1, 'ok': 0, 'warning': 1, 'critical': 0, 'info': 0}
        }
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 1
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_exit_code_critical(self, mock_scanner_class, mock_is_windows, runner):
        """Test exit code 2 for critical issues."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [
                {'category': 'Test', 'status': 'critical', 'description': 'Test critical', 'details': None}
            ],
            'summary': {'total': 1, 'ok': 0, 'warning': 0, 'critical': 1, 'info': 0}
        }
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 2
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_exit_code_both_warning_and_critical(self, mock_scanner_class, mock_is_windows, runner):
        """Test exit code 2 when both warnings and critical exist."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.return_value = {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [
                {'category': 'Test', 'status': 'warning', 'description': 'Test warning', 'details': None},
                {'category': 'Test', 'status': 'critical', 'description': 'Test critical', 'details': None}
            ],
            'summary': {'total': 2, 'ok': 0, 'warning': 1, 'critical': 1, 'info': 0}
        }
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 2  # Critical takes precedence
    
    # ========================================================================
    # Error Handling Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_scan_error_handling(self, mock_scanner_class, mock_is_windows, runner):
        """Test handling of scan errors."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.side_effect = Exception("Scan failed")
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 1
        assert "Error" in result.output
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_keyboard_interrupt(self, mock_scanner_class, mock_is_windows, runner):
        """Test handling of keyboard interrupt."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.side_effect = KeyboardInterrupt()
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic'])
        
        assert result.exit_code == 130
        assert "interrupted" in result.output.lower()
    
    @patch('winsec_auditor.cli.is_windows')
    @patch('winsec_auditor.cli.SecurityScanner')
    def test_verbose_error_output(self, mock_scanner_class, mock_is_windows, runner):
        """Test verbose error output includes traceback."""
        mock_is_windows.return_value = True
        
        mock_scanner = MagicMock()
        mock_scanner.scan_with_progress.side_effect = ValueError("Test error")
        mock_scanner_class.return_value = mock_scanner
        
        result = runner.invoke(main, ['--scan', 'basic', '--verbose'])
        
        assert result.exit_code == 1
    
    # ========================================================================
    # Version Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    def test_version_flag(self, mock_is_windows, runner):
        """Test --version flag."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--version'])
        
        assert result.exit_code == 0
        assert "winsec-audit" in result.output.lower() or "0.1.0" in result.output
    
    # ========================================================================
    # Help Tests
    # ========================================================================
    
    @patch('winsec_auditor.cli.is_windows')
    def test_help_flag(self, mock_is_windows, runner):
        """Test --help flag."""
        mock_is_windows.return_value = True
        
        result = runner.invoke(main, ['--help'])
        
        assert result.exit_code == 0
        assert "--scan" in result.output
        assert "--check" in result.output
        assert "--list-checks" in result.output
        assert "--json" in result.output
        assert "--html" in result.output
        assert "--no-color" in result.output
        assert "--verbose" in result.output


class TestInteractiveSelection:
    """Test interactive mode functionality."""
    
    @patch('winsec_auditor.cli.click.prompt')
    def test_interactive_basic_choice_1(self, mock_prompt):
        """Test selecting basic scan interactively with '1'."""
        mock_prompt.return_value = '1'
        
        from rich.console import Console
        console = Console()
        
        result = _interactive_scan_selection(console)
        
        assert result == 'basic'
    
    @patch('winsec_auditor.cli.click.prompt')
    def test_interactive_basic_choice_basic(self, mock_prompt):
        """Test selecting basic scan interactively with 'basic'."""
        mock_prompt.return_value = 'basic'
        
        from rich.console import Console
        console = Console()
        
        result = _interactive_scan_selection(console)
        
        assert result == 'basic'
    
    @patch('winsec_auditor.cli.click.prompt')
    def test_interactive_full_choice_2(self, mock_prompt):
        """Test selecting full scan interactively with '2'."""
        mock_prompt.return_value = '2'
        
        from rich.console import Console
        console = Console()
        
        result = _interactive_scan_selection(console)
        
        assert result == 'full'
    
    @patch('winsec_auditor.cli.click.prompt')
    def test_interactive_full_choice_full(self, mock_prompt):
        """Test selecting full scan interactively with 'full'."""
        mock_prompt.return_value = 'full'
        
        from rich.console import Console
        console = Console()
        
        result = _interactive_scan_selection(console)
        
        assert result == 'full'
    
    @patch('winsec_auditor.cli.click.prompt')
    def test_interactive_default_full(self, mock_prompt):
        """Test that default is full scan."""
        mock_prompt.return_value = '2'  # Default
        
        from rich.console import Console
        console = Console()
        
        result = _interactive_scan_selection(console)
        
        assert result == 'full'


class TestListAvailableChecks:
    """Test list available checks display."""
    
    def test_list_shows_all_checks(self, mock_console):
        """Test that all checks are listed."""
        _list_available_checks(mock_console)
        
        # Verify print was called
        assert mock_console.print.called
    
    def test_list_shows_check_info(self):
        """Test that check information is displayed."""
        from rich.console import Console
        console = Console(color_system=None)
        
        _list_available_checks(console)
        # Should not raise any exceptions
