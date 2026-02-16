"""Integration tests for end-to-end scenarios."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from winsec_auditor.scanner import SecurityScanner
from winsec_auditor.report import ReportGenerator
from winsec_auditor.config import Config


class TestFullScanIntegration:
    """Integration tests for full scan workflow."""
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_full_scan_with_all_checks(self, mock_get_checks, mock_get_func):
        """Test full scan runs all checks."""
        mock_get_checks.return_value = ['system', 'firewall', 'users', 'services', 'network']
        
        # Create varied results
        def create_check(check_name):
            mock = MagicMock()
            if check_name == 'system':
                mock.return_value = [
                    {'category': 'System', 'status': 'ok', 'description': 'System OK', 'details': None}
                ]
            elif check_name == 'firewall':
                mock.return_value = [
                    {'category': 'Firewall', 'status': 'ok', 'description': 'Firewall enabled', 'details': None}
                ]
            else:
                mock.return_value = []
            return mock
        
        mock_get_func.side_effect = lambda x: create_check(x)
        
        scanner = SecurityScanner()
        result = scanner.scan('full')
        
        assert result['scan_type'] == 'full'
        assert result['summary']['total'] >= 2
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_scan_handles_partial_failures(self, mock_get_func):
        """Test scan handles partial failures gracefully."""
        def create_check(check_name):
            mock = MagicMock()
            if check_name == 'system':
                mock.return_value = [
                    {'category': 'System', 'status': 'ok', 'description': 'OK', 'details': None}
                ]
            elif check_name == 'firewall':
                mock.side_effect = Exception("Simulated failure")
            return mock
        
        mock_get_func.side_effect = lambda x: create_check(x)
        
        scanner = SecurityScanner()
        result = scanner.scan('custom', specific_checks=['system', 'firewall'])
        
        # Should have both success and error
        assert result['summary']['total'] == 2
        assert result['summary']['ok'] == 1
        assert result['summary']['error'] == 1


class TestConfigIntegration:
    """Integration tests for configuration system."""
    
    def test_config_from_env_priority(self):
        """Test that environment variables are used when set."""
        with patch.dict('os.environ', {'WSA_MAX_AUTORUN': '100'}):
            cfg = Config.from_env()
            assert cfg.max_autorun_entries == 100
    
    def test_config_from_file(self):
        """Test loading config from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'max_autorun_entries': 25}, f)
            config_file = f.name
        
        try:
            cfg = Config.from_file(config_file)
            # Should use file value
            assert cfg.max_autorun_entries == 25
            # Other values should be defaults
            assert cfg.max_event_log_entries == 100
        finally:
            Path(config_file).unlink()
    
    def test_config_priority_file_over_defaults(self):
        """Test that file config overrides defaults."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'max_autorun_entries': 25}, f)
            config_file = f.name
        
        try:
            cfg = Config.from_file(config_file)
            # Should use file value
            assert cfg.max_autorun_entries == 25
            # Other values should be defaults
            assert cfg.max_event_log_entries == 100
        finally:
            Path(config_file).unlink()
    
    def test_config_validation_enforced(self):
        """Test that config validates detail levels."""
        cfg = Config()
        
        # Use validate_detail_level method
        assert cfg.validate_detail_level('minimal') == 'minimal'
        assert cfg.validate_detail_level('standard') == 'standard'
        assert cfg.validate_detail_level('full') == 'full'
        
        # Case insensitive
        assert cfg.validate_detail_level('MINIMAL') == 'minimal'
        assert cfg.validate_detail_level('Standard') == 'standard'
        
        # Invalid should raise
        with pytest.raises(ValueError):
            cfg.validate_detail_level('invalid')


class TestReportIntegration:
    """Integration tests for report generation."""
    
    def test_json_to_html_roundtrip(self):
        """Test that JSON and HTML reports are consistent."""
        scan_result = {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [
                {'category': 'Test', 'status': 'ok', 'description': 'OK', 'details': None},
                {'category': 'Test', 'status': 'warning', 'description': 'Warning', 'details': None},
            ],
            'summary': {'total': 2, 'ok': 1, 'warning': 1, 'critical': 0, 'info': 0, 'error': 0}
        }
        
        from rich.console import Console
        console = Console(color_system=None, force_terminal=False)
        gen = ReportGenerator(console)
        
        json_str = gen.generate_json_report(scan_result)
        html_str = gen.generate_html_report(scan_result)
        
        # Both should contain the data
        assert '2024-01-01' in json_str
        assert 'basic' in json_str
        # HTML uses "Basic" (title case)
        assert 'Basic' in html_str
        
        # Summary counts should match
        assert '"total": 2' in json_str
        assert '2' in html_str  # Total count in HTML
    
    @patch('winsec_auditor.report.open', create=True)
    def test_json_save_and_load(self, mock_open):
        """Test saving JSON report and loading it back."""
        scan_result = {
            'timestamp': '2024-01-01T00:00:00',
            'scan_type': 'basic',
            'findings': [
                {'category': 'Test', 'status': 'ok', 'description': 'Test', 'details': None}
            ],
            'summary': {'total': 1, 'ok': 1, 'warning': 0, 'critical': 0, 'info': 0, 'error': 0}
        }
        
        from rich.console import Console
        console = Console(color_system=None, force_terminal=False)
        gen = ReportGenerator(console)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            gen.save_json_report(scan_result, filepath)
            
            # Verify the file contains valid JSON
            with open(filepath, 'r') as f:
                loaded = json.load(f)
            
            assert loaded['timestamp'] == '2024-01-01T00:00:00'
            assert len(loaded['findings']) == 1
        finally:
            Path(filepath).unlink()


class TestSecurityValidationIntegration:
    """Integration tests for security validation."""
    
    def test_cmdlet_whitelist_enforced_integration(self):
        """Test that whitelist is enforced in real usage."""
        from winsec_auditor.utils import run_powershell_command
        
        # Should work with whitelisted cmdlet
        with patch('winsec_auditor.utils.subprocess.run') as mock:
            mock.return_value = MagicMock(returncode=0, stdout='test', stderr='')
            result = run_powershell_command('Get-Service')
            assert result.success is True
        
        # Should fail with non-whitelisted cmdlet
        with pytest.raises(Exception):  # CommandNotAllowedError
            run_powershell_command('Invoke-Mimikatz')
    
    def test_parameter_injection_blocked(self):
        """Test that parameter injection is blocked."""
        from winsec_auditor.utils import run_powershell_command
        
        # Try to inject command via parameter
        with pytest.raises(Exception):  # InvalidParameterError
            run_powershell_command('Get-Service', {'Name': 'test;rm -rf'})
    
    def test_path_traversal_blocked(self):
        """Test that path traversal is blocked."""
        from winsec_auditor.utils import _validate_parameter_value
        
        with pytest.raises(Exception):  # InvalidParameterError
            _validate_parameter_value('../../../etc/passwd')


class TestEdgeCases:
    """Edge case tests."""
    
    def test_scanner_empty_scan_type(self):
        """Test scanner with unknown scan type."""
        scanner = SecurityScanner()
        
        with patch('winsec_auditor.scanner.get_checks_for_scan_type') as mock:
            mock.return_value = []
            result = scanner.scan('unknown')
            
            # Should return empty results
            assert result['summary']['total'] == 0
    
    def test_scanner_with_progress_no_checks(self):
        """Test scan_with_progress with no checks to run."""
        scanner = SecurityScanner()
        
        with patch('winsec_auditor.scanner.get_checks_for_scan_type') as mock:
            mock.return_value = []
            result = scanner.scan_with_progress('basic')
            
            assert result['summary']['total'] == 0
    
    def test_report_with_null_details(self):
        """Test report handles null details in findings."""
        from rich.console import Console
        console = Console(color_system=None, force_terminal=False)
        gen = ReportGenerator(console)
        
        result = {
            'timestamp': '2024-01-01',
            'scan_type': 'basic',
            'findings': [
                {'category': 'Test', 'status': 'ok', 'description': 'OK', 'details': None}
            ],
            'summary': {'total': 1, 'ok': 1, 'warning': 0, 'critical': 0, 'info': 0, 'error': 0}
        }
        
        # Should not raise
        json_str = gen.generate_json_report(result)
        html_str = gen.generate_html_report(result)
        
        assert json_str is not None
        assert html_str is not None
    
    def test_config_invalid_env_value_ignored(self):
        """Test that invalid env values are ignored and defaults used."""
        with patch.dict('os.environ', {'WSA_MAX_AUTORUN': 'not_a_number'}):
            cfg = Config.from_env()
            # Should use default instead of failing
            assert cfg.max_autorun_entries == 50
