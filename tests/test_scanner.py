"""Tests for scanner module."""

from unittest.mock import patch, MagicMock

import pytest
from rich.console import Console

from winsec_auditor.scanner import SecurityScanner


class TestSecurityScanner:
    """Test cases for SecurityScanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance."""
        return SecurityScanner()
    
    @pytest.fixture
    def verbose_scanner(self):
        """Create a verbose scanner instance."""
        return SecurityScanner(verbose=True)
    
    # ========================================================================
    # Initialization Tests
    # ========================================================================
    
    def test_scanner_init_default(self, scanner):
        """Test scanner initialization with default parameters."""
        assert scanner.verbose is False
    
    def test_scanner_init_verbose(self, verbose_scanner):
        """Test scanner initialization with verbose=True."""
        assert verbose_scanner.verbose is True
    
    # ========================================================================
    # Basic Scan Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_basic_scan(self, mock_get_checks, mock_get_func, scanner):
        """Test basic scan execution."""
        mock_get_checks.return_value = ['system', 'updates', 'firewall']
        
        mock_check = MagicMock()
        mock_check.return_value = [
            {'category': 'Test', 'status': 'ok', 'description': 'Test finding', 'details': None}
        ]
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('basic')
        
        assert result['scan_type'] == 'basic'
        assert 'timestamp' in result
        assert 'findings' in result
        assert 'summary' in result
        assert result['summary']['total'] == 3
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_full_scan(self, mock_get_checks, mock_get_func, scanner):
        """Test full scan execution."""
        mock_get_checks.return_value = ['system', 'updates', 'firewall', 'autorun', 'users']
        
        mock_check = MagicMock()
        mock_check.return_value = []
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('full')
        
        assert result['scan_type'] == 'full'
        assert result['summary']['total'] == 0
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_empty_scan_type(self, mock_get_checks, mock_get_func, scanner):
        """Test scan with empty check list."""
        mock_get_checks.return_value = []
        
        result = scanner.scan('basic')
        
        assert result['scan_type'] == 'basic'
        assert result['summary']['total'] == 0
    
    # ========================================================================
    # Specific Checks Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_specific_checks(self, mock_get_func, scanner):
        """Test running specific checks."""
        mock_check = MagicMock()
        mock_check.return_value = [
            {'category': 'Test', 'status': 'ok', 'description': 'Test', 'details': None}
        ]
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('custom', specific_checks=['system', 'firewall'])
        
        assert result['scan_type'] == 'custom'
        assert result['summary']['total'] == 2
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_single_specific_check(self, mock_get_func, scanner):
        """Test running a single specific check."""
        mock_check = MagicMock()
        mock_check.return_value = [
            {'category': 'Test', 'status': 'ok', 'description': 'Test', 'details': None}
        ]
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('custom', specific_checks=['system'])
        
        assert result['scan_type'] == 'custom'
        assert result['summary']['total'] == 1
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_specific_checks_override_scan_type(self, mock_get_func, scanner):
        """Test that specific_checks override scan_type."""
        mock_check = MagicMock()
        mock_check.return_value = []
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('basic', specific_checks=['firewall'])
        
        # Should be 'custom' not 'basic' when specific_checks provided
        assert result['scan_type'] == 'custom'
    
    # ========================================================================
    # Error Handling Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_scan_with_check_error(self, mock_get_func, scanner):
        """Test handling of check errors."""
        mock_check = MagicMock()
        mock_check.side_effect = Exception("Test error")
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('basic', specific_checks=['system'])
        
        assert result['summary']['total'] == 1
        assert result['findings'][0]['status'] == 'error'
        assert 'Test error' in result['findings'][0]['description']
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_scan_with_multiple_errors(self, mock_get_func, scanner):
        """Test handling of multiple check errors."""
        mock_check = MagicMock()
        mock_check.side_effect = [Exception("Error 1"), Exception("Error 2")]
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('basic', specific_checks=['system', 'firewall'])
        
        assert result['summary']['total'] == 2
        assert result['summary']['error'] == 2
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_scan_with_mixed_results(self, mock_get_func, scanner):
        """Test scan with mixed success and errors."""
        mock_success = MagicMock()
        mock_success.return_value = [
            {'category': 'Test', 'status': 'ok', 'description': 'Success', 'details': None}
        ]
        mock_fail = MagicMock()
        mock_fail.side_effect = Exception("Failed")
        
        mock_get_func.side_effect = [mock_success, mock_fail]
        
        result = scanner.scan('basic', specific_checks=['system', 'firewall'])
        
        assert result['summary']['total'] == 2
        assert result['summary']['ok'] == 1
        assert result['summary']['error'] == 1
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_none_check_function(self, mock_get_func, scanner):
        """Test handling when check function returns None."""
        mock_get_func.return_value = None
        
        result = scanner.scan('basic', specific_checks=['system'])
        
        assert result['summary']['total'] == 0
    
    # ========================================================================
    # Progress Callback Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_progress_callback(self, mock_get_checks, mock_get_func, scanner):
        """Test progress callback functionality."""
        mock_get_checks.return_value = ['system', 'firewall']
        
        mock_check = MagicMock()
        mock_check.return_value = []
        mock_get_func.return_value = mock_check
        
        callbacks = []
        def callback(msg):
            callbacks.append(msg)
        
        scanner.scan('basic', progress_callback=callback)
        
        assert len(callbacks) == 2
        assert all('Running' in msg or 'Checking' in msg for msg in callbacks)
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_no_progress_callback(self, mock_get_func, scanner):
        """Test scan without progress callback."""
        mock_check = MagicMock()
        mock_check.return_value = []
        mock_get_func.return_value = mock_check
        
        # Should not raise any errors
        result = scanner.scan('basic', specific_checks=['system'])
        
        assert result is not None
    
    # ========================================================================
    # Scan with Progress Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_scan_with_progress(self, mock_get_checks, mock_get_func, scanner):
        """Test scan_with_progress execution."""
        mock_get_checks.return_value = ['system', 'firewall']
        
        mock_check = MagicMock()
        mock_check.return_value = [
            {'category': 'Test', 'status': 'ok', 'description': 'Test', 'details': None}
        ]
        mock_get_func.return_value = mock_check
        
        console = Console(force_terminal=False, color_system=None)
        result = scanner.scan_with_progress('basic', console=console)
        
        assert result['scan_type'] == 'basic'
        assert result['summary']['total'] == 2
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_scan_with_progress_error_handling(self, mock_get_checks, mock_get_func, scanner):
        """Test error handling in scan_with_progress."""
        mock_get_checks.return_value = ['system']
        
        mock_check = MagicMock()
        mock_check.side_effect = Exception("Progress test error")
        mock_get_func.return_value = mock_check
        
        console = Console(force_terminal=False, color_system=None)
        result = scanner.scan_with_progress('basic', console=console)
        
        assert result['summary']['error'] == 1
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_scan_with_progress_no_console(self, mock_get_checks, mock_get_func, scanner):
        """Test scan_with_progress without console."""
        mock_get_checks.return_value = ['system']
        
        mock_check = MagicMock()
        mock_check.return_value = []
        mock_get_func.return_value = mock_check
        
        # Should work without console (uses default)
        result = scanner.scan_with_progress('basic')
        
        assert result is not None
    
    # ========================================================================
    # Summary Generation Tests
    # ========================================================================
    
    def test_generate_summary(self, scanner):
        """Test summary generation."""
        findings = [
            {'category': 'Test', 'status': 'ok', 'description': 'OK', 'details': None},
            {'category': 'Test', 'status': 'ok', 'description': 'OK', 'details': None},
            {'category': 'Test', 'status': 'warning', 'description': 'Warning', 'details': None},
            {'category': 'Test', 'status': 'critical', 'description': 'Critical', 'details': None},
            {'category': 'Test', 'status': 'info', 'description': 'Info', 'details': None},
        ]
        
        summary = scanner._generate_summary(findings)
        
        assert summary['total'] == 5
        assert summary['ok'] == 2
        assert summary['warning'] == 1
        assert summary['critical'] == 1
        assert summary['info'] == 1
    
    def test_generate_summary_empty(self, scanner):
        """Test summary generation with empty findings."""
        summary = scanner._generate_summary([])
        
        assert summary['total'] == 0
        assert summary['ok'] == 0
        assert summary['warning'] == 0
        assert summary['critical'] == 0
        assert summary['info'] == 0
        assert summary['error'] == 0
    
    def test_generate_summary_only_ok(self, scanner):
        """Test summary with only OK findings."""
        findings = [
            {'category': 'Test', 'status': 'ok', 'description': 'OK', 'details': None},
            {'category': 'Test', 'status': 'ok', 'description': 'OK', 'details': None},
        ]
        
        summary = scanner._generate_summary(findings)
        
        assert summary['total'] == 2
        assert summary['ok'] == 2
        assert summary['warning'] == 0
        assert summary['critical'] == 0
    
    def test_generate_summary_only_critical(self, scanner):
        """Test summary with only critical findings."""
        findings = [
            {'category': 'Test', 'status': 'critical', 'description': 'Critical', 'details': None},
            {'category': 'Test', 'status': 'critical', 'description': 'Critical', 'details': None},
        ]
        
        summary = scanner._generate_summary(findings)
        
        assert summary['total'] == 2
        assert summary['critical'] == 2
        assert summary['ok'] == 0
    
    def test_generate_summary_missing_status(self, scanner):
        """Test summary handling of findings without status."""
        findings = [
            {'category': 'Test', 'description': 'No status', 'details': None},
        ]
        
        summary = scanner._generate_summary(findings)
        
        # Should handle missing status gracefully (defaults to info)
        assert summary['total'] == 1
    
    def test_generate_summary_invalid_status(self, scanner):
        """Test summary handling of invalid status values."""
        findings = [
            {'category': 'Test', 'status': 'invalid', 'description': 'Invalid', 'details': None},
        ]
        
        summary = scanner._generate_summary(findings)
        
        # Should handle invalid status gracefully
        assert summary['total'] == 1
    
    # ========================================================================
    # Timestamp Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    @patch('winsec_auditor.scanner.get_checks_for_scan_type')
    def test_timestamp_format(self, mock_get_checks, mock_get_func, scanner):
        """Test that timestamp is in ISO format."""
        mock_get_checks.return_value = ['system']
        
        mock_check = MagicMock()
        mock_check.return_value = []
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('basic')
        
        # Timestamp should be a valid ISO format string
        timestamp = result['timestamp']
        assert 'T' in timestamp  # ISO format has T separator
        assert '-' in timestamp  # Date separator
        assert ':' in timestamp  # Time separator
    
    # ========================================================================
    # Finding Details Tests
    # ========================================================================
    
    @patch('winsec_auditor.scanner.get_check_function')
    def test_findings_preserved(self, mock_get_func, scanner):
        """Test that findings are preserved in result."""
        test_findings = [
            {'category': 'Test1', 'status': 'ok', 'description': 'Test 1', 'details': {'key': 'value'}},
            {'category': 'Test2', 'status': 'warning', 'description': 'Test 2', 'details': None},
        ]
        
        mock_check = MagicMock()
        mock_check.return_value = test_findings
        mock_get_func.return_value = mock_check
        
        result = scanner.scan('basic', specific_checks=['system'])
        
        assert len(result['findings']) == 2
        assert result['findings'][0]['category'] == 'Test1'
        assert result['findings'][1]['category'] == 'Test2'
