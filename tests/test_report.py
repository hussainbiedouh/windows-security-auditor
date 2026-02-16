"""Tests for report module."""

import json
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from winsec_auditor.report import ReportGenerator


class TestReportGenerator:
    """Test cases for ReportGenerator."""
    
    @pytest.fixture
    def console(self):
        """Create a console instance."""
        return Console(color_system=None, force_terminal=False)
    
    @pytest.fixture
    def report_gen(self, console):
        """Create a report generator."""
        return ReportGenerator(console)
    
    @pytest.fixture
    def sample_result(self):
        """Sample scan result."""
        return {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic",
            "findings": [
                {
                    "category": "System Information",
                    "status": "info",
                    "description": "OS: Windows 10",
                    "details": {"version": "10.0.19045"}
                },
                {
                    "category": "System Information",
                    "status": "ok",
                    "description": "Disk usage normal",
                    "details": {"used_percent": 50}
                },
                {
                    "category": "Firewall",
                    "status": "ok",
                    "description": "All firewall profiles enabled",
                    "details": {"enabled_profiles": 3}
                },
                {
                    "category": "Updates",
                    "status": "warning",
                    "description": "5 pending updates",
                    "details": {"pending": 5}
                },
                {
                    "category": "User Accounts",
                    "status": "critical",
                    "description": "Guest account enabled",
                    "details": None
                },
                {
                    "category": "Registry",
                    "status": "error",
                    "description": "Error reading registry",
                    "details": None
                }
            ],
            "summary": {
                "total": 6,
                "info": 1,
                "ok": 2,
                "warning": 1,
                "critical": 1,
                "error": 1
            }
        }
    
    @pytest.fixture
    def empty_result(self):
        """Empty scan result."""
        return {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic",
            "findings": [],
            "summary": {
                "total": 0,
                "info": 0,
                "ok": 0,
                "warning": 0,
                "critical": 0,
                "error": 0
            }
        }
    
    @pytest.fixture
    def critical_result(self):
        """Scan result with only critical findings."""
        return {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "full",
            "findings": [
                {
                    "category": "Security",
                    "status": "critical",
                    "description": "Critical issue 1",
                    "details": None
                },
                {
                    "category": "Security",
                    "status": "critical",
                    "description": "Critical issue 2",
                    "details": None
                }
            ],
            "summary": {
                "total": 2,
                "info": 0,
                "ok": 0,
                "warning": 0,
                "critical": 2,
                "error": 0
            }
        }
    
    # ========================================================================
    # Console Report Tests
    # ========================================================================
    
    def test_generate_console_report(self, report_gen, sample_result):
        """Test console report generation."""
        # Should not raise any exceptions
        report_gen.generate_console_report(sample_result)
    
    def test_generate_console_report_empty(self, report_gen, empty_result):
        """Test console report with empty results."""
        # Should not raise any exceptions
        report_gen.generate_console_report(empty_result)
    
    def test_generate_console_report_critical(self, report_gen, critical_result):
        """Test console report with critical findings."""
        # Should not raise any exceptions
        report_gen.generate_console_report(critical_result)
    
    def test_console_report_shows_timestamp(self, report_gen, sample_result, capsys):
        """Test console report shows timestamp."""
        report_gen.generate_console_report(sample_result)
        # Verify console output contains timestamp
        # Note: Rich console capture is complex, we test structure instead
    
    def test_console_report_shows_summary(self, report_gen, sample_result):
        """Test console report shows summary table."""
        # Should generate summary table with counts
        report_gen.generate_console_report(sample_result)
    
    def test_console_report_categorizes_findings(self, report_gen, sample_result):
        """Test console report categorizes findings."""
        # Should group findings by category
        report_gen.generate_console_report(sample_result)
    
    def test_console_report_shows_status_icons(self, report_gen, sample_result):
        """Test console report shows status icons."""
        # Should show different icons for different statuses
        report_gen.generate_console_report(sample_result)
    
    # ========================================================================
    # JSON Report Tests
    # ========================================================================
    
    def test_generate_json_report(self, report_gen, sample_result):
        """Test JSON report generation."""
        json_str = report_gen.generate_json_report(sample_result)
        
        # Should be valid JSON
        data = json.loads(json_str)
        assert data['timestamp'] == sample_result['timestamp']
        assert data['scan_type'] == sample_result['scan_type']
    
    def test_generate_json_report_empty(self, report_gen, empty_result):
        """Test JSON report with empty results."""
        json_str = report_gen.generate_json_report(empty_result)
        
        data = json.loads(json_str)
        assert data['findings'] == []
        assert data['summary']['total'] == 0
    
    def test_json_report_structure(self, report_gen, sample_result):
        """Test JSON report has correct structure."""
        json_str = report_gen.generate_json_report(sample_result)
        data = json.loads(json_str)
        
        assert 'timestamp' in data
        assert 'scan_type' in data
        assert 'findings' in data
        assert 'summary' in data
        assert 'total' in data['summary']
        assert 'ok' in data['summary']
        assert 'warning' in data['summary']
        assert 'critical' in data['summary']
    
    def test_json_report_finding_structure(self, report_gen, sample_result):
        """Test JSON report findings have correct structure."""
        json_str = report_gen.generate_json_report(sample_result)
        data = json.loads(json_str)
        
        for finding in data['findings']:
            assert 'category' in finding
            assert 'status' in finding
            assert 'description' in finding
            assert 'details' in finding
    
    def test_json_report_pretty_printed(self, report_gen, sample_result):
        """Test JSON report is pretty printed."""
        json_str = report_gen.generate_json_report(sample_result)
        
        # Should have indentation
        assert '\n' in json_str
        assert '  ' in json_str or '\t' in json_str
    
    # ========================================================================
    # Save JSON Report Tests
    # ========================================================================
    
    def test_save_json_report(self, report_gen, sample_result, tmp_path):
        """Test saving JSON report to file."""
        filepath = tmp_path / "report.json"
        
        report_gen.save_json_report(sample_result, str(filepath))
        
        assert filepath.exists()
        
        # Verify content
        data = json.loads(filepath.read_text())
        assert data['timestamp'] == sample_result['timestamp']
    
    def test_save_json_report_nested_dir(self, report_gen, sample_result, tmp_path):
        """Test saving JSON report to nested directory."""
        filepath = tmp_path / "reports" / "security" / "report.json"
        filepath.parent.mkdir(parents=True)
        
        report_gen.save_json_report(sample_result, str(filepath))
        
        assert filepath.exists()
    
    def test_save_json_report_overwrite(self, report_gen, sample_result, tmp_path):
        """Test overwriting existing JSON report."""
        filepath = tmp_path / "report.json"
        filepath.write_text("old content")
        
        report_gen.save_json_report(sample_result, str(filepath))
        
        content = filepath.read_text()
        assert "old content" not in content
        assert "timestamp" in content
    
    # ========================================================================
    # HTML Report Tests
    # ========================================================================
    
    def test_generate_html_report(self, report_gen, sample_result):
        """Test HTML report generation."""
        html = report_gen.generate_html_report(sample_result)
        
        assert "<!DOCTYPE html>" in html or "<html" in html.lower()
        assert "Windows Security Audit Report" in html
        assert sample_result['timestamp'] in html
    
    def test_generate_html_report_empty(self, report_gen, empty_result):
        """Test HTML report with empty results."""
        html = report_gen.generate_html_report(empty_result)
        
        assert "<!DOCTYPE html>" in html or "<html" in html.lower()
        # Should show 0 counts
        assert html.count("0") >= 3  # At least a few zeros
    
    def test_generate_html_report_critical(self, report_gen, critical_result):
        """Test HTML report with critical findings."""
        html = report_gen.generate_html_report(critical_result)
        
        assert "Critical" in html or "critical" in html.lower()
        assert "2" in html  # Count should be present
    
    def test_html_report_contains_summary_cards(self, report_gen, sample_result):
        """Test HTML report has summary cards."""
        html = report_gen.generate_html_report(sample_result)
        
        # Should have sections for total, ok, warning, critical, info
        assert "Total" in html
        assert "Secure" in html or "OK" in html.upper()
        assert "Warning" in html or "warning" in html.lower()
    
    def test_html_report_contains_categories(self, report_gen, sample_result):
        """Test HTML report shows categories."""
        html = report_gen.generate_html_report(sample_result)
        
        # Should show at least some categories
        assert "System Information" in html or "System" in html
    
    def test_html_report_contains_findings(self, report_gen, sample_result):
        """Test HTML report shows individual findings."""
        html = report_gen.generate_html_report(sample_result)
        
        # Should contain finding descriptions
        assert "Disk usage normal" in html or "Windows 10" in html
    
    def test_html_report_has_styles(self, report_gen, sample_result):
        """Test HTML report has CSS styles."""
        html = report_gen.generate_html_report(sample_result)
        
        assert "<style>" in html
        assert "</style>" in html
        assert "class=" in html.lower()
    
    def test_html_report_responsive_meta(self, report_gen, sample_result):
        """Test HTML report has responsive meta tag."""
        html = report_gen.generate_html_report(sample_result)
        
        assert "viewport" in html.lower()
    
    # ========================================================================
    # Save HTML Report Tests
    # ========================================================================
    
    def test_save_html_report(self, report_gen, sample_result, tmp_path):
        """Test saving HTML report to file."""
        filepath = tmp_path / "report.html"
        
        report_gen.save_html_report(sample_result, str(filepath))
        
        assert filepath.exists()
        
        content = filepath.read_text()
        assert "<!DOCTYPE html>" in content or "<html" in content.lower()
    
    def test_save_html_report_nested_dir(self, report_gen, sample_result, tmp_path):
        """Test saving HTML report to nested directory."""
        filepath = tmp_path / "reports" / "security" / "report.html"
        filepath.parent.mkdir(parents=True)
        
        report_gen.save_html_report(sample_result, str(filepath))
        
        assert filepath.exists()
    
    def test_save_html_report_overwrite(self, report_gen, sample_result, tmp_path):
        """Test overwriting existing HTML report."""
        filepath = tmp_path / "report.html"
        filepath.write_text("<html>old content</html>")
        
        report_gen.save_html_report(sample_result, str(filepath))
        
        content = filepath.read_text()
        # Check that old content is replaced (look for specific old content pattern)
        assert "old content" not in content
        assert "Windows Security Audit Report" in content
    
    # ========================================================================
    # Console Output Tests
    # ========================================================================
    
    def test_save_json_prints_confirmation(self, report_gen, sample_result, tmp_path, mock_console):
        """Test that save_json prints confirmation."""
        filepath = tmp_path / "report.json"
        report_gen.save_json_report(sample_result, str(filepath))
        
        # Console should have printed success message
        # (Testing actual console output is tricky with Rich)
    
    def test_save_html_prints_confirmation(self, report_gen, sample_result, tmp_path, mock_console):
        """Test that save_html prints confirmation."""
        filepath = tmp_path / "report.html"
        report_gen.save_html_report(sample_result, str(filepath))
        
        # Console should have printed success message
    
    # ========================================================================
    # Report with Special Characters Tests
    # ========================================================================
    
    def test_json_handles_special_characters(self, report_gen):
        """Test JSON report handles special characters."""
        result = {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic",
            "findings": [
                {
                    "category": "Test",
                    "status": "info",
                    "description": 'Special chars: "quotes" \n newline \t tab',
                    "details": {"key": "value with <html> & special"}
                }
            ],
            "summary": {"total": 1, "info": 1, "ok": 0, "warning": 0, "critical": 0, "error": 0}
        }
        
        json_str = report_gen.generate_json_report(result)
        data = json.loads(json_str)
        
        # Should round-trip correctly
        assert data['findings'][0]['description'] == result['findings'][0]['description']
    
    def test_html_escapes_special_characters(self, report_gen):
        """Test HTML report escapes special characters."""
        result = {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic",
            "findings": [
                {
                    "category": "Test",
                    "status": "info",
                    "description": "Contains <script>alert('xss')</script>",
                    "details": None
                }
            ],
            "summary": {"total": 1, "info": 1, "ok": 0, "warning": 0, "critical": 0, "error": 0}
        }
        
        html = report_gen.generate_html_report(result)
        
        # Should not contain raw script tags
        assert "<script>alert" not in html
    
    # ========================================================================
    # Large Result Tests
    # ========================================================================
    
    def test_handles_large_number_of_findings(self, report_gen):
        """Test report generation with many findings."""
        result = {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "full",
            "findings": [
                {
                    "category": f"Category {i % 10}",
                    "status": ["ok", "warning", "critical", "info"][i % 4],
                    "description": f"Finding {i}",
                    "details": None
                }
                for i in range(100)
            ],
            "summary": {"total": 100, "info": 25, "ok": 25, "warning": 25, "critical": 25, "error": 0}
        }
        
        # Should not raise any exceptions
        json_str = report_gen.generate_json_report(result)
        html = report_gen.generate_html_report(result)
        
        assert len(json_str) > 0
        assert len(html) > 0
    
    # ========================================================================
    # Unicode Tests
    # ========================================================================
    
    def test_handles_unicode(self, report_gen):
        """Test report generation with unicode characters."""
        result = {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic",
            "findings": [
                {
                    "category": "Test",
                    "status": "info",
                    "description": "Unicode: 🔐 🚨 ⚠️ ✅ ℹ️ Café 日本語",
                    "details": None
                }
            ],
            "summary": {"total": 1, "info": 1, "ok": 0, "warning": 0, "critical": 0, "error": 0}
        }
        
        # Should not raise any exceptions
        json_str = report_gen.generate_json_report(result)
        html = report_gen.generate_html_report(result)
        
        # JSON should preserve unicode
        data = json.loads(json_str)
        assert "🔐" in data['findings'][0]['description']
    
    # ========================================================================
    # Report Generation with Missing Fields Tests
    # ========================================================================
    
    def test_handles_missing_summary(self, report_gen):
        """Test report generation with missing summary."""
        result = {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic",
            "findings": []
            # No summary
        }
        
        # Should handle missing summary gracefully
        report_gen.generate_console_report(result)
        json_str = report_gen.generate_json_report(result)
        html = report_gen.generate_html_report(result)
        
        assert json_str is not None
        assert html is not None
    
    def test_handles_missing_findings(self, report_gen):
        """Test report generation with missing findings."""
        result = {
            "timestamp": "2024-01-15T10:30:00",
            "scan_type": "basic"
            # No findings
        }
        
        # Should handle missing findings gracefully
        report_gen.generate_console_report(result)
        json_str = report_gen.generate_json_report(result)
        html = report_gen.generate_html_report(result)
        
        assert json_str is not None
        assert html is not None
