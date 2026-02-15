"""Tests for system check module."""

from unittest.mock import patch, MagicMock

import pytest

from winsec_auditor.checks import system


class TestSystemChecks:
    """Test system information checks."""
    
    @patch('winsec_auditor.checks.system.is_windows')
    def test_non_windows(self, mock_is_windows):
        """Test that check fails on non-Windows."""
        mock_is_windows.return_value = False
        
        findings = system.check_system()
        
        assert len(findings) == 1
        assert findings[0]['status'] == 'error'
        assert 'Windows' in findings[0]['description']
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    @patch('winsec_auditor.checks.system.psutil.boot_time')
    def test_windows_system_all_ok(self, mock_boot, mock_memory, mock_disk, mock_is_windows):
        """Test system check on Windows with all OK status."""
        mock_is_windows.return_value = True
        
        # Mock disk usage - normal (50%)
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=250_000_000_000,
            percent=50
        )
        
        # Mock memory - normal (50%)
        mock_memory.return_value = MagicMock(
            total=16_000_000_000,
            available=8_000_000_000,
            percent=50
        )
        
        # Mock boot time
        mock_boot.return_value = 1704067200  # 2024-01-01
        
        findings = system.check_system()
        
        # Should have OS, Arch, CPU, Disk, Memory, Uptime
        assert len(findings) >= 4
        
        categories = [f['category'] for f in findings]
        assert all(c == 'System Information' for c in categories)
        
        # Disk and Memory should be OK
        disk_finding = [f for f in findings if 'Disk' in f['description']]
        assert len(disk_finding) == 1
        assert disk_finding[0]['status'] == 'ok'
        
        memory_finding = [f for f in findings if 'Memory' in f['description']]
        assert len(memory_finding) == 1
        assert memory_finding[0]['status'] == 'ok'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_disk_warning(self, mock_memory, mock_disk, mock_is_windows):
        """Test disk warning status (90-95% usage)."""
        mock_is_windows.return_value = True
        
        # Mock disk usage - warning level (92%)
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=40_000_000_000,
            percent=92
        )
        
        # Mock memory - normal
        mock_memory.return_value = MagicMock(
            total=16_000_000_000,
            available=8_000_000_000,
            percent=50
        )
        
        findings = system.check_system()
        
        disk_finding = [f for f in findings if 'Disk' in f['description']]
        assert len(disk_finding) == 1
        assert disk_finding[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_disk_critical(self, mock_memory, mock_disk, mock_is_windows):
        """Test disk critical status (>95% usage)."""
        mock_is_windows.return_value = True
        
        # Mock disk usage - critical level (97%)
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=15_000_000_000,
            percent=97
        )
        
        # Mock memory - normal
        mock_memory.return_value = MagicMock(
            total=16_000_000_000,
            available=8_000_000_000,
            percent=50
        )
        
        findings = system.check_system()
        
        disk_finding = [f for f in findings if 'Disk' in f['description']]
        assert len(disk_finding) == 1
        assert disk_finding[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_memory_warning(self, mock_memory, mock_disk, mock_is_windows):
        """Test memory warning status (80-90% usage)."""
        mock_is_windows.return_value = True
        
        # Mock disk - normal
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=250_000_000_000,
            percent=50
        )
        
        # Mock memory - warning level (85%)
        mock_memory.return_value = MagicMock(
            total=16_000_000_000,
            available=2_400_000_000,
            percent=85
        )
        
        findings = system.check_system()
        
        memory_finding = [f for f in findings if 'Memory' in f['description']]
        assert len(memory_finding) == 1
        assert memory_finding[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_memory_critical(self, mock_memory, mock_disk, mock_is_windows):
        """Test memory critical status (>90% usage)."""
        mock_is_windows.return_value = True
        
        # Mock disk - normal
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=250_000_000_000,
            percent=50
        )
        
        # Mock memory - critical level (95%)
        mock_memory.return_value = MagicMock(
            total=16_000_000_000,
            available=800_000_000,
            percent=95
        )
        
        findings = system.check_system()
        
        memory_finding = [f for f in findings if 'Memory' in f['description']]
        assert len(memory_finding) == 1
        assert memory_finding[0]['status'] == 'critical'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    def test_disk_exception(self, mock_disk, mock_is_windows):
        """Test handling of disk usage exception."""
        mock_is_windows.return_value = True
        mock_disk.side_effect = Exception("Disk error")
        
        findings = system.check_system()
        
        disk_finding = [f for f in findings if 'Disk' in f['description'] and 'Could not' in f['description']]
        assert len(disk_finding) == 1
        assert disk_finding[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_memory_exception(self, mock_memory, mock_disk, mock_is_windows):
        """Test handling of memory exception."""
        mock_is_windows.return_value = True
        
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=250_000_000_000,
            percent=50
        )
        mock_memory.side_effect = Exception("Memory error")
        
        findings = system.check_system()
        
        memory_finding = [f for f in findings if 'Memory' in f['description'] and 'Could not' in f['description']]
        assert len(memory_finding) == 1
        assert memory_finding[0]['status'] == 'warning'
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    @patch('winsec_auditor.checks.system.psutil.boot_time')
    def test_os_info_structure(self, mock_boot, mock_memory, mock_disk, mock_is_windows):
        """Test OS info has correct structure."""
        mock_is_windows.return_value = True
        mock_disk.return_value = MagicMock(total=100, free=50, percent=50)
        mock_memory.return_value = MagicMock(total=100, available=50, percent=50)
        mock_boot.return_value = 1704067200
        
        findings = system.check_system()
        
        # Find OS finding
        os_finding = [f for f in findings if 'Operating System' in f['description']]
        assert len(os_finding) == 1
        assert os_finding[0]['status'] == 'info'
        assert os_finding[0]['details'] is not None
        assert 'version' in os_finding[0]['details']
        assert 'machine' in os_finding[0]['details']
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_disk_details_structure(self, mock_memory, mock_disk, mock_is_windows):
        """Test disk finding has correct details structure."""
        mock_is_windows.return_value = True
        mock_disk.return_value = MagicMock(
            total=500_000_000_000,
            free=250_000_000_000,
            percent=50
        )
        mock_memory.return_value = MagicMock(total=100, available=50, percent=50)
        
        findings = system.check_system()
        
        disk_finding = [f for f in findings if 'Disk Space' in f['description']][0]
        assert disk_finding['details'] is not None
        assert 'total_gb' in disk_finding['details']
        assert 'free_gb' in disk_finding['details']
        assert 'used_percent' in disk_finding['details']
        assert isinstance(disk_finding['details']['total_gb'], (int, float))
        assert isinstance(disk_finding['details']['free_gb'], (int, float))
        assert isinstance(disk_finding['details']['used_percent'], (int, float))
    
    @patch('winsec_auditor.checks.system.is_windows')
    @patch('winsec_auditor.checks.system.psutil.disk_usage')
    @patch('winsec_auditor.checks.system.psutil.virtual_memory')
    def test_memory_details_structure(self, mock_memory, mock_disk, mock_is_windows):
        """Test memory finding has correct details structure."""
        mock_is_windows.return_value = True
        mock_disk.return_value = MagicMock(total=100, free=50, percent=50)
        mock_memory.return_value = MagicMock(
            total=16_000_000_000,
            available=8_000_000_000,
            percent=50
        )
        
        findings = system.check_system()
        
        memory_finding = [f for f in findings if 'Memory:' in f['description']][0]
        assert memory_finding['details'] is not None
        assert 'total_gb' in memory_finding['details']
        assert 'available_gb' in memory_finding['details']
        assert 'used_percent' in memory_finding['details']
