"""Tests for configuration module."""

import os
import json
import tempfile
from unittest.mock import patch

import pytest

from winsec_auditor.config import Config, config, get_config, set_config


class TestConfigDefaults:
    """Test Config default values."""
    
    def test_default_max_autorun_entries(self):
        """Test default autorun entries limit."""
        cfg = Config()
        assert cfg.max_autorun_entries == 50
    
    def test_default_max_event_log_entries(self):
        """Test default event log entries limit."""
        cfg = Config()
        assert cfg.max_event_log_entries == 100
    
    def test_default_privilege_escalation_threshold(self):
        """Test default privilege escalation threshold."""
        cfg = Config()
        assert cfg.privilege_escalation_threshold == 10
    
    def test_default_brute_force_threshold(self):
        """Test default brute force threshold."""
        cfg = Config()
        assert cfg.brute_force_threshold == 5
    
    def test_default_suspicious_powershell_threshold(self):
        """Test default suspicious PowerShell threshold."""
        cfg = Config()
        assert cfg.suspicious_powershell_threshold == 3
    
    def test_default_detail_level(self):
        """Test default detail level."""
        cfg = Config()
        assert cfg.default_detail_level == "standard"
    
    def test_default_powershell_timeout(self):
        """Test default PowerShell timeout."""
        cfg = Config()
        assert cfg.powershell_timeout == 30
    
    def test_default_command_timeout(self):
        """Test default command timeout."""
        cfg = Config()
        assert cfg.command_timeout == 10
    
    def test_default_high_connection_threshold(self):
        """Test default high connection threshold."""
        cfg = Config()
        assert cfg.high_connection_threshold == 100
    
    def test_default_risky_ports_not_empty(self):
        """Test that risky ports list is not empty."""
        cfg = Config()
        assert len(cfg.risky_ports) > 0
        assert 3389 in cfg.risky_ports  # RDP
        assert 445 in cfg.risky_ports   # SMB
    
    def test_default_risky_ports_with_desc(self):
        """Test that risky ports with descriptions is not empty."""
        cfg = Config()
        assert len(cfg.risky_ports_with_desc) > 0
        # Check first element is a tuple
        assert isinstance(cfg.risky_ports_with_desc[0], tuple)
        assert len(cfg.risky_ports_with_desc[0]) == 2


class TestConfigFromEnv:
    """Test loading config from environment variables."""
    
    @patch.dict(os.environ, {'WSA_MAX_AUTORUN': '100'})
    def test_max_autorun_from_env(self):
        """Test loading max_autorun from environment."""
        cfg = Config.from_env()
        assert cfg.max_autorun_entries == 100
    
    @patch.dict(os.environ, {'WSA_MAX_EVENTS': '200'})
    def test_max_events_from_env(self):
        """Test loading max_events from environment."""
        cfg = Config.from_env()
        assert cfg.max_event_log_entries == 200
    
    @patch.dict(os.environ, {'WSA_PRIV_THRESHOLD': '20'})
    def test_priv_threshold_from_env(self):
        """Test loading privilege threshold from environment."""
        cfg = Config.from_env()
        assert cfg.privilege_escalation_threshold == 20
    
    @patch.dict(os.environ, {'WSA_BRUTE_THRESHOLD': '10'})
    def test_brute_threshold_from_env(self):
        """Test loading brute force threshold from environment."""
        cfg = Config.from_env()
        assert cfg.brute_force_threshold == 10
    
    @patch.dict(os.environ, {'WSA_PS_THRESHOLD': '5'})
    def test_ps_threshold_from_env(self):
        """Test loading PowerShell threshold from environment."""
        cfg = Config.from_env()
        assert cfg.suspicious_powershell_threshold == 5
    
    @patch.dict(os.environ, {'WSA_DETAIL_LEVEL': 'minimal'})
    def test_detail_level_from_env(self):
        """Test loading detail level from environment."""
        cfg = Config.from_env()
        assert cfg.default_detail_level == "minimal"
    
    @patch.dict(os.environ, {'WSA_PS_TIMEOUT': '60'})
    def test_ps_timeout_from_env(self):
        """Test loading PowerShell timeout from environment."""
        cfg = Config.from_env()
        assert cfg.powershell_timeout == 60
    
    @patch.dict(os.environ, {'WSA_CMD_TIMEOUT': '20'})
    def test_cmd_timeout_from_env(self):
        """Test loading command timeout from environment."""
        cfg = Config.from_env()
        assert cfg.command_timeout == 20
    
    @patch.dict(os.environ, {'WSA_HIGH_CONN_THRESHOLD': '150'})
    def test_high_conn_threshold_from_env(self):
        """Test loading high connection threshold from environment."""
        cfg = Config.from_env()
        assert cfg.high_connection_threshold == 150
    
    @patch.dict(os.environ, {'WSA_MAX_AUTORUN': 'invalid'})
    def test_invalid_int_env_ignored(self):
        """Test that invalid integer env vars are ignored."""
        cfg = Config.from_env()
        # Should use default value
        assert cfg.max_autorun_entries == 50


class TestConfigFromFile:
    """Test loading config from JSON file."""
    
    def test_load_from_file(self):
        """Test loading config from JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                'max_autorun_entries': 75,
                'max_event_log_entries': 150,
                'default_detail_level': 'full',
            }, f)
            temp_path = f.name
        
        try:
            cfg = Config.from_file(temp_path)
            assert cfg.max_autorun_entries == 75
            assert cfg.max_event_log_entries == 150
            assert cfg.default_detail_level == 'full'
            # Other values should use defaults
            assert cfg.powershell_timeout == 30
        finally:
            os.unlink(temp_path)
    
    def test_file_not_found(self):
        """Test loading from non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            Config.from_file('/nonexistent/path/config.json')


class TestConfigToFile:
    """Test saving config to JSON file."""
    
    def test_save_to_file(self):
        """Test saving config to JSON file."""
        cfg = Config()
        cfg.max_autorun_entries = 99
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            cfg.to_file(temp_path)
            
            # Read and verify
            with open(temp_path, 'r') as f:
                data = json.load(f)
            
            assert data['max_autorun_entries'] == 99
            assert data['default_detail_level'] == 'standard'
        finally:
            os.unlink(temp_path)


class TestValidateDetailLevel:
    """Test detail level validation."""
    
    def test_valid_minimal(self):
        """Test validating 'minimal' detail level."""
        cfg = Config()
        assert cfg.validate_detail_level('minimal') == 'minimal'
    
    def test_valid_standard(self):
        """Test validating 'standard' detail level."""
        cfg = Config()
        assert cfg.validate_detail_level('standard') == 'standard'
    
    def test_valid_full(self):
        """Test validating 'full' detail level."""
        cfg = Config()
        assert cfg.validate_detail_level('full') == 'full'
    
    def test_case_insensitive(self):
        """Test that validation is case insensitive."""
        cfg = Config()
        assert cfg.validate_detail_level('MINIMAL') == 'minimal'
        assert cfg.validate_detail_level('Standard') == 'standard'
        assert cfg.validate_detail_level('FULL') == 'full'
    
    def test_invalid_level(self):
        """Test that invalid level raises ValueError."""
        cfg = Config()
        with pytest.raises(ValueError) as exc_info:
            cfg.validate_detail_level('invalid')
        assert 'invalid' in str(exc_info.value)


class TestGlobalConfig:
    """Test global config instance functions."""
    
    def test_get_config_returns_config(self):
        """Test that get_config returns a Config instance."""
        cfg = get_config()
        assert isinstance(cfg, Config)
    
    def test_set_config_updates_global(self):
        """Test that set_config updates the global config."""
        new_config = Config()
        new_config.max_autorun_entries = 999
        
        set_config(new_config)
        
        cfg = get_config()
        assert cfg.max_autorun_entries == 999
    
    def test_module_level_config_exists(self):
        """Test that module-level config exists."""
        assert isinstance(config, Config)


class TestConfigBackwardCompatibility:
    """Test that config maintains backward compatibility."""
    
    def test_old_hardcoded_values_match_defaults(self):
        """Test that old hardcoded values match new defaults."""
        cfg = Config()
        
        # These were the original hardcoded values
        assert cfg.max_autorun_entries == 50  # Was 10, now configurable
        assert cfg.privilege_escalation_threshold == 10  # Was magic number 10
        assert cfg.brute_force_threshold == 5  # Was magic number 5
        assert cfg.high_connection_threshold == 100  # Was magic number 100
    
    def test_risky_ports_contains_original_ports(self):
        """Test that risky ports includes original hardcoded ports."""
        cfg = Config()
        original_ports = [20, 21, 23, 25, 110, 135, 137, 138, 139, 445, 993, 995, 1433, 3389, 5900]
        
        for port in original_ports:
            assert port in cfg.risky_ports, f"Port {port} should be in risky_ports"
