# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Documentation improvements and comprehensive README
- Enhanced usage examples with automation scripts

## [0.1.0] - 2026-02-15

### Added

#### Core Features
- Complete package architecture with proper Python package structure
- CLI built with Click for enhanced user experience
- Rich-based console UI with progress bars, tables, and color-coded output
- Multiple output formats: console (default), JSON, and HTML reports
- Interactive scan selection mode with guided prompts
- Modular check system supporting Basic, Full, and Custom scan types

#### Security Checks (11 Total)
- **System Information** - OS version, architecture, disk usage, memory usage, uptime
- **Windows Updates** - Pending updates and Windows Update service status
- **Firewall Status** - Domain, Private, and Public profile status
- **Autorun Programs** - Startup items with suspicious path and keyword detection
- **User Accounts** - User enumeration, admin privileges, guest account status
- **Running Services** - Service enumeration with risky service identification
- **Registry Security** - UAC settings and PowerShell execution policy
- **Network Security** - Listening ports and active connections
- **Security Software** - Antivirus, firewall, and antispyware status via WMI
- **Event Log Analysis** - Brute force detection, account lockouts, suspicious PowerShell activity

#### Check Features
- Security level classification (info, ok, warning, critical, error)
- Detailed finding descriptions with structured data
- Suspicious startup program detection using path and keyword heuristics
- Event log threat analysis covering:
  - Failed login attempts (brute force detection)
  - Account lockouts
  - New service installations
  - Malicious PowerShell commands
  - Privilege escalation attempts

#### Reporting
- Beautiful console reports with Rich tables and panels
- JSON export for automation and integration
- Professional HTML reports with responsive dark theme
- Categorized findings grouped by security check
- Summary statistics with color-coded severity counts

#### Development
- Comprehensive test suite with pytest
- Code coverage reporting with pytest-cov
- Type checking with mypy
- Linting and formatting with ruff
- GitHub templates for issues and pull requests
- Proper pyproject.toml configuration with:
  - Build system configuration
  - Project metadata
  - Optional development dependencies
  - CLI entry points
  - Tool configurations (pytest, coverage, mypy, ruff)

#### Documentation
- Comprehensive README with badges, examples, and feature descriptions
- Detailed usage examples document
- Contributing guidelines
- MIT License

### Changed
- Migrated from single-file script to proper Python package
- Replaced argparse with Click for CLI
- Replaced colorama-only output with Rich for enhanced UI
- Restructured codebase into src layout (`src/winsec_auditor/`)
- Improved error handling with try-except blocks and user-friendly messages
- Enhanced Windows detection and compatibility checks

### Removed
- Single-file script architecture
- Basic text-only output (replaced with Rich)
- Direct console print statements (replaced with Rich Console)

### Technical Details

#### Package Structure
```
src/winsec_auditor/
├── __init__.py          # Package version
├── __main__.py          # Entry point for `python -m`
├── cli.py               # Click CLI implementation
├── scanner.py           # Main scan orchestrator with progress tracking
├── report.py            # Report generation (console, JSON, HTML)
├── types.py             # Type hints and interfaces
├── utils.py             # Utility functions (WMI, PowerShell, Windows checks)
└── checks/              # Security check modules
    ├── __init__.py      # Check registry and metadata
    ├── system.py        # System information checks
    ├── updates.py       # Windows Update checks
    ├── firewall.py      # Firewall status checks
    ├── autorun.py       # Startup program checks
    ├── users.py         # User account checks
    ├── services.py      # Service enumeration checks
    ├── registry.py      # Registry security checks
    ├── network.py       # Network security checks
    ├── security_sw.py   # Security software checks
    └── events.py        # Event log analysis checks
```

#### Dependencies
- **Runtime**: rich>=13.0.0, click>=8.0.0, psutil>=5.9.0, wmi>=1.5.1, colorama>=0.4.6
- **Development**: pytest>=7.0.0, pytest-cov>=4.0.0, mypy>=1.0.0, ruff>=0.1.0, types-colorama

#### Exit Codes
- `0` - Success, no issues found
- `1` - Warnings found
- `2` - Critical issues found
- `130` - Interrupted by user

[Unreleased]: https://github.com/yourusername/winsec-auditor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/winsec-auditor/releases/tag/v0.1.0
