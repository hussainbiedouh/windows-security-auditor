# 🔐 Windows Security Auditor

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/pypi-v0.1.0-blue.svg?logo=pypi&logoColor=white)](https://pypi.org/project/winsec-auditor/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/yourusername/winsec-auditor/actions)
[![Code style](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> A comprehensive Python-based security scanning tool for Windows systems. Identifies security misconfigurations, vulnerabilities, and potential threats with beautiful console output and detailed reports.

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Security Checks](#-security-checks)
- [Report Formats](#-report-formats)
- [Configuration](#-configuration)
- [Requirements](#-requirements)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- 🚀 **Multiple Scan Modes**: Basic (3 checks), Full (11 checks), or Custom scan profiles
- 📊 **Beautiful Console UI**: Rich tables, panels, and progress indicators
- 📝 **Multiple Report Formats**: Console, JSON, and HTML reports
- 🛡️ **Comprehensive Security Checks**: 11 security modules covering system, network, and software
- 🔍 **Threat Detection**: Identifies suspicious startup programs, brute force attempts, and malicious PowerShell activity
- ⚡ **Fast & Lightweight**: Efficient WMI and PowerShell integration
- 🤖 **CI/CD Ready**: JSON output and exit codes for automation
- 🎯 **Modular Design**: Easy to extend with new security checks

## 🚀 Quick Start

Three commands to get started:

```bash
# Install the tool
pip install winsec-auditor

# Run an interactive scan
winsec-audit

# Generate a full HTML report
winsec-audit --scan full --html security_report.html
```

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install winsec-auditor
```

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/winsec-auditor.git
cd winsec-auditor

# Create virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate  # Windows

# Install in editable mode
pip install -e ".[dev]"
```

### Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **Python**: 3.9 or higher
- **Privileges**: Administrator rights recommended for best results

## 🎯 Usage

### Interactive Mode

Launch the interactive menu to select your scan type:

```bash
winsec-audit
```

```
╭────────────── Select Scan Type ─────────────╮
│                                             │
│   1. Basic Scan    - Quick system overview  │
│   2. Full Scan     - Comprehensive audit    │
│                                             │
╰─────────────────────────────────────────────╯
Enter your choice [2]:
```

### Basic Scan

Quick scan of essential security settings (3 checks):

```bash
winsec-audit --scan basic
```

Checks included:
- System information and resources
- Windows Update status
- Firewall configuration

### Full Scan

Comprehensive security audit (11 checks):

```bash
winsec-audit --scan full
```

### Custom Checks

Run only specific security checks:

```bash
# Check firewall and network only
winsec-audit --check firewall,network

# Check user accounts and services
winsec-audit --check users,services

# Multiple specific checks
winsec-audit --check firewall,users,registry,events
```

### Generate Reports

**JSON Output:**
```bash
# Output to stdout
winsec-audit --scan full --json

# Save to file
winsec-audit --scan full --json results.json
```

**HTML Report:**
```bash
winsec-audit --scan full --html audit_report.html
```

**Combined Output:**
```bash
winsec-audit --scan full --json results.json --html report.html
```

### List Available Checks

```bash
winsec-audit --list-checks
```

Output:
```
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID           ┃ Name                ┃ Type   ┃ Description                            ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ system       │ System Information  │ basic  │ Basic system information and resource  │
│              │                     │        │ usage                                  │
│ updates      │ Windows Updates     │ basic  │ Check Windows Update status            │
│ firewall     │ Firewall Status     │ basic  │ Check Windows Firewall status for all  │
│              │                     │        │ profiles                               │
│ autorun      │ Autorun Programs    │ full   │ Check startup programs with suspicious │
│              │                     │        │ detection                              │
│ users        │ User Accounts       │ full   │ Analyze user accounts and privileges   │
│ ...          │ ...                 │ ...    │ ...                                    │
└──────────────┴─────────────────────┴────────┴────────────────────────────────────────┘
```

### Additional Options

```bash
# Verbose mode for detailed error information
winsec-audit --scan full --verbose

# Disable colored output (useful for logging)
winsec-audit --scan full --no-color

# Check version
winsec-audit --version
```

## 🔒 Security Checks

The Windows Security Auditor performs **11 comprehensive security checks** across your system:

| Check | Scan Type | Description |
|:------|:---------:|:------------|
| **System Information** | Basic | OS version, architecture, processor, disk space, memory usage, uptime |
| **Windows Updates** | Basic | Pending updates, Windows Update service status |
| **Firewall Status** | Basic | All profiles status (Domain, Private, Public) |
| **Autorun Programs** | Full | Startup items with suspicious path and keyword detection |
| **User Accounts** | Full | User enumeration, admin privileges, guest account status, active sessions |
| **Running Services** | Full | Service enumeration with risky service identification |
| **Registry Security** | Full | UAC settings, PowerShell execution policy, security settings |
| **Network Security** | Full | Listening ports, active connections, network interface status |
| **Security Software** | Full | Antivirus, firewall, and antispyware status via WMI |
| **Event Log Analysis** | Full | Brute force detection, account lockouts, suspicious PowerShell activity |

### Security Levels

Findings are classified with clear severity indicators:

| Level | Color | Description | Action Required |
|:------|:-----:|:------------|:----------------|
| ℹ️ `info` | Blue | Informational | None - for awareness |
| ✅ `ok` | Green | Secure/Good | None - maintain current state |
| ⚠️ `warning` | Yellow | Needs attention | Review and consider remediation |
| 🚨 `critical` | Red | Security risk | Immediate action required |

## 📊 Report Formats

### Console Output

Beautiful Rich-based output with tables and color-coded findings:

```
╭───────────────────────────────────────────────╮
│  🔐 Windows Security Audit Report             │
╰───────────────────────────────────────────────╯

                      Scan Summary
┏━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric      ┃ Count ┃
┡━━━━━━━━━━━━━╇━━━━━━━┩
│ Total       │ 45    │
│ ✅ Secure   │ 12    │
│ ⚠ Warnings │ 5     │
│ 🚨 Critical │ 1     │
│ ℹ Info     │ 27    │
└─────────────┴───────┘

[bold blue]System Information[/bold blue]
  ℹ Operating System: Windows 10 22H2
  ℹ Architecture: 64bit
  ℹ Processor: Intel64 Family 6 Model 158
  ✅ Disk Space (C:): 150.5 GB free of 500.0 GB (30% used)
  ✅ Memory: 8.2 GB available of 16.0 GB (49% used)

[bold green]Windows Updates[/bold green]
  ✅ System is up to date
  ✅ Windows Update service is running

[bold yellow]Registry Security[/bold yellow]
  🚨 PowerShell execution policy is too permissive: unrestricted

[bold green]Security Software[/bold green]
  ✅ Active antivirus: Windows Defender
  ✅ Windows Firewall is active (3/3 profiles)
  ✅ Windows Defender Antispyware is enabled
```

### JSON Output

Structured data perfect for automation and integration:

```json
{
  "timestamp": "2026-02-15T10:30:00",
  "scan_type": "full",
  "summary": {
    "total": 45,
    "info": 27,
    "ok": 12,
    "warning": 5,
    "critical": 1,
    "error": 0
  },
  "findings": [
    {
      "category": "System Information",
      "status": "info",
      "description": "Operating System: Windows 10 22H2",
      "details": {
        "version": "10.0.19045",
        "machine": "AMD64"
      }
    },
    {
      "category": "Registry Security",
      "status": "critical",
      "description": "PowerShell execution policy is too permissive: unrestricted",
      "details": null
    }
  ]
}
```

### HTML Report

Professional, responsive HTML report with dark theme:

![HTML Report Preview](docs/html-report-preview.png)

Features:
- Modern gradient design
- Summary cards with color coding
- Categorized findings with icons
- Status badges for quick scanning
- Responsive layout for all devices

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|:---------|:------------|:--------|
| `WINSEC_NO_COLOR` | Disable colored output | `false` |
| `WINSEC_VERBOSE` | Enable verbose logging | `false` |

### Exit Codes

| Code | Meaning |
|:----:|:--------|
| `0` | Success - no issues found |
| `1` | Warnings found (review recommended) |
| `2` | Critical issues found (immediate action required) |
| `130` | Scan interrupted by user |

## 📋 Requirements

### System Requirements

- **OS**: Windows 10, Windows 11, Windows Server 2016, 2019, 2022
- **Architecture**: x64 (64-bit)
- **Privileges**: Administrator rights recommended

### Python Dependencies

```
rich>=13.0.0
click>=8.0.0
psutil>=5.9.0
wmi>=1.5.1
colorama>=0.4.6
```

### Windows Features Required

- Windows Management Instrumentation (WMI)
- PowerShell 5.1 or higher
- Windows Event Log access (for event analysis)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Setting up the development environment
- Running tests
- Adding new security checks
- Code style requirements
- Pull request process

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built with:
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [Click](https://github.com/pallets/click) - Command-line interface framework
- [psutil](https://github.com/giampaolo/psutil) - System monitoring
- [WMI](https://pypi.org/project/WMI/) - Windows Management Instrumentation

---

<p align="center">
  Made with ❤️ for the Windows security community
</p>
