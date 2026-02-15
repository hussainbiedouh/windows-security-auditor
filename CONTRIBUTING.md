# Contributing to Windows Security Auditor

Thank you for your interest in contributing to Windows Security Auditor! This document provides comprehensive guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Adding New Checks](#adding-new-checks)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## 🤝 Code of Conduct

This project and everyone participating in it is governed by our commitment to:

- Being respectful and constructive in all interactions
- Welcoming newcomers and helping them learn
- Focusing on what is best for the community and users
- Showing empathy towards others

## 🚀 How to Contribute

### Reporting Bugs

Before creating a bug report, please:

1. **Check existing issues** to avoid duplicates
2. **Use the latest version** to verify the bug still exists
3. **Collect relevant information** about your environment

**Bug Report Template:**

```markdown
**Environment:**
- OS Version: e.g., Windows 11 23H2 (Build 22631.3007)
- Python Version: e.g., 3.11.4
- Tool Version: e.g., 0.1.0
- Installation Method: pip / source

**Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Run command '...'
2. Select option '...'
3. See error

**Expected Behavior:**
What you expected to happen

**Actual Behavior:**
What actually happened

**Screenshots/Logs:**
If applicable, add screenshots or console output
```

### Suggesting Features

Feature requests are welcome! Please provide:

- **Clear use case**: Why is this feature needed?
- **Expected behavior**: How should it work?
- **Potential implementation**: Any ideas on how to build it?
- **Alternatives considered**: What else did you consider?

### Improving Documentation

Documentation improvements are always appreciated:

- Fix typos or unclear explanations
- Add more examples
- Improve code comments
- Add diagrams or screenshots

## 🛠️ Development Setup

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- Python 3.9 or higher
- Git

### Setting Up Your Environment

```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/winsec-auditor.git
cd winsec-auditor

# 3. Create a virtual environment
python -m venv .venv

# 4. Activate the virtual environment
.venv\Scripts\activate  # Windows

# 5. Install in editable mode with dev dependencies
pip install -e ".[dev]"

# 6. Verify installation
winsec-audit --version
```

### Project Structure

```
winsec-auditor/
├── src/
│   └── winsec_auditor/
│       ├── __init__.py          # Version info
│       ├── __main__.py          # Entry point
│       ├── cli.py               # CLI implementation
│       ├── scanner.py           # Scan orchestration
│       ├── report.py            # Report generation
│       ├── types.py             # Type definitions
│       ├── utils.py             # Utilities
│       └── checks/              # Security checks
│           ├── __init__.py      # Check registry
│           ├── system.py
│           ├── updates.py
│           ├── firewall.py
│           ├── autorun.py
│           ├── users.py
│           ├── services.py
│           ├── registry.py
│           ├── network.py
│           ├── security_sw.py
│           └── events.py
├── tests/                       # Test suite
│   ├── conftest.py
│   ├── test_cli.py
│   ├── test_scanner.py
│   └── test_checks/
├── docs/                        # Documentation
├── pyproject.toml              # Project configuration
└── README.md
```

## 🎨 Code Style

We use modern Python tooling to maintain code quality:

### Tools

- **ruff**: Linting and import sorting
- **ruff format**: Code formatting
- **mypy**: Type checking

### Running Code Quality Checks

```bash
# Run linter
ruff check src/

# Fix auto-fixable linting issues
ruff check --fix src/

# Format code
ruff format src/

# Type checking
mypy src/winsec_auditor

# Run all checks (do this before committing)
ruff check src/ && ruff format --check src/ && mypy src/winsec_auditor
```

### Style Guidelines

1. **Follow PEP 8** with these specific rules:
   - Line length: 100 characters maximum
   - Use double quotes for strings
   - Use trailing commas in multi-line collections

2. **Type Hints**:
   - Add type hints to all function parameters and return types
   - Use `typing.TYPE_CHECKING` for imports only used for type hints
   - Use modern syntax: `list[str]` instead of `List[str]`

3. **Docstrings**:
   - Use Google-style docstrings
   - Document all public functions and classes
   - Include Args and Returns sections

   ```python
   def check_firewall() -> list["SecurityFinding"]:
       """Check Windows Firewall status for all profiles.
       
       Returns:
           List of security findings with firewall status.
       """
   ```

4. **Error Handling**:
   - Use try-except blocks for external calls (WMI, PowerShell)
   - Log errors with meaningful messages
   - Return findings even on partial failures

## 🔧 Adding New Checks

Adding a new security check is straightforward:

### Step 1: Create the Check Module

Create a new file in `src/winsec_auditor/checks/`:

```python
"""Description of what this check does."""

from typing import TYPE_CHECKING

from winsec_auditor.utils import run_powershell

if TYPE_CHECKING:
    from winsec_auditor.types import SecurityFinding


def check_my_feature() -> list["SecurityFinding"]:
    """Brief description of the check.
    
    More detailed description explaining what is being checked
    and why it matters for security.
    
    Returns:
        List of security findings.
    """
    findings: list["SecurityFinding"] = []
    
    try:
        # Your check logic here
        success, output = run_powershell("Your-Command-Here", timeout=30)
        
        if success:
            # Analyze output
            if is_secure:
                findings.append({
                    "category": "My Feature",
                    "status": "ok",
                    "description": "Everything is secure",
                    "details": {"key": "value"},
                })
            else:
                findings.append({
                    "category": "My Feature",
                    "status": "warning",  # or "critical"
                    "description": "Issue detected: ...",
                    "details": {"key": "value"},
                })
        else:
            findings.append({
                "category": "My Feature",
                "status": "error",
                "description": "Could not retrieve feature status",
                "details": None,
            })
    except Exception as e:
        findings.append({
            "category": "My Feature",
            "status": "error",
            "description": f"Check failed: {e}",
            "details": None,
        })
    
    return findings
```

### Step 2: Register the Check

Add your check to `src/winsec_auditor/checks/__init__.py`:

```python
from winsec_auditor.checks import (
    # ... existing imports ...
    my_feature,  # Add your import
)

AVAILABLE_CHECKS: dict[str, dict[str, any]] = {
    # ... existing checks ...
    "my_feature": {
        "name": "My Feature Check",
        "description": "Brief description of what this check does",
        "scan_type": "full",  # or "basic"
        "function": my_feature.check_my_feature,
    },
}
```

### Step 3: Add Tests

Create tests in `tests/test_checks/`:

```python
"""Tests for my_feature check."""

import pytest
from unittest.mock import patch, MagicMock

from winsec_auditor.checks.my_feature import check_my_feature


class TestMyFeatureCheck:
    """Test cases for my_feature security check."""

    def test_check_my_feature_success(self):
        """Test successful check returns findings."""
        with patch('winsec_auditor.checks.my_feature.run_powershell') as mock_run:
            mock_run.return_value = (True, "Secure output")
            
            findings = check_my_feature()
            
            assert len(findings) > 0
            assert any(f['category'] == 'My Feature' for f in findings)

    def test_check_my_feature_failure(self):
        """Test failed command handling."""
        with patch('winsec_auditor.checks.my_feature.run_powershell') as mock_run:
            mock_run.return_value = (False, "")
            
            findings = check_my_feature()
            
            assert any(f['status'] == 'error' for f in findings)

    def test_check_my_feature_exception(self):
        """Test exception handling."""
        with patch('winsec_auditor.checks.my_feature.run_powershell') as mock_run:
            mock_run.side_effect = Exception("Test error")
            
            findings = check_my_feature()
            
            assert any(f['status'] == 'error' for f in findings)
```

### Step 4: Update Documentation

- Add the check to the security checks table in README.md
- Add usage examples to docs/USAGE_EXAMPLES.md
- Update CHANGELOG.md

### Check Development Best Practices

1. **Always handle exceptions** - Don't let one check crash the entire scan
2. **Use timeouts** - External commands should have reasonable timeouts
3. **Provide meaningful details** - Include relevant data in the details field
4. **Use appropriate status levels**:
   - `ok`: Configuration is secure
   - `warning`: Something to review, not critical
   - `critical`: Security risk requiring immediate attention
   - `error`: Check couldn't complete
   - `info`: Informational only
5. **Mock external dependencies in tests** - Don't actually run PowerShell/WMI in unit tests

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=winsec_auditor --cov-report=term-missing

# Run specific test file
pytest tests/test_checks/test_my_feature.py

# Run with verbose output
pytest -v

# Run only failed tests
pytest --lf
```

### Writing Tests

1. **Mock external dependencies**:
   ```python
   with patch('winsec_auditor.checks.system.run_powershell') as mock_ps:
       mock_ps.return_value = (True, "Mock output")
       # Your test here
   ```

2. **Test both success and failure cases**

3. **Use descriptive test names**:
   ```python
   def test_check_firewall_all_enabled_returns_ok():
       """Test that all enabled firewalls return ok status."""
   ```

4. **Keep tests focused** - One concept per test

### Test Coverage

Aim for high coverage on core logic. Run:

```bash
pytest --cov=winsec_auditor --cov-report=html
```

Then open `htmlcov/index.html` to see coverage details.

## 📝 Pull Request Process

### Before Creating a PR

1. **Run all checks**:
   ```bash
   ruff check src/ && ruff format --check src/ && mypy src/winsec_auditor && pytest
   ```

2. **Update documentation**:
   - README.md if adding features
   - CHANGELOG.md under [Unreleased]
   - docs/USAGE_EXAMPLES.md if relevant

3. **Add/update tests** for new functionality

### Creating a PR

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes** with clear, focused commits

3. **Commit messages** should be descriptive:
   ```
   Add new check for Windows Defender exclusions
   
   - Checks for paths excluded from Windows Defender scanning
   - Flags potentially dangerous exclusions
   - Includes tests and documentation
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```

5. **Create Pull Request** on GitHub with:
   - Clear title and description
   - Reference any related issues
   - Include screenshots if UI changes
   - Checklist showing tests pass

### PR Review Process

- Maintainers will review within a few days
- Address review comments with additional commits
- Once approved, a maintainer will merge

### PR Checklist

```markdown
## PR Checklist

- [ ] Tests pass locally (`pytest`)
- [ ] Code follows style guidelines (`ruff check src/`)
- [ ] Code is formatted (`ruff format src/`)
- [ ] Type checking passes (`mypy src/winsec_auditor`)
- [ ] Docstrings added/updated for new functions
- [ ] CHANGELOG.md updated
- [ ] README.md updated if needed
- [ ] Tests added for new functionality
- [ ] All checks run on Windows
```

## 🏷️ Release Process

1. Update version in `src/winsec_auditor/__init__.py`
2. Update CHANGELOG.md with release date
3. Create a git tag: `git tag v0.2.0`
4. Push tag: `git push origin v0.2.0`
5. Create GitHub release with notes from CHANGELOG

## 💬 Questions?

- **General questions**: Open a GitHub Discussion
- **Bug reports**: Open an issue using the template
- **Feature requests**: Open an issue using the template
- **Security issues**: Email security@example.com (do not open public issue)

## 🎉 Thank You!

Every contribution, whether it's:
- Reporting a bug
- Suggesting a feature
- Writing code
- Improving documentation
- Helping others in issues

...makes Windows Security Auditor better for everyone. Thank you for contributing! 🙏
