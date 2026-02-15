# Usage Examples

This document provides comprehensive, practical examples of using the Windows Security Auditor in various scenarios.

## 📋 Table of Contents

- [Basic Usage](#basic-usage)
- [Scan Types](#scan-types)
- [Output Formats](#output-formats)
- [Advanced Usage](#advanced-usage)
- [Automation Examples](#automation-examples)
- [CI/CD Integration](#cicd-integration)
- [Real-World Use Cases](#real-world-use-cases)
- [Sample Output](#sample-output)

## 🚀 Basic Usage

### Interactive Mode

Simply run without arguments to enter interactive mode:

```bash
winsec-audit
```

This presents a menu to select your scan type:

```
╭────────────── Select Scan Type ─────────────╮
│                                             │
│   1. Basic Scan    - Quick system overview  │
│   2. Full Scan     - Comprehensive audit    │
│                                             │
╰─────────────────────────────────────────────╯
Enter your choice [2]:
```

### Quick Basic Scan

Run a quick scan of essential security settings:

```bash
winsec-audit --scan basic
```

**Checks included:**
- System information and resource usage
- Windows Update status
- Firewall configuration

**When to use:** Quick health check of critical security settings

### Full Security Audit

Run a comprehensive security audit:

```bash
winsec-audit --scan full
```

**Checks included (11 total):**
1. System information and resources
2. Windows Update status
3. Firewall status (all profiles)
4. Autorun/startup programs
5. User accounts and privileges
6. Running services
7. Registry security (UAC, PowerShell)
8. Network security (ports, connections)
9. Security software status
10. Event log analysis

**When to use:** Complete security assessment, compliance checks

## 🔍 Scan Types

### List Available Checks

See all available security checks:

```bash
winsec-audit --list-checks
```

Output:
```
                        Available Security Checks
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
│ services     │ Running Services    │ full   │ Enumerate running system services      │
│ registry     │ Registry Security   │ full   │ Check registry security settings       │
│ network      │ Network Security    │ full   │ Check listening ports and active       │
│              │                     │        │ connections                            │
│ security_sw  │ Security Software   │ full   │ Check antivirus, firewall, and         │
│              │                     │        │ antispyware status                     │
│ events       │ Event Log Analysis  │ full   │ Analyze event logs for security        │
│              │                     │        │ threats                                │
└──────────────┴─────────────────────┴────────┴────────────────────────────────────────┘
```

### Run Specific Checks

Run only the checks you're interested in:

```bash
# Check firewall and network only
winsec-audit --check firewall,network

# Check user accounts and registry
winsec-audit --check users,registry

# Multiple checks
winsec-audit --check firewall,users,services,security_sw

# Focus on startup programs
winsec-audit --check autorun

# Security software only
winsec-audit --check security_sw
```

### Combining Check IDs

Available check IDs:
- `system` - System Information
- `updates` - Windows Updates
- `firewall` - Firewall Status
- `autorun` - Autorun Programs
- `users` - User Accounts
- `services` - Running Services
- `registry` - Registry Security
- `network` - Network Security
- `security_sw` - Security Software
- `events` - Event Log Analysis

## 📊 Output Formats

### Console Output (Default)

Rich, color-coded console output with tables and panels:

```bash
winsec-audit --scan full
```

### JSON Output

**Output to stdout:**
```bash
winsec-audit --scan full --json
```

**Save to file:**
```bash
winsec-audit --scan full --json results.json
```

**Pretty print with jq:**
```bash
winsec-audit --scan full --json | jq '.summary'
```

**Extract specific fields:**
```bash
# Get only critical findings
winsec-audit --scan full --json | jq '.findings[] | select(.status == "critical")'

# Count warnings by category
winsec-audit --scan full --json | jq '[.findings[] | select(.status == "warning")] | group_by(.category) | map({category: .[0].category, count: length})'
```

### HTML Report

Generate a beautiful HTML report:

```bash
winsec-audit --scan full --html security_report.html
```

Then open `security_report.html` in your browser:
```bash
start security_report.html  # Windows
```

### Combined Output

Generate multiple formats at once:

```bash
# Console + JSON + HTML
winsec-audit --scan full --json results.json --html report.html

# Silent JSON and HTML only (no console output)
winsec-audit --scan full --json results.json --html report.html --no-color > nul
```

## 🔧 Advanced Usage

### Verbose Mode

Get detailed error information:

```bash
winsec-audit --scan full --verbose
```

Useful for debugging failed checks or understanding scan progress.

### No Colors

Disable colored output (useful for logging to files):

```bash
winsec-audit --scan full --no-color > scan.log
```

Or set environment variable:
```bash
set WINSEC_NO_COLOR=1
winsec-audit --scan full
```

### Check Version

```bash
winsec-audit --version
```

Output:
```
winsec-audit, version 0.1.0
```

### Using Short Alias

The tool also registers a shorter alias:

```bash
wsa --scan basic
wsa --list-checks
```

## 🤖 Automation Examples

### Scheduled Task (Windows)

Create a scheduled task to run daily scans:

**Via PowerShell:**
```powershell
# Create daily security scan at 2 AM
$action = New-ScheduledTaskAction `
    -Execute "winsec-audit" `
    -Argument "--scan full --html C:\Reports\security_$(Get-Date -Format 'yyyyMMdd').html --json C:\Reports\security_$(Get-Date -Format 'yyyyMMdd').json"

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

$settings = New-ScheduledTaskSettingsSet `
    -RunOnlyIfNetworkAvailable `
    -WakeToRun

Register-ScheduledTask `
    -TaskName "DailySecurityAudit" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings

# Run the task immediately for testing
Start-ScheduledTask -TaskName "DailySecurityAudit"

# View task history
Get-ScheduledTaskInfo -TaskName "DailySecurityAudit"
```

**Via Command Prompt:**
```cmd
schtasks /create /tn "WeeklySecurityAudit" /tr "winsec-audit --scan full --html C:\Reports\weekly.html" /sc weekly /d SUN /st 03:00
```

### PowerShell Scripting

**Basic automation script:**
```powershell
# security_scan.ps1
param(
    [string]$OutputDir = "C:\SecurityReports",
    [string]$EmailTo = "admin@company.com"
)

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$htmlPath = Join-Path $OutputDir "security_audit_$date.html"
$jsonPath = Join-Path $OutputDir "security_audit_$date.json"

# Run the scan
Write-Host "Running security audit..." -ForegroundColor Cyan
winsec-audit --scan full --html $htmlPath --json $jsonPath

$exitCode = $LASTEXITCODE

# Load and analyze results
$results = Get-Content $jsonPath | ConvertFrom-Json

# Generate summary
$summary = @"
Windows Security Audit Complete
===============================
Generated: $($results.timestamp)
Total Findings: $($results.summary.total)
Secure: $($results.summary.ok)
Warnings: $($results.summary.warning)
Critical: $($results.summary.critical)

"@

# Check for critical issues
if ($results.summary.critical -gt 0) {
    Write-Host "CRITICAL: Found $($results.summary.critical) critical issues!" -ForegroundColor Red
    $criticalFindings = $results.findings | Where-Object { $_.status -eq "critical" }
    foreach ($finding in $criticalFindings) {
        Write-Host "  - [$($finding.category)] $($finding.description)" -ForegroundColor Red
    }
    
    # Send alert email
    Send-MailMessage `
        -To $EmailTo `
        -From "security@server.local" `
        -Subject "CRITICAL: Security Issues Detected on $env:COMPUTERNAME" `
        -Body $summary `
        -Attachments $htmlPath `
        -SmtpServer "your-smtp-server.com"
}
elseif ($results.summary.warning -gt 0) {
    Write-Host "WARNING: Found $($results.summary.warning) warnings." -ForegroundColor Yellow
}
else {
    Write-Host "SUCCESS: No security issues detected." -ForegroundColor Green
}

# Cleanup old reports (keep last 30 days)
Get-ChildItem $OutputDir -Filter "security_audit_*.html" | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force

exit $exitCode
```

**Run the script:**
```powershell
.\security_scan.ps1 -OutputDir "D:\Reports" -EmailTo "security@company.com"
```

### Python Scripting

**Basic automation:**
```python
#!/usr/bin/env python3
"""Security audit automation script."""

import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path


def run_security_scan(output_dir: str = "./reports") -> dict:
    """Run security audit and return results."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"audit_{timestamp}.json"
    html_file = output_path / f"audit_{timestamp}.html"
    
    # Run scan
    result = subprocess.run(
        [
            "winsec-audit",
            "--scan", "full",
            "--json", str(json_file),
            "--html", str(html_file)
        ],
        capture_output=True,
        text=True
    )
    
    # Load results
    data = json.loads(json_file.read_text())
    data['exit_code'] = result.returncode
    data['report_files'] = {
        'json': str(json_file),
        'html': str(html_file)
    }
    
    return data


def analyze_results(data: dict) -> None:
    """Analyze and display scan results."""
    summary = data['summary']
    
    print(f"\n{'='*50}")
    print("Security Audit Results")
    print(f"{'='*50}")
    print(f"Timestamp: {data['timestamp']}")
    print(f"Total Findings: {summary['total']}")
    print(f"✅ Secure: {summary['ok']}")
    print(f"⚠️  Warnings: {summary['warning']}")
    print(f"🚨 Critical: {summary['critical']}")
    
    # List critical issues
    if summary['critical'] > 0:
        print(f"\n🚨 CRITICAL ISSUES:")
        for finding in data['findings']:
            if finding['status'] == 'critical':
                print(f"  - [{finding['category']}] {finding['description']}")
    
    # List warnings
    if summary['warning'] > 0:
        print(f"\n⚠️  WARNINGS:")
        for finding in data['findings']:
            if finding['status'] == 'warning':
                print(f"  - [{finding['category']}] {finding['description']}")


def main():
    """Main function."""
    print("Starting security audit...")
    
    try:
        data = run_security_scan()
        analyze_results(data)
        
        # Return appropriate exit code
        sys.exit(data['exit_code'])
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Batch File Automation

**daily_scan.bat:**
```batch
@echo off
setlocal enabledelayedexpansion

:: Configuration
set REPORT_DIR=C:\SecurityReports
set DATE=%date:~-4,4%%date:~-10,2%%date:~-7,2%

:: Create report directory if it doesn't exist
if not exist %REPORT_DIR% mkdir %REPORT_DIR%

echo Running security audit...
winsec-audit --scan full --html %REPORT_DIR%\audit_%DATE%.html --json %REPORT_DIR%\audit_%DATE%.json

if %ERRORLEVEL% == 2 (
    echo CRITICAL ISSUES FOUND!
    echo Check report: %REPORT_DIR%\audit_%DATE%.html
    :: Add notification command here
    exit /b 2
) else if %ERRORLEVEL% == 1 (
    echo Warnings found - review recommended
    exit /b 1
) else (
    echo Scan completed successfully
    exit /b 0
)
```

## 🔄 CI/CD Integration

### GitHub Actions

**`.github/workflows/security-scan.yml`:**
```yaml
name: Security Audit

on:
  schedule:
    # Run weekly on Sundays at 3 AM UTC
    - cron: '0 3 * * 0'
  workflow_dispatch:  # Allow manual trigger

jobs:
  security-scan:
    runs-on: windows-latest
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
        
    - name: Install winsec-auditor
      run: pip install winsec-auditor
      
    - name: Run security audit
      run: |
        winsec-audit --scan full --json scan-results.json --html scan-report.html
      continue-on-error: true
      
    - name: Analyze results
      id: analyze
      run: |
        $results = Get-Content scan-results.json | ConvertFrom-Json
        echo "total=$($results.summary.total)" >> $env:GITHUB_OUTPUT
        echo "critical=$($results.summary.critical)" >> $env:GITHUB_OUTPUT
        echo "warning=$($results.summary.warning)" >> $env:GITHUB_OUTPUT
        
        if ($results.summary.critical -gt 0) {
          echo "status=failure" >> $env:GITHUB_OUTPUT
          exit 1
        } elseif ($results.summary.warning -gt 0) {
          echo "status=warning" >> $env:GITHUB_OUTPUT
        } else {
          echo "status=success" >> $env:GITHUB_OUTPUT
        }
      shell: pwsh
      continue-on-error: true
      
    - name: Upload scan results
      uses: actions/upload-artifact@v4
      with:
        name: security-scan-results
        path: |
          scan-results.json
          scan-report.html
        retention-days: 30
        
    - name: Create issue on critical findings
      if: steps.analyze.outputs.critical > 0
      uses: actions/github-script@v7
      with:
        script: |
          github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: `🚨 Critical Security Issues Detected - ${new Date().toISOString().split('T')[0]}`,
            body: `Critical security issues were detected during the automated scan.
            
            **Summary:**
            - Total Findings: ${{ steps.analyze.outputs.total }}
            - Critical: ${{ steps.analyze.outputs.critical }}
            - Warnings: ${{ steps.analyze.outputs.warning }}
            
            See the uploaded artifacts for the full report.`
          })
```

### Azure DevOps Pipeline

**`azure-pipelines.yml`:**
```yaml
trigger: none  # Only scheduled runs

schedules:
- cron: "0 3 * * 0"
  displayName: Weekly Security Audit
  branches:
    include:
    - main
  always: true

pool:
  vmImage: 'windows-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'
  displayName: 'Use Python 3.11'

- script: |
    pip install winsec-auditor
  displayName: 'Install Security Auditor'

- script: |
    winsec-audit --scan full --json $(Build.ArtifactStagingDirectory)\scan-results.json --html $(Build.ArtifactStagingDirectory)\scan-report.html
  displayName: 'Run Security Audit'
  continueOnError: true

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)'
    artifactName: 'security-scan'
  displayName: 'Publish Scan Results'

- powershell: |
    $results = Get-Content $(Build.ArtifactStagingDirectory)\scan-results.json | ConvertFrom-Json
    
    Write-Host "##vso[task.setvariable variable=CRITICAL_COUNT]$($results.summary.critical)"
    Write-Host "##vso[task.setvariable variable=WARNING_COUNT]$($results.summary.warning)"
    
    if ($results.summary.critical -gt 0) {
      Write-Error "Critical security issues found: $($results.summary.critical)"
    }
  displayName: 'Check Results'
```

### Jenkins Pipeline

**`Jenkinsfile`:**
```groovy
pipeline {
    agent { label 'windows' }
    
    triggers {
        cron('H 3 * * 0')  // Weekly on Sundays
    }
    
    stages {
        stage('Setup') {
            steps {
                bat 'pip install winsec-auditor'
            }
        }
        
        stage('Security Scan') {
            steps {
                bat '''
                    winsec-audit --scan full --json scan-results.json --html scan-report.html
                '''
                archiveArtifacts artifacts: 'scan-results.json,scan-report.html'
            }
        }
        
        stage('Analyze Results') {
            steps {
                script {
                    def results = readJSON file: 'scan-results.json'
                    def critical = results.summary.critical
                    def warning = results.summary.warning
                    
                    echo "Total Findings: ${results.summary.total}"
                    echo "Critical: ${critical}"
                    echo "Warning: ${warning}"
                    
                    if (critical > 0) {
                        currentBuild.result = 'FAILURE'
                        error "Critical security issues found: ${critical}"
                    } else if (warning > 0) {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }
    
    post {
        failure {
            emailext (
                subject: "CRITICAL: Security Audit Failed - ${env.JOB_NAME}",
                body: "Critical security issues were detected. See attached report.",
                to: "${env.CHANGE_AUTHOR_EMAIL}",
                attachmentsPattern: 'scan-report.html'
            )
        }
    }
}
```

## 💼 Real-World Use Cases

### 1. Compliance Auditing

**Scenario**: Monthly compliance check for SOX/PCI-DSS

```powershell
# compliance_check.ps1
$checks = @("firewall", "users", "registry", "security_sw", "events")
$date = Get-Date -Format "yyyy-MM-dd"
$report = "C:\Compliance\Reports\compliance_$date.html"

winsec-audit --check ($checks -join ",") --html $report

# Validate specific compliance requirements
$results = winsec-audit --check firewall,users,registry --json | ConvertFrom-Json

$complianceIssues = @()

# Check: Firewall must be enabled
$firewallOk = $results.findings | Where-Object { 
    $_.category -eq "Firewall" -and $_.description -like "*All firewall profiles are enabled*"
}
if (-not $firewallOk) {
    $complianceIssues += "Firewall not fully enabled"
}

# Check: Guest account must be disabled
$guestOk = $results.findings | Where-Object { 
    $_.category -eq "User Accounts" -and $_.description -eq "Guest account is disabled"
}
if (-not $guestOk) {
    $complianceIssues += "Guest account is enabled"
}

# Report
if ($complianceIssues.Count -eq 0) {
    Write-Host "✅ COMPLIANT: All checks passed" -ForegroundColor Green
} else {
    Write-Host "❌ NON-COMPLIANT: Issues found" -ForegroundColor Red
    $complianceIssues | ForEach-Object { Write-Host "  - $_" }
}
```

### 2. Incident Response

**Scenario**: Investigate potential compromise

```bash
# Focus on indicators of compromise
winsec-audit --check events,autorun,users,network --html incident_report.html

# Look specifically for:
# - Failed login attempts (brute force)
# - Suspicious startup programs
# - New administrator accounts
# - Unusual network connections
```

### 3. System Hardening Verification

**Scenario**: Verify system hardening after setup

```powershell
# hardening_check.ps1
param(
    [switch]$Strict
)

# Full scan with strict mode
winsec-audit --scan full --json hardening_results.json
$results = Get-Content hardening_results.json | ConvertFrom-Json

$hardeningRules = @{
    "FirewallEnabled" = ($results.findings | Where-Object { 
        $_.category -eq "Firewall" -and $_.description -like "*All firewall profiles are enabled*"
    }) -ne $null
    "GuestDisabled" = ($results.findings | Where-Object { 
        $_.category -eq "User Accounts" -and $_.description -eq "Guest account is disabled"
    }) -ne $null
    "UACEnabled" = ($results.findings | Where-Object { 
        $_.category -eq "Registry Security" -and $_.description -notlike "*disabled*"
    }) -ne $null
    "NoSuspiciousAutorun" = ($results.findings | Where-Object { 
        $_.category -eq "Autorun Programs" -and $_.status -eq "warning"
    }) -eq $null
}

Write-Host "\nHardening Verification Results:" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

$passed = 0
$failed = 0

foreach ($rule in $hardeningRules.GetEnumerator()) {
    if ($rule.Value) {
        Write-Host "✅ $($rule.Key): PASS" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "❌ $($rule.Key): FAIL" -ForegroundColor Red
        $failed++
    }
}

Write-Host "\nResults: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
exit $failed
```

### 4. Fleet Management

**Scenario**: Audit multiple systems and aggregate results

```powershell
# fleet_audit.ps1
$computers = @("SERVER01", "SERVER02", "WORKSTATION01", "WORKSTATION02")
$results = @()

foreach ($computer in $computers) {
    Write-Host "Scanning $computer..." -ForegroundColor Cyan
    
    $output = Invoke-Command -ComputerName $computer -ScriptBlock {
        winsec-audit --scan basic --json | ConvertFrom-Json
    } -ErrorAction SilentlyContinue
    
    if ($output) {
        $results += [PSCustomObject]@{
            Computer = $computer
            Total = $output.summary.total
            Critical = $output.summary.critical
            Warning = $output.summary.warning
            Secure = $output.summary.ok
        }
    } else {
        $results += [PSCustomObject]@{
            Computer = $computer
            Total = "N/A"
            Critical = "ERROR"
            Warning = "ERROR"
            Secure = "ERROR"
        }
    }
}

# Display summary table
$results | Format-Table -AutoSize

# Export to CSV
$results | Export-Csv -Path "fleet_audit_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

## 📊 Sample Output

### Console Summary Example

```
╭───────────────────────────────────────────────╮
│  🔐 Windows Security Audit Report             │
│  Generated: 2026-02-15T10:30:00               │
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
  ℹ System Uptime: 5 days, 12 hours

[bold green]Windows Updates[/bold green]
  ✅ System is up to date
  ✅ Windows Update service is running

[bold green]Firewall[/bold green]
  ✅ Domain Profile: Active
  ✅ Private Profile: Active
  ✅ Public Profile: Active
  ✅ All firewall profiles are enabled

[bold yellow]Autorun Programs[/bold yellow]
  ℹ Startup programs: 12 found
  ⚠ Suspicious startup entry: UpdateService
  ⚠ Found 1 potentially suspicious startup entries

[bold yellow]User Accounts[/bold yellow]
  ℹ Total user accounts: 5
  ℹ Active accounts: 4
  ℹ Disabled accounts: 1
  ℹ 2 accounts have administrator privileges
  ✅ Guest account is disabled

[bold green]Running Services[/bold green]
  ℹ Running services: 187 found
  ⚠ Remote Desktop Services is running (port 3389)

[bold yellow]Registry Security[/bold yellow]
  ✅ UAC is enabled
  🚨 PowerShell execution policy is too permissive: unrestricted

[bold green]Network Security[/bold green]
  ✅ No unusual listening ports detected
  ℹ Active connections: 42 found

[bold green]Security Software[/bold green]
  ✅ Active antivirus: Windows Defender
  ✅ Windows Firewall is active (3/3 profiles)
  ✅ Windows Defender Antispyware is enabled

[bold green]Event Log Analysis[/bold green]
  ✅ No security threats detected in recent event logs

[bold red]Scan complete! Found 1 critical issue(s) that need immediate attention.[/bold red]
```

### JSON Output Example

```json
{
  "timestamp": "2026-02-15T10:30:00",
  "scan_type": "full",
  "findings": [
    {
      "category": "System Information",
      "status": "info",
      "description": "Operating System: Windows 10 22H2",
      "details": {
        "version": "10.0.19045.3803",
        "machine": "AMD64"
      }
    },
    {
      "category": "System Information",
      "status": "ok",
      "description": "Disk Space (C:): 150.5 GB free of 500.0 GB (30% used)",
      "details": {
        "total_gb": 500.0,
        "free_gb": 150.5,
        "used_percent": 30
      }
    },
    {
      "category": "Registry Security",
      "status": "critical",
      "description": "PowerShell execution policy is too permissive: unrestricted",
      "details": null
    }
  ],
  "summary": {
    "total": 45,
    "info": 27,
    "ok": 12,
    "warning": 5,
    "critical": 1,
    "error": 0
  }
}
```

## 💡 Tips

1. **Run as Administrator** for best results - some checks require elevation
2. **Regular scans** - Schedule weekly or monthly full scans
3. **Review warnings** - Not all warnings are critical, but should be reviewed
4. **Keep updated** - Ensure Windows is updated for accurate update checks
5. **Document changes** - Use `--html` reports to document security posture over time
6. **Monitor trends** - Compare JSON outputs over time to track improvements
7. **Integrate early** - Add to CI/CD pipelines for proactive security
8. **Backup reports** - Keep historical reports for compliance and forensics

---

For more information, see the [README.md](../README.md) or visit the [GitHub repository](https://github.com/yourusername/winsec-auditor).
