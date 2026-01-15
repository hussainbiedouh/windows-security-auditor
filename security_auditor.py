#!/usr/bin/env python3
"""
Windows System Security Auditor CLI
A tool to scan Windows systems for security misconfigurations and vulnerabilities
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime

try:
    import wmi
    import psutil
except ImportError:
    print("Required modules not found. Please run: pip install -r requirements.txt")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Windows System Security Auditor')
    parser.add_argument('--scan', choices=['basic', 'full'], default='basic',
                        help='Type of security scan to perform')
    parser.add_argument('--output', type=str, help='Output file for results')
    parser.add_argument('--format', choices=['json', 'text'], default='text',
                        help='Output format')
    
    args = parser.parse_args()
    
    print("Windows System Security Auditor")
    print("=" * 40)
    
    if platform.system() != 'Windows':
        print("This tool is designed for Windows systems only.")
        sys.exit(1)
    
    results = perform_scan(args.scan)
    
    if args.output:
        save_results(results, args.output, args.format)
    else:
        display_results(results, args.format)


def perform_scan(scan_type):
    """Perform security scan based on type"""
    results = {
        'timestamp': datetime.now().isoformat(),
        'scan_type': scan_type,
        'findings': []
    }
    
    # Basic system information
    results['findings'].extend(get_system_info())
    
    # Check Windows updates
    results['findings'].extend(check_windows_updates())
    
    # Check firewall status
    results['findings'].extend(check_firewall_status())
    
    if scan_type == 'full':
        # Full scan checks
        results['findings'].extend(check_autorun_programs())
        results['findings'].extend(check_user_accounts())
        results['findings'].extend(check_services())
    
    return results

def get_system_info():
    """Get basic system information"""
    findings = []
    findings.append({
        'category': 'System Information',
        'status': 'info',
        'description': f'Operating System: {platform.system()} {platform.release()}',
    })
    findings.append({
        'category': 'System Information',
        'status': 'info',
        'description': f'Architecture: {platform.architecture()[0]}',
    })
    findings.append({
        'category': 'System Information',
        'status': 'info',
        'description': f'Processor: {platform.processor()}',
    })
    
    # Disk usage
    disk_usage = psutil.disk_usage('C:')
    total_gb = disk_usage.total / (1024**3)
    findings.append({
        'category': 'System Information',
        'status': 'info',
        'description': f'Disk Space (C:): Total {total_gb:.2f} GB',
    })
    
    return findings

def check_windows_updates():
    """Check Windows Update status"""
    findings = []
    try:
        # Using PowerShell to check Windows Update status
        result = subprocess.run(
            ['powershell', 'Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object -Property HotFixID, Description, InstalledOn | Format-Table -AutoSize'],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0:
            updates = len(result.stdout.strip().split('\n')) - 2  # Subtract header lines
            findings.append({
                'category': 'Windows Updates',
                'status': 'info',
                'description': f'Installed updates: {updates} (recent)',
            })
        else:
            findings.append({
                'category': 'Windows Updates',
                'status': 'warning',
                'description': 'Could not retrieve Windows Update history',
            })
    except Exception as e:
        findings.append({
            'category': 'Windows Updates',
            'status': 'error',
            'description': f'Error checking Windows Updates: {str(e)}',
        })
    
    return findings

def check_firewall_status():
    """Check Windows Firewall status"""
    findings = []
    try:
        # Using netsh to check firewall status
        result = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            output = result.stdout
            profiles = ['Domain Profile', 'Private Profile', 'Public Profile']
            
            for profile in profiles:
                if profile in output:
                    status_start = output.find(profile)
                    status_end = output.find('\n', status_start)
                    profile_section = output[status_start:status_end]
                    
                    if 'ON' in profile_section.upper():
                        findings.append({
                            'category': 'Firewall',
                            'status': 'ok',
                            'description': f'{profile}: Active',
                        })
                    else:
                        findings.append({
                            'category': 'Firewall',
                            'status': 'warning',
                            'description': f'{profile}: Inactive',
                        })
        else:
            findings.append({
                'category': 'Firewall',
                'status': 'error',
                'description': 'Could not retrieve firewall status',
            })
    except Exception as e:
        findings.append({
            'category': 'Firewall',
            'status': 'error',
            'description': f'Error checking firewall: {str(e)}',
        })
    
    return findings

def check_autorun_programs():
    """Check programs that run at startup"""
    findings = []
    try:
        # Using wmic to get startup programs
        result = subprocess.run(
            ['wmic', 'startup', 'get', 'caption,command,user', '/format:list'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            startups = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            startup_count = len(startups)
            findings.append({
                'category': 'Autorun Programs',
                'status': 'info',
                'description': f'Startup programs: {startup_count} found',
            })
        else:
            findings.append({
                'category': 'Autorun Programs',
                'status': 'error',
                'description': 'Could not retrieve autorun programs',
            })
    except Exception as e:
        findings.append({
            'category': 'Autorun Programs',
            'status': 'error',
            'description': f'Error checking autorun programs: {str(e)}',
        })
    
    return findings

def check_user_accounts():
    """Check user accounts on the system"""
    findings = []
    try:
        # Using wmic to get user accounts
        result = subprocess.run(
            ['wmic', 'useraccount', 'get', 'name,sid,disabled,lockout,status', '/format:list'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            accounts = [line.strip() for line in result.stdout.split('\n') if 'Name=' in line]
            findings.append({
                'category': 'User Accounts',
                'status': 'info',
                'description': f'Total user accounts: {len(accounts)}',
            })
        else:
            findings.append({
                'category': 'User Accounts',
                'status': 'error',
                'description': 'Could not retrieve user accounts',
            })
    except Exception as e:
        findings.append({
            'category': 'User Accounts',
            'status': 'error',
            'description': f'Error checking user accounts: {str(e)}',
        })
    
    return findings

def check_services():
    """Check system services"""
    findings = []
    try:
        # Using wmic to get services
        result = subprocess.run(
            ['wmic', 'service', 'where', "State='Running'", 'get', 'name,processid,startmode,pathname', '/format:list'],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            services = [line.strip() for line in result.stdout.split('\n') if 'Name=' in line]
            findings.append({
                'category': 'Services',
                'status': 'info',
                'description': f'Running services: {len(services)}',
            })
        else:
            findings.append({
                'category': 'Services',
                'status': 'error',
                'description': 'Could not retrieve services',
            })
    except Exception as e:
        findings.append({
            'category': 'Services',
            'status': 'error',
            'description': f'Error checking services: {str(e)}',
        })
    
    return findings


def display_results(results, format_type):
    """Display scan results"""
    if format_type == 'json':
        print(json.dumps(results, indent=2))
    else:
        print(f"Scan performed at: {results['timestamp']}")
        print(f"Scan type: {results['scan_type']}")
        print("\nFindings:")
        current_category = None
        for finding in results['findings']:
            if finding['category'] != current_category:
                current_category = finding['category']
                print(f"\n[{finding['category']}]\n{'-' * len(finding['category'])}")
            status_icon = {
                'ok': '[✓]',
                'info': '[i]',
                'warning': '[!]',
                'error': '[✗]'
            }.get(finding['status'], '[?]')
            print(f"  {status_icon} {finding['description']}")


def save_results(results, output_file, format_type):
    """Save results to file"""
    if format_type == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        with open(output_file, 'w') as f:
            f.write(f"Security Audit Report\n")
            f.write(f"Generated: {results['timestamp']}\n")
            f.write(f"Scan Type: {results['scan_type']}\n")
            f.write(f"\nFindings:\n")
            current_category = None
            for finding in results['findings']:
                if finding['category'] != current_category:
                    current_category = finding['category']
                    f.write(f"\n[{finding['category']}]\n{'-' * len(finding['category'])}\n")
                status_icon = {
                    'ok': '[✓]',
                    'info': '[i]',
                    'warning': '[!]',
                    'error': '[✗]'
                }.get(finding['status'], '[?]')
                f.write(f"  {status_icon} {finding['description']}\n")
    
    print(f"Results saved to {output_file}")


if __name__ == '__main__':
    main()