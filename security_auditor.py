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
    import winreg
    from colorama import init, Fore, Back, Style
    # Initialize colorama for cross-platform colored output
    init(autoreset=True)
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
        results['findings'].extend(check_registry_security())
        results['findings'].extend(check_network_security())
        results['findings'].extend(check_security_software())
    
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
        # First try with PowerShell (more likely to be available)
        result_ps = subprocess.run(
            ['powershell', '-Command', 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command | Format-List'],
            capture_output=True, text=True, timeout=30
        )
        
        if result_ps.returncode == 0 and result_ps.stdout.strip():
            lines = result_ps.stdout.split('\n')
            command_lines = [line for line in lines if line.strip().startswith('Command')]
            startup_count = len(command_lines)
            findings.append({
                'category': 'Autorun Programs',
                'status': 'info',
                'description': f'Startup programs: {startup_count} found (via PowerShell)',
            })
        else:
            # Fallback to wmic if PowerShell fails
            result = subprocess.run(
                ['wmic', 'startup', 'get', 'caption,command,user', '/format=list'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0 and 'Caption' in result.stdout:  # Check if command worked
                startups = [line.strip() for line in result.stdout.split('\n') if line.strip() and '=' in line]
                startup_count = len(startups)
                findings.append({
                    'category': 'Autorun Programs',
                    'status': 'info',
                    'description': f'Startup programs: {startup_count} found',
                })
            else:
                findings.append({
                    'category': 'Autorun Programs',
                    'status': 'warning',
                    'description': 'Could not retrieve autorun programs (WMIC/Powershell not available)',
                })
    except subprocess.TimeoutExpired:
        findings.append({
            'category': 'Autorun Programs',
            'status': 'warning',
            'description': 'Timeout retrieving autorun programs',
        })
    except Exception as e:
        findings.append({
            'category': 'Autorun Programs',
            'status': 'warning',
            'description': f'Error checking autorun programs: {str(e)}',
        })
    
    return findings

def check_user_accounts():
    """Check user accounts on the system"""
    findings = []
    try:
        # First try with PowerShell (more likely to be available)
        result_ps = subprocess.run(
            ['powershell', '-Command', 'Get-LocalUser | Select-Object Name, Enabled, LastLogon, SID | Format-List'],
            capture_output=True, text=True, timeout=30
        )
        
        if result_ps.returncode == 0 and result_ps.stdout.strip():
            lines = result_ps.stdout.split('\n')
            
            # Parse the output to extract user information
            users_data = []
            current_user = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('Name') and ':' in line:
                    if current_user and 'Name' in current_user:
                        users_data.append(current_user)
                    current_user = {'Name': line.split(':', 1)[1].strip()}
                elif line.startswith('Enabled') and ':' in line:
                    current_user['Enabled'] = line.split(':', 1)[1].strip()
                elif line.startswith('LastLogon') and ':' in line:
                    last_logon = line.split(':', 1)[1].strip()
                    current_user['LastLogon'] = last_logon if last_logon != '' else 'Never'
                elif line.startswith('SID') and ':' in line:
                    current_user['SID'] = line.split(':', 1)[1].strip()
            
            # Add the last user
            if current_user and 'Name' in current_user:
                users_data.append(current_user)
            
            findings.append({
                'category': 'User Accounts',
                'status': 'info',
                'description': f'Total user accounts: {len(users_data)} (via PowerShell)',
            })
            
            # Check for currently logged in users
            try:
                # Use qwinsta to check for active sessions
                result_sessions = subprocess.run(
                    ['qwinsta'],
                    capture_output=True, text=True, timeout=10
                )
                if result_sessions.returncode == 0 and result_sessions.stdout.strip():
                    lines = result_sessions.stdout.split('\n')[1:]  # Skip header
                    active_users = []
                    for line in lines:
                        if line.strip():
                            # Parse qwinsta output to get session info
                            parts = line.split()
                            if len(parts) >= 2:
                                username = parts[0].strip()
                                if username.lower() != '>services' and username != '.':
                                    active_users.append(username)
                    
                    if active_users:
                        findings.append({
                            'category': 'User Accounts',
                            'status': 'info',
                            'description': f'Currently active users: {", ".join(active_users)}',
                        })
            except Exception:
                # Fallback to whoami command
                try:
                    current_user_result = subprocess.run(
                        ['whoami'],
                        capture_output=True, text=True, timeout=10
                    )
                    if current_user_result.returncode == 0:
                        current_user = current_user_result.stdout.strip()
                        findings.append({
                            'category': 'User Accounts',
                            'status': 'info',
                            'description': f'Current user context: {current_user}',
                        })
                except Exception:
                    pass
            
            # Report on accounts with last login information
            active_accounts = [user for user in users_data if user.get('Enabled', '').upper() == 'TRUE']
            inactive_accounts = [user for user in users_data if user.get('Enabled', '').upper() != 'TRUE']
            
            if active_accounts:
                findings.append({
                    'category': 'User Accounts',
                    'status': 'info',
                    'description': f'Active accounts: {len(active_accounts)}',
                })
            
            if inactive_accounts:
                findings.append({
                    'category': 'User Accounts',
                    'status': 'info',
                    'description': f'Disabled accounts: {len(inactive_accounts)}',
                })
        else:
            # Fallback to wmic if PowerShell fails
            result = subprocess.run(
                ['wmic', 'useraccount', 'get', 'name,sid,disabled,lockout,status', '/format=list'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0 and 'Name=' in result.stdout:
                accounts = [line.strip() for line in result.stdout.split('\n') if 'Name=' in line]
                findings.append({
                    'category': 'User Accounts',
                    'status': 'info',
                    'description': f'Total user accounts: {len(accounts)}',
                })
            else:
                findings.append({
                    'category': 'User Accounts',
                    'status': 'warning',
                    'description': 'Could not retrieve user accounts (WMIC/Powershell not available)',
                })
    except subprocess.TimeoutExpired:
        findings.append({
            'category': 'User Accounts',
            'status': 'warning',
            'description': 'Timeout retrieving user accounts',
        })
    except Exception as e:
        findings.append({
            'category': 'User Accounts',
            'status': 'warning',
            'description': f'Error checking user accounts: {str(e)}',
        })
    
    return findings

def check_services():
    """Check system services"""
    findings = []
    try:
        # First try with PowerShell (more likely to be available)
        result_ps = subprocess.run(
            ['powershell', '-Command', 'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, Status | Measure-Object'],
            capture_output=True, text=True, timeout=30
        )
        
        if result_ps.returncode == 0 and result_ps.stdout.strip():
            # Extract count from PowerShell output
            lines = result_ps.stdout.split('\n')
            count_line = [line for line in lines if 'Count' in line and ':' in line]
            if count_line:
                count = count_line[0].split(':')[-1].strip()
                findings.append({
                    'category': 'Services',
                    'status': 'info',
                    'description': f'Running services: {count} (via PowerShell)',
                })
            else:
                findings.append({
                    'category': 'Services',
                    'status': 'info',
                    'description': 'Running services: count unavailable',
                })
        else:
            # Fallback to wmic if PowerShell fails
            result = subprocess.run(
                ['wmic', 'service', 'where', "State='Running'", 'get', 'name,processid,startmode,pathname', '/format=list'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0 and 'Name=' in result.stdout:
                services = [line.strip() for line in result.stdout.split('\n') if 'Name=' in line]
                findings.append({
                    'category': 'Services',
                    'status': 'info',
                    'description': f'Running services: {len(services)}',
                })
            else:
                findings.append({
                    'category': 'Services',
                    'status': 'warning',
                    'description': 'Could not retrieve services (WMIC/Powershell not available)',
                })
    except subprocess.TimeoutExpired:
        findings.append({
            'category': 'Services',
            'status': 'warning',
            'description': 'Timeout retrieving services',
        })
    except Exception as e:
        findings.append({
            'category': 'Services',
            'status': 'warning',
            'description': f'Error checking services: {str(e)}',
        })
    
    return findings

def check_registry_security():
    """Check important registry security settings"""
    findings = []
    
    # Check if UAC is enabled
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, reg_type = winreg.QueryValueEx(key, "EnableLUA")
                if value == 1:
                    findings.append({
                        'category': 'Registry Security',
                        'status': 'ok',
                        'description': 'UAC (User Account Control) is enabled',
                    })
                else:
                    findings.append({
                        'category': 'Registry Security',
                        'status': 'warning',
                        'description': 'UAC (User Account Control) is disabled',
                    })
            except FileNotFoundError:
                findings.append({
                    'category': 'Registry Security',
                    'status': 'warning',
                    'description': 'UAC registry key not found',
                })
    except Exception as e:
        findings.append({
            'category': 'Registry Security',
            'status': 'warning',
            'description': f'Error checking UAC setting: {str(e)}',
        })
    
    # Check if PowerShell execution policy is restricted
    try:
        result = subprocess.run(
            ['powershell', 'Get-ExecutionPolicy'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            policy = result.stdout.strip().lower()
            if policy in ['restricted', 'allsigned']:
                findings.append({
                    'category': 'Registry Security',
                    'status': 'ok',
                    'description': f'PowerShell execution policy is restrictive: {policy}',
                })
            elif policy in ['remotesigned', 'unrestricted']:
                findings.append({
                    'category': 'Registry Security',
                    'status': 'warning',
                    'description': f'PowerShell execution policy is permissive: {policy}',
                })
        else:
            findings.append({
                'category': 'Registry Security',
                'status': 'warning',
                'description': 'Could not determine PowerShell execution policy',
            })
    except Exception as e:
        findings.append({
            'category': 'Registry Security',
            'status': 'warning',
            'description': f'Error checking PowerShell execution policy: {str(e)}',
        })
    
    return findings

def check_network_security():
    """Check network-related security settings"""
    findings = []
    
    # Get listening ports
    try:
        result = subprocess.run(
            ['netstat', '-an'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            listening_ports = [line for line in lines if 'LISTEN' in line]
            
            # Filter out common safe ports
            potentially_risky_ports = []
            for line in listening_ports:
                # Extract port number
                parts = line.split()
                if len(parts) >= 2:
                    local_address = parts[1]
                    port_str = local_address.split(':')[-1]
                    try:
                        port = int(port_str)
                        # Common potentially risky ports (FTP, Telnet, RDP, SMB, etc.)
                        risky_port_ranges = [20, 21, 23, 25, 110, 135, 137, 138, 139, 445, 993, 995, 3389, 5900]
                        if port in risky_port_ranges:
                            potentially_risky_ports.append(str(port))
                    except ValueError:
                        continue
            
            if potentially_risky_ports:
                findings.append({
                    'category': 'Network Security',
                    'status': 'warning',
                    'description': f'Potentially risky ports are listening: {", ".join(potentially_risky_ports)}',
                })
            else:
                findings.append({
                    'category': 'Network Security',
                    'status': 'info',
                    'description': f'{len(listening_ports)} ports are listening (no common risky ports detected)',
                })
        else:
            findings.append({
                'category': 'Network Security',
                'status': 'warning',
                'description': 'Could not retrieve network listening ports',
            })
    except Exception as e:
        findings.append({
            'category': 'Network Security',
            'status': 'warning',
            'description': f'Error checking network ports: {str(e)}',
        })
    
    # Check for established connections
    try:
        result = subprocess.run(
            ['netstat', '-an'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            established_connections = [line for line in lines if 'ESTABLISHED' in line]
            findings.append({
                'category': 'Network Security',
                'status': 'info',
                'description': f'{len(established_connections)} active connections',
            })
        else:
            findings.append({
                'category': 'Network Security',
                'status': 'warning',
                'description': 'Could not retrieve active connections',
            })
    except Exception as e:
        findings.append({
            'category': 'Network Security',
            'status': 'warning',
            'description': f'Error checking active connections: {str(e)}',
        })
    
    return findings

def check_security_software():
    """Check for installed security software"""
    findings = []
    
    # Check for installed antivirus software using PowerShell
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntivirusProduct'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            # More robust parsing of WMI output
            output = result.stdout
            
            # Split output into sections based on the object boundaries
            lines = output.split('\n')
            
            # Variables to hold current object properties
            current_display_name = None
            current_product_state = None
            av_objects = []
            
            for line in lines:
                line_lower = line.lower()
                
                # Check if this line contains a display name
                if 'displayname' in line_lower and ':' in line:
                    current_display_name = line.split(':', 1)[-1].strip()
                
                # Check if this line contains a product state
                elif 'productstate' in line_lower and ':' in line:
                    try:
                        current_product_state = int(line.split(':', 1)[-1].strip())
                    except ValueError:
                        current_product_state = None
                
                # If we have both name and state, store the object and reset
                if current_display_name and current_product_state is not None:
                    av_objects.append({'name': current_display_name, 'state': current_product_state})
                    current_display_name = None
                    current_product_state = None
            
            # Determine which antivirus products are active based on their states
            active_avs = []
            inactive_avs = []
            
            for obj in av_objects:
                name = obj['name']
                state = obj['state']
                
                # Define active states
                # 266240 = Running with up-to-date signatures
                # 266496 = Running with out-of-date signatures
                # 393472 = Windows Defender specific state (running with up-to-date signatures)
                if state in [266240, 266496, 393472]:
                    active_avs.append(name)
                else:
                    inactive_avs.append(f"{name} (state: {state})")
            
            if active_avs:
                # Remove duplicates while preserving order
                seen = set()
                unique_active_avs = []
                for av in active_avs:
                    if av not in seen:
                        seen.add(av)
                        unique_active_avs.append(av)
                findings.append({
                    'category': 'Security Software',
                    'status': 'ok',
                    'description': f'Active antivirus software: {", ".join(unique_active_avs)}',
                })
            elif av_objects:
                # There are AV products but none are active
                names_only = [obj['name'] for obj in av_objects]
                # Remove duplicates while preserving order
                seen = set()
                unique_names_only = []
                for name in names_only:
                    if name not in seen:
                        seen.add(name)
                        unique_names_only.append(name)
                findings.append({
                    'category': 'Security Software',
                    'status': 'warning',
                    'description': f'Antivirus software installed but may not be active: {", ".join(unique_names_only)}',
                })
            else:
                # Alternative method to check Windows Defender specifically
                defender_result = subprocess.run(
                    ['powershell', '-Command', 'Get-MpComputerStatus'],
                    capture_output=True, text=True, timeout=15
                )
                # Check if Defender is actually enabled based on specific property values
                if ('True' in defender_result.stdout and 'Enabled' in defender_result.stdout) or \
                   ('antivirusenabled' in defender_result.stdout.lower() and 'true' in defender_result.stdout.lower()):
                    findings.append({
                        'category': 'Security Software',
                        'status': 'ok',
                        'description': 'Windows Defender is active',
                    })
                else:
                    findings.append({
                        'category': 'Security Software',
                        'status': 'warning',
                        'description': 'No active antivirus software detected',
                    })
        else:
            # Try alternative method for Windows Defender
            defender_result = subprocess.run(
                ['powershell', '-Command', 'Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled'],
                capture_output=True, text=True, timeout=15
            )
            if 'True' in defender_result.stdout:
                findings.append({
                    'category': 'Security Software',
                    'status': 'ok',
                    'description': 'Windows Defender is active',
                })
            else:
                findings.append({
                    'category': 'Security Software',
                    'status': 'warning',
                    'description': 'No antivirus software detected',
                })
    except Exception as e:
        findings.append({
            'category': 'Security Software',
            'status': 'warning',
            'description': f'Error checking antivirus status: {str(e)}',
        })
    
    # Check for firewall status using PowerShell
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-NetFirewallProfile | Select-Object Name, Enabled'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.split('\n')
            enabled_profiles = 0
            for line in lines:
                if 'True' in line:
                    enabled_profiles += 1
            
            if enabled_profiles > 0:
                findings.append({
                    'category': 'Security Software',
                    'status': 'ok',
                    'description': f'Windows Firewall is active ({enabled_profiles}/3 profiles enabled)',
                })
            else:
                findings.append({
                    'category': 'Security Software',
                    'status': 'warning',
                    'description': 'Windows Firewall is not active',
                })
        else:
            findings.append({
                'category': 'Security Software',
                'status': 'warning',
                'description': 'Could not determine Windows Firewall status',
            })
    except Exception as e:
        findings.append({
            'category': 'Security Software',
            'status': 'warning',
            'description': f'Error checking firewall status: {str(e)}',
        })
    
    # Check for antispyware software
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiSpywareProduct'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.split('\n')
            as_products = [line for line in lines if 'displayName' in line.lower() or 'productname' in line.lower()]
            if as_products:
                findings.append({
                    'category': 'Security Software',
                    'status': 'ok',
                    'description': f'Antispyware software detected ({len(as_products)} product(s) found)',
                })
            else:
                findings.append({
                    'category': 'Security Software',
                    'status': 'info',
                    'description': 'No dedicated antispyware software detected (may be included in antivirus)',
                })
        else:
            findings.append({
                'category': 'Security Software',
                'status': 'info',
                'description': 'No dedicated antispyware software detected (may be included in antivirus)',
            })
    except Exception as e:
        findings.append({
            'category': 'Security Software',
            'status': 'warning',
            'description': f'Error checking antispyware status: {str(e)}',
        })
    
    return findings


def display_results(results, format_type):
    """Display scan results"""
    if format_type == 'json':
        print(json.dumps(results, indent=2))
    else:
        print(Fore.CYAN + "Scan performed at: " + Fore.YELLOW + f"{results['timestamp']}")
        print(Fore.CYAN + "Scan type: " + Fore.YELLOW + f"{results['scan_type']}")
        print("")
        print(Fore.CYAN + "Findings:" + Style.RESET_ALL)
        current_category = None
        for finding in results['findings']:
            if finding['category'] != current_category:
                current_category = finding['category']
                print("")
                print(Fore.MAGENTA + f"[{finding['category']}]" + Style.RESET_ALL)
                print(Fore.MAGENTA + f"{'-' * len(finding['category'])}" + Style.RESET_ALL)
            status_colors = {
                'ok': Fore.GREEN,
                'info': Fore.BLUE,
                'warning': Fore.YELLOW,
                'error': Fore.RED
            }
            status_icons = {
                'ok': '[✓]',
                'info': '[ℹ]',
                'warning': '[⚠]',
                'error': '[✗]'
            }
            color = status_colors.get(finding['status'], Fore.WHITE)
            icon = status_icons.get(finding['status'], '[?]')
            print(f"  {color}{icon} {finding['description']}" + Style.RESET_ALL)


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