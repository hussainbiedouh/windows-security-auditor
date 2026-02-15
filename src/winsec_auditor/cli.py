"""CLI entry point for Windows Security Auditor."""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from winsec_auditor import __version__
from winsec_auditor.scanner import SecurityScanner
from winsec_auditor.report import ReportGenerator
from winsec_auditor.checks import AVAILABLE_CHECKS
from winsec_auditor.utils import is_windows


@click.command()
@click.option(
    '--scan',
    'scan_type',
    type=click.Choice(['basic', 'full'], case_sensitive=False),
    help='Scan type to perform (default: interactive selection)'
)
@click.option(
    '--check',
    'specific_checks',
    help='Run specific checks only (comma-separated, e.g., firewall,users,network)'
)
@click.option(
    '--list-checks',
    is_flag=True,
    help='List all available checks and exit'
)
@click.option(
    '--json',
    'json_output',
    type=click.Path(dir_okay=False, writable=True),
    required=False,
    nargs=1,
    is_flag=False,
    flag_value='-',
    help='Output as JSON (to file or stdout if "-")'
)
@click.option(
    '--html',
    'html_output',
    type=click.Path(dir_okay=False, writable=True),
    help='Save HTML report to file'
)
@click.option(
    '--no-color',
    is_flag=True,
    help='Disable colored output'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Enable verbose output'
)
@click.version_option(version=__version__, prog_name='winsec-audit')
def main(
    scan_type: Optional[str],
    specific_checks: Optional[str],
    list_checks: bool,
    json_output: Optional[str],
    html_output: Optional[str],
    no_color: bool,
    verbose: bool,
) -> None:
    """Windows Security Auditor - Comprehensive security scanning tool.
    
    Examples:
    
        \b
        winsec-audit                          # Interactive mode
        winsec-audit --scan basic             # Basic scan
        winsec-audit --scan full              # Full scan with progress
        winsec-audit --scan full --json       # Full scan, JSON to stdout
        winsec-audit --scan full --html report.html  # Full scan, HTML report
        winsec-audit --check firewall,users   # Run specific checks
        winsec-audit --list-checks            # List all checks
    """
    # Initialize console
    console = Console(color_system=None if no_color else "auto")
    
    # Check if running on Windows
    if not is_windows():
        console.print("[red]Error: This tool is designed for Windows systems only.[/red]")
        sys.exit(1)
    
    # List checks and exit
    if list_checks:
        _list_available_checks(console)
        return
    
    # Determine scan type
    if specific_checks:
        # Parse specific checks
        check_list = [c.strip().lower() for c in specific_checks.split(',')]
        invalid_checks = [c for c in check_list if c not in AVAILABLE_CHECKS]
        
        if invalid_checks:
            console.print(f"[red]Error: Invalid check(s): {', '.join(invalid_checks)}[/red]")
            console.print("\n[yellow]Use --list-checks to see available checks.[/yellow]")
            sys.exit(1)
        
        scan_mode = "custom"
        checks_to_run = check_list
    elif scan_type:
        scan_mode = scan_type
        checks_to_run = None
    else:
        # Interactive mode
        scan_mode = _interactive_scan_selection(console)
        checks_to_run = None
    
    # Run the scan
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]🔐 Windows Security Auditor v{__version__}[/bold cyan]",
        subtitle=f"Scan type: {scan_mode.title()}"
    ))
    console.print()
    
    scanner = SecurityScanner(verbose=verbose)
    
    try:
        if json_output == '-':
            # JSON to stdout - no progress bars
            result = scanner.scan(scan_mode, specific_checks=checks_to_run)
        else:
            # Normal scan with progress
            result = scanner.scan_with_progress(scan_mode, console=console)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)
    
    # Generate reports
    report_gen = ReportGenerator(console)
    
    # Console output (unless only JSON/HTML requested)
    if not json_output and not html_output:
        report_gen.generate_console_report(result)
    
    # JSON output
    if json_output:
        if json_output == '-':
            console.print(report_gen.generate_json_report(result))
        else:
            report_gen.save_json_report(result, json_output)
    
    # HTML output
    if html_output:
        report_gen.save_html_report(result, html_output)
    
    # Print final summary
    summary = result.get('summary', {})
    console.print()
    
    if summary.get('critical', 0) > 0:
        console.print(f"[bold red]Scan complete! Found {summary['critical']} critical issue(s) that need immediate attention.[/bold red]")
    elif summary.get('warning', 0) > 0:
        console.print(f"[bold yellow]Scan complete! Found {summary['warning']} warning(s) that should be reviewed.[/bold yellow]")
    else:
        console.print("[bold green]Scan complete! No security issues detected.[/bold green]")
    
    # Exit with appropriate code
    if summary.get('critical', 0) > 0:
        sys.exit(2)
    elif summary.get('warning', 0) > 0:
        sys.exit(1)


def _list_available_checks(console: Console) -> None:
    """Display all available checks in a table."""
    table = Table(title="[bold]Available Security Checks[/bold]")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Description")
    
    for check_id, check_info in sorted(AVAILABLE_CHECKS.items()):
        scan_type = check_info["scan_type"]
        scan_type_style = "[green]basic[/green]" if scan_type == "basic" else "[blue]full[/blue]"
        table.add_row(
            check_id,
            check_info["name"],
            scan_type_style,
            check_info["description"],
        )
    
    console.print()
    console.print(table)
    console.print()
    console.print("[dim]Use --check with comma-separated IDs to run specific checks.[/dim]")


def _interactive_scan_selection(console: Console) -> str:
    """Interactive scan type selection.
    
    Returns:
        Selected scan type.
    """
    console.print()
    console.print(Panel.fit(
        "[bold]Select Scan Type[/bold]",
        border_style="cyan"
    ))
    console.print()
    console.print("  [cyan]1.[/cyan] [green]Basic Scan[/green]    - Quick system overview (3 checks)")
    console.print("  [cyan]2.[/cyan] [blue]Full Scan[/blue]     - Comprehensive security audit (11 checks)")
    console.print()
    
    choice = click.prompt(
        "Enter your choice",
        type=click.Choice(['1', '2', 'basic', 'full']),
        default='2',
        show_choices=False,
    )
    
    if choice in ['1', 'basic']:
        return 'basic'
    return 'full'


if __name__ == '__main__':
    main()
