"""Main scanner orchestrator for Windows Security Auditor."""

from datetime import datetime
from typing import TYPE_CHECKING

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from winsec_auditor.checks import (
    AVAILABLE_CHECKS,
    get_checks_for_scan_type,
    get_check_function,
)

if TYPE_CHECKING:
    from winsec_auditor.types import ScanResult, SecurityFinding


class SecurityScanner:
    """Orchestrates security scans across multiple check modules."""
    
    def __init__(self, verbose: bool = False) -> None:
        """Initialize the scanner.
        
        Args:
            verbose: Enable verbose output.
        """
        self.verbose = verbose
    
    def scan(
        self,
        scan_type: str = "basic",
        specific_checks: list[str] | None = None,
        progress_callback: callable | None = None,
    ) -> "ScanResult":
        """Perform a security scan.
        
        Args:
            scan_type: Type of scan ('basic' or 'full').
            specific_checks: List of specific check IDs to run (overrides scan_type).
            progress_callback: Optional callback for progress updates.
            
        Returns:
            Scan results dictionary.
        """
        # Determine which checks to run
        if specific_checks:
            checks_to_run = specific_checks
        else:
            checks_to_run = get_checks_for_scan_type(scan_type)
        
        all_findings: list["SecurityFinding"] = []
        
        # Run each check
        for check_id in checks_to_run:
            check_func = get_check_function(check_id)
            
            if check_func:
                if progress_callback:
                    progress_callback(f"Running {AVAILABLE_CHECKS[check_id]['name']}...")
                
                try:
                    findings = check_func()
                    all_findings.extend(findings)
                except Exception as e:
                    all_findings.append({
                        "category": AVAILABLE_CHECKS[check_id]['name'],
                        "status": "error",
                        "description": f"Check failed: {e}",
                        "details": None,
                    })
        
        # Generate summary
        summary = self._generate_summary(all_findings)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type if not specific_checks else "custom",
            "findings": all_findings,
            "summary": summary,
        }
    
    def scan_with_progress(self, scan_type: str = "basic", console=None) -> "ScanResult":
        """Perform a scan with visual progress indicators.
        
        Args:
            scan_type: Type of scan ('basic' or 'full').
            console: Rich console instance for output.
            
        Returns:
            Scan results dictionary.
        """
        checks_to_run = get_checks_for_scan_type(scan_type)
        all_findings: list["SecurityFinding"] = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Running security checks...", total=len(checks_to_run))
            
            for check_id in checks_to_run:
                check_name = AVAILABLE_CHECKS[check_id]['name']
                progress.update(task, description=f"[cyan]Checking {check_name}...")
                
                check_func = get_check_function(check_id)
                if check_func:
                    try:
                        findings = check_func()
                        all_findings.extend(findings)
                    except Exception as e:
                        all_findings.append({
                            "category": check_name,
                            "status": "error",
                            "description": f"Check failed: {e}",
                            "details": None,
                        })
                
                progress.advance(task)
        
        summary = self._generate_summary(all_findings)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type,
            "findings": all_findings,
            "summary": summary,
        }
    
    def _generate_summary(self, findings: list["SecurityFinding"]) -> dict:
        """Generate summary statistics from findings.
        
        Args:
            findings: List of security findings.
            
        Returns:
            Summary dictionary with counts.
        """
        summary = {
            "total": len(findings),
            "info": 0,
            "ok": 0,
            "warning": 0,
            "critical": 0,
            "error": 0,
        }
        
        for finding in findings:
            status = finding.get("status", "info")
            if status in summary:
                summary[status] += 1
        
        return summary
