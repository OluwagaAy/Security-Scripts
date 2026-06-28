#!/usr/bin/env python3
"""
Indicators of Compromise (IOC) Scanner
Scans files and directories for known malicious indicators.
Useful for threat hunting and incident response.

Usage:
    python ioc_scanner.py --ioc iocs.txt --scan-path /var/www
    python ioc_scanner.py --ioc iocs.txt --scan-path /home --recursive
"""

import os
import re
import argparse
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

class IOCScanner:
    def __init__(self, ioc_file: str, scan_path: str, recursive: bool = True):
        self.ioc_file = ioc_file
        self.scan_path = scan_path
        self.recursive = recursive
        self.iocs = {'hashes': [], 'ips': [], 'domains': [], 'patterns': [], 'filenames': []}
        self.matches = []

    def load_iocs(self):
        """Load IOCs from file."""
        console.print(f"[cyan]Loading IOCs from {self.ioc_file}...[/cyan]")

        with open(self.ioc_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Categorize IOC
                if re.match(r'^[a-fA-F0-9]{32}$', line):  # MD5
                    self.iocs['hashes'].append(line.lower())
                elif re.match(r'^[a-fA-F0-9]{64}$', line):  # SHA256
                    self.iocs['hashes'].append(line.lower())
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):  # IP
                    self.iocs['ips'].append(line)
                elif re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}$', line):  # Domain
                    self.iocs['domains'].append(line.lower())
                elif '*' in line or '?' in line:  # Pattern
                    self.iocs['patterns'].append(line)
                else:  # Filename
                    self.iocs['filenames'].append(line)

        total = sum(len(v) for v in self.iocs.values())
        console.print(f"[green]Loaded {total} IOCs[/green]")

    def calculate_hashes(self, filepath: str) -> dict:
        """Calculate MD5 and SHA256 hashes of a file."""
        hashes = {'md5': None, 'sha256': None}
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            hashes['md5'] = md5.hexdigest()
            hashes['sha256'] = sha256.hexdigest()
        except (IOError, OSError):
            pass
        return hashes

    def scan_file(self, filepath: str):
        """Scan a single file for IOCs."""
        matches = []
        filename = os.path.basename(filepath).lower()

        # Check filename IOCs
        for ioc_filename in self.iocs['filenames']:
            if ioc_filename.lower() in filename:
                matches.append({
                    'file': filepath,
                    'ioc': ioc_filename,
                    'type': 'filename',
                    'severity': 'HIGH'
                })

        # Check hash IOCs
        if self.iocs['hashes']:
            hashes = self.calculate_hashes(filepath)
            for hash_ioc in self.iocs['hashes']:
                if hash_ioc in [hashes['md5'], hashes['sha256']]:
                    matches.append({
                        'file': filepath,
                        'ioc': hash_ioc,
                        'type': 'hash',
                        'severity': 'CRITICAL'
                    })

        # Check content for IP/Domain IOCs (only in text files)
        if self.iocs['ips'] or self.iocs['domains']:
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()

                for ip in self.iocs['ips']:
                    if ip in content:
                        matches.append({
                            'file': filepath,
                            'ioc': ip,
                            'type': 'ip_reference',
                            'severity': 'HIGH'
                        })

                for domain in self.iocs['domains']:
                    if domain.lower() in content.lower():
                        matches.append({
                            'file': filepath,
                            'ioc': domain,
                            'type': 'domain_reference',
                            'severity': 'MEDIUM'
                        })
            except:
                pass

        return matches

    def scan(self):
        """Run the IOC scan."""
        files_to_scan = []

        if os.path.isfile(self.scan_path):
            files_to_scan = [self.scan_path]
        elif os.path.isdir(self.scan_path):
            if self.recursive:
                for root, dirs, files in os.walk(self.scan_path):
                    for f in files:
                        files_to_scan.append(os.path.join(root, f))
            else:
                files_to_scan = [os.path.join(self.scan_path, f)
                               for f in os.listdir(self.scan_path)
                               if os.path.isfile(os.path.join(self.scan_path, f))]

        console.print(f"[cyan]Scanning {len(files_to_scan)} files...[/cyan]")

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(files_to_scan))

            with ThreadPoolExecutor(max_workers=10) as executor:
                for file_matches in executor.map(self.scan_file, files_to_scan):
                    self.matches.extend(file_matches)
                    progress.advance(task)

    def generate_report(self):
        """Generate scan report."""
        console.print(Panel.fit(
            f"[bold cyan]IOC Scan Report[/bold cyan]\n"
            f"Scan Path: {self.scan_path}\n"
            f"Files Scanned: Analyzed\n"
            f"Matches Found: {len(self.matches)}"
        ))

        if self.matches:
            table = Table(title="IOC Matches")
            table.add_column("File", style="cyan")
            table.add_column("IOC", style="yellow")
            table.add_column("Type", style="green")
            table.add_column("Severity", style="bold")

            severity_colors = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'blue'}

            for match in self.matches:
                color = severity_colors.get(match['severity'], 'white')
                table.add_row(
                    match['file'][-60:],
                    match['ioc'],
                    match['type'],
                    f"[{color}]{match['severity']}[/{color}]"
                )

            console.print(table)

            console.print(Panel.fit(
                "[bold red]⚠️ IOCs detected! Follow incident response procedures.[/bold red]\n"
                "1. Isolate affected systems\n"
                "2. Preserve evidence\n"
                "3. Escalate to incident response team\n"
                "4. Investigate scope of compromise",
                title="Alert"
            ))
        else:
            console.print("[green]No IOCs found.[/green]")

def main():
    parser = argparse.ArgumentParser(description='IOC Scanner')
    parser.add_argument('--ioc', required=True, help='IOC file (one per line)')
    parser.add_argument('--scan-path', required=True, help='Path to scan')
    parser.add_argument('--no-recursive', action='store_true', help='Disable recursive scanning')
    args = parser.parse_args()

    scanner = IOCScanner(args.ioc, args.scan_path, not args.no_recursive)
    scanner.load_iocs()
    scanner.scan()
    scanner.generate_report()

if __name__ == "__main__":
    main()
