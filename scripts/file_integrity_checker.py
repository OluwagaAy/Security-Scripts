#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Monitors critical files and directories for unauthorized changes.
Compares against a baseline to detect modifications, additions, or deletions.

Usage:
    python file_integrity_checker.py --dir /etc --baseline
    python file_integrity_checker.py --dir /etc --check
"""

import hashlib
import json
import os
import argparse
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class FileIntegrityMonitor:
    def __init__(self, target_dir: str, baseline_file: str = None):
        self.target_dir = target_dir
        self.baseline_file = baseline_file or f"baseline_{Path(target_dir).name}.json"
        self.baseline = {}
        self.current = {}

    def calculate_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (IOError, OSError):
            return None

    def scan_directory(self):
        """Scan directory and calculate hashes for all files."""
        self.current = {}

        if not os.path.exists(self.target_dir):
            console.print(f"[red]Directory not found: {self.target_dir}[/red]")
            return

        console.print(f"[cyan]Scanning {self.target_dir}...[/cyan]")

        for root, dirs, files in os.walk(self.target_dir):
            # Skip common non-essential directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.cache']]

            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    file_hash = self.calculate_hash(filepath)
                    if file_hash:
                        self.current[filepath] = {
                            'hash': file_hash,
                            'size': os.path.getsize(filepath),
                            'mtime': os.path.getmtime(filepath)
                        }
                except (OSError, IOError):
                    continue

        console.print(f"[green]Scanned {len(self.current)} files[/green]")

    def create_baseline(self):
        """Create a new baseline from current scan."""
        self.scan_directory()
        self.baseline = self.current

        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)

        console.print(Panel.fit(
            f"[green]Baseline created successfully![/green]\n"
            f"Files tracked: {len(self.baseline)}\n"
            f"Baseline saved to: {self.baseline_file}",
            title="Baseline Created"
        ))

    def check_integrity(self):
        """Check current state against baseline."""
        # Load baseline
        if not os.path.exists(self.baseline_file):
            console.print(f"[red]Baseline file not found: {self.baseline_file}[/red]")
            console.print("[yellow]Run with --baseline first to create a baseline.[/yellow]")
            return

        with open(self.baseline_file, 'r') as f:
            self.baseline = json.load(f)

        self.scan_directory()

        # Compare
        modified = []
        added = []
        deleted = []

        # Check for modifications and deletions
        for filepath, baseline_data in self.baseline.items():
            if filepath not in self.current:
                deleted.append(filepath)
            elif self.current[filepath]['hash'] != baseline_data['hash']:
                modified.append({
                    'file': filepath,
                    'old_hash': baseline_data['hash'],
                    'new_hash': self.current[filepath]['hash']
                })

        # Check for additions
        for filepath in self.current:
            if filepath not in self.baseline:
                added.append(filepath)

        self._generate_report(modified, added, deleted)

    def _generate_report(self, modified: list, added: list, deleted: list):
        """Generate integrity check report."""
        total_changes = len(modified) + len(added) + len(deleted)

        if total_changes == 0:
            console.print(Panel.fit(
                "[green]All files match the baseline. No unauthorized changes detected.[/green]",
                title="✅ Integrity Check Passed"
            ))
            return

        console.print(Panel.fit(
            f"[yellow]Changes detected: {total_changes}[/yellow]\n"
            f"  Modified: {len(modified)}\n"
            f"  Added: {len(added)}\n"
            f"  Deleted: {len(deleted)}",
            title="⚠️ Integrity Check Results"
        ))

        if modified:
            console.print("\n[bold red]Modified Files:[/bold red]")
            table = Table()
            table.add_column("File", style="cyan")
            table.add_column("Old Hash", style="yellow")
            table.add_column("New Hash", style="red")
            for item in modified:
                table.add_row(
                    item['file'][-50:],  # Truncate for display
                    item['old_hash'][:16] + "...",
                    item['new_hash'][:16] + "..."
                )
            console.print(table)

        if added:
            console.print(f"\n[bold yellow]Added Files ({len(added)}):[/bold yellow]")
            for f in added[:10]:  # Show first 10
                console.print(f"  + {f}")
            if len(added) > 10:
                console.print(f"  ... and {len(added) - 10} more")

        if deleted:
            console.print(f"\n[bold red]Deleted Files ({len(deleted)}):[/bold red]")
            for f in deleted[:10]:
                console.print(f"  - {f}")
            if len(deleted) > 10:
                console.print(f"  ... and {len(deleted) - 10} more")

        console.print(Panel.fit(
            "[bold]Investigation Steps:[/bold]\n"
            "1. Verify if changes were authorized (updates, patches)\n"
            "2. Check timestamps and user access logs\n"
            "3. Review with system administrators\n"
            "4. If unauthorized, initiate incident response\n"
            "5. Update baseline after authorized changes",
            title="Next Steps"
        ))

def main():
    parser = argparse.ArgumentParser(description='File Integrity Monitor')
    parser.add_argument('--dir', required=True, help='Directory to monitor')
    parser.add_argument('--baseline', action='store_true', help='Create baseline')
    parser.add_argument('--check', action='store_true', help='Check integrity')
    parser.add_argument('--baseline-file', help='Custom baseline file path')
    args = parser.parse_args()

    fim = FileIntegrityMonitor(args.dir, args.baseline_file)

    if args.baseline:
        fim.create_baseline()
    elif args.check:
        fim.check_integrity()
    else:
        console.print("[yellow]Please specify --baseline or --check[/yellow]")

if __name__ == "__main__":
    main()
