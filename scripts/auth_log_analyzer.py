#!/usr/bin/env python3
"""
Authentication Log Analyzer
Analyzes Linux auth logs for failed login attempts, brute force attacks,
and suspicious authentication patterns.

Usage:
    python auth_log_analyzer.py --log /var/log/auth.log
    python auth_log_analyzer.py --log /var/log/secure
    python auth_log_analyzer.py --report daily
"""

import re
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

console = Console()

class AuthLogAnalyzer:
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.failed_logins = []
        self.successful_logins = []
        self.suspicious_ips = defaultdict(lambda: {'failed': 0, 'success': 0, 'users': set()})
        self.brute_force_candidates = []

    def parse_log_line(self, line: str) -> dict:
        """Parse a single auth log line."""
        patterns = {
            'failed_password': r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (invalid user )?(\w+) from ([\d.]+)',
            'accepted_password': r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from ([\d.]+)',
            'invalid_user': r'(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\w+) from ([\d.]+)',
            'connection_closed': r'(\w+\s+\d+\s+\d+:\d+:\d+).*Connection closed by ([\d.]+)',
        }

        for event_type, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'event_type': event_type,
                    'groups': match.groups()[1:]
                }
        return None

    def analyze_file(self):
        """Analyze the auth log file."""
        if not self.log_file or not Path(self.log_file).exists():
            console.print("[yellow]Log file not found. Using sample data for demonstration.[/yellow]")
            self._use_sample_data()
            return

        console.print(f"[cyan]Analyzing {self.log_file}...[/cyan]")

        with open(self.log_file, 'r', errors='ignore') as f:
            lines = f.readlines()

        with Progress() as progress:
            task = progress.add_task("[cyan]Parsing logs...", total=len(lines))

            for line in lines:
                parsed = self.parse_log_line(line)
                if parsed:
                    self._process_event(parsed)
                progress.advance(task)

        self._identify_brute_force()

    def _process_event(self, event: dict):
        """Process a parsed event."""
        if event['event_type'] == 'failed_password':
            user = event['groups'][1] if event['groups'][0] else event['groups'][0]
            ip = event['groups'][-1]
            self.failed_logins.append({'user': user, 'ip': ip, 'time': event['timestamp']})
            self.suspicious_ips[ip]['failed'] += 1
            self.suspicious_ips[ip]['users'].add(user)

        elif event['event_type'] == 'accepted_password':
            user = event['groups'][0]
            ip = event['groups'][1]
            self.successful_logins.append({'user': user, 'ip': ip, 'time': event['timestamp']})
            self.suspicious_ips[ip]['success'] += 1

    def _identify_brute_force(self, threshold: int = 5):
        """Identify potential brute force attacks."""
        for ip, data in self.suspicious_ips.items():
            if data['failed'] >= threshold:
                self.brute_force_candidates.append({
                    'ip': ip,
                    'failed_attempts': data['failed'],
                    'success': data['success'],
                    'targeted_users': data['users']
                })

    def _use_sample_data(self):
        """Generate sample data for demonstration."""
        sample_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '45.142.214.89']
        sample_users = ['admin', 'root', 'user1', 'test', 'oracle']

        import random
        for i in range(200):
            ip = random.choice(sample_ips)
            if ip == '45.142.214.89':  # Attacker IP
                self.failed_logins.append({
                    'user': random.choice(['admin', 'root']),
                    'ip': ip,
                    'time': 'Jan 15 08:30:00'
                })
                self.suspicious_ips[ip]['failed'] += 1
            else:
                if random.random() > 0.3:
                    self.successful_logins.append({
                        'user': 'user1',
                        'ip': ip,
                        'time': 'Jan 15 09:00:00'
                    })

        for ip, data in self.suspicious_ips.items():
            if data['failed'] >= 5:
                self.brute_force_candidates.append({
                    'ip': ip,
                    'failed_attempts': data['failed'],
                    'success': data.get('success', 0),
                    'targeted_users': data['users']
                })

    def generate_report(self):
        """Generate analysis report."""
        console.print(Panel.fit(
            f"[bold cyan]Authentication Log Analysis Report[/bold cyan]\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Log File: {self.log_file or 'Sample Data'}"
        ))

        # Summary statistics
        table = Table(title="Summary Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="yellow")

        table.add_row("Failed Login Attempts", str(len(self.failed_logins)))
        table.add_row("Successful Logins", str(len(self.successful_logins)))
        table.add_row("Unique Source IPs", str(len(self.suspicious_ips)))
        table.add_row("Brute Force Candidates", str(len(self.brute_force_candidates)))

        console.print(table)

        # Top attacking IPs
        if self.failed_logins:
            console.print("\n[bold red]🔴 Top Attacking IPs[/bold red]")
            ip_table = Table()
            ip_table.add_column("IP Address", style="red")
            ip_table.add_column("Failed Attempts", style="yellow", justify="right")
            ip_table.add_column("Successful", style="green", justify="right")
            ip_table.add_column("Targeted Users", style="cyan")

            sorted_ips = sorted(
                self.suspicious_ips.items(),
                key=lambda x: x[1]['failed'],
                reverse=True
            )[:10]

            for ip, data in sorted_ips:
                if data['failed'] > 0:
                    ip_table.add_row(
                        ip,
                        str(data['failed']),
                        str(data['success']),
                        ', '.join(data['users']) or 'N/A'
                    )

            console.print(ip_table)

        # Brute force alerts
        if self.brute_force_candidates:
            console.print("\n[bold red]🚨 Brute Force Alerts[/bold red]")
            for candidate in self.brute_force_candidates:
                console.print(Panel.fit(
                    f"[red]IP: {candidate['ip']}[/red]\n"
                    f"Failed Attempts: {candidate['failed_attempts']}\n"
                    f"Successful Logins: {candidate['success']}\n"
                    f"Targeted Users: {', '.join(candidate['targeted_users'])}\n\n"
                    f"[yellow]Recommended Action: Block IP immediately[/yellow]",
                    title="⚠️ Brute Force Detected"
                ))

        # Recommendations
        console.print(Panel.fit(
            "[bold green]📋 Recommendations:[/bold green]\n"
            "• Implement fail2ban or equivalent IP blocking\n"
            "• Enable key-based SSH authentication (disable password auth)\n"
            "• Change default SSH port (22) to non-standard port\n"
            "• Implement rate limiting on login attempts\n"
            "• Enable Multi-Factor Authentication (MFA)\n"
            "• Regularly review and rotate credentials",
            title="Security Hardening"
        ))

def main():
    parser = argparse.ArgumentParser(description='Authentication Log Analyzer')
    parser.add_argument('--log', help='Path to auth log file')
    parser.add_argument('--report', choices=['summary', 'detailed', 'csv'],
                        default='detailed', help='Report type')
    args = parser.parse_args()

    analyzer = AuthLogAnalyzer(args.log)
    analyzer.analyze_file()
    analyzer.generate_report()

if __name__ == "__main__":
    main()
