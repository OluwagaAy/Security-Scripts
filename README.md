# Security Scripts & Automation 🔧

> A collection of daily-use cybersecurity automation scripts for system hardening, log analysis, network monitoring, and threat detection.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=for-the-badge&logo=powershell)](https://)

---

## 📂 Script Categories

| Category | Scripts | Description |
|----------|---------|-------------|
| **System Hardening** | `linux_hardening.sh`, `windows_hardening.ps1` | OS security configuration |
| **Log Analysis** | `auth_log_analyzer.py`, `failed_login_report.py` | Authentication log analysis |
| **Network Monitoring** | `connection_monitor.py`, `bandwidth_usage.py` | Network activity monitoring |
| **File Integrity** | `file_integrity_checker.py` | Detect unauthorized file changes |
| **Threat Hunting** | `ioc_scanner.py`, `suspicious_process_check.py` | Hunt for indicators of compromise |
| **Compliance** | `cis_benchmark_check.py` | CIS benchmark compliance checking |

---

## 🚀 Quick Start

```bash
git clone https://github.com/OluwagaAy/Security-Scripts.git
cd Security-Scripts

# Install dependencies
pip install -r requirements.txt

# Run a script
python scripts/auth_log_analyzer.py
```

---

## 📋 Available Scripts

### Authentication Log Analyzer
```bash
python scripts/auth_log_analyzer.py --log /var/log/auth.log
# Generates report of failed logins, brute force attempts, and successful authentications
```

### Linux System Hardening
```bash
sudo bash scripts/linux_hardening.sh
# Applies CIS Level 1 hardening: password policy, SSH config, firewall, updates
```

### File Integrity Monitor
```bash
python scripts/file_integrity_checker.py --dir /etc --baseline
# Creates baseline and monitors for unauthorized changes
```

### IOC Scanner
```bash
python scripts/ioc_scanner.py --ioc iocs.txt --scan-path /var/www
# Scans for known indicators of compromise in files
```

---

## 🎯 Use Cases

- **SOC Analysts**: Automate repetitive analysis tasks
- **System Administrators**: Harden systems and monitor changes
- **Security Consultants**: Quick assessment scripts
- **Students**: Learn security automation concepts

---

## ⚠️ Disclaimer

These scripts are for **authorized use only**. Always test in a lab environment first. Review scripts before running on production systems.

---

**Maintained by [MAPELEAD](https://www.mapelead.com) | Built with ❤️ by Coach Ay**
