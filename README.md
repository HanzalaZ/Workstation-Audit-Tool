# Workstation Audit Automation Script

An automated, Windows PowerShell script made to accelerate endpoint inventory tracking and compliance auditing. This script extracts deep hardware metrics, licensing states, domain topography, and security configurations, completely aligning with the structural requirements of the corporate **Workstation Audit Checklist**.

---

## 📋 Table of Contents
- [🚀 Quick Start (How to Run)](#-quick-start-how-to-run)


---

## 🚀 Quick Start (How to Run)

To capture advanced metrics—including Windows product keys, firewall profiles, and system-locked group policies—the script **must** be executed within an elevated administrative terminal session.

1. Open **PowerShell** or **VS Code** with **Administrator privileges**.
2. If script execution is restricted on the target machine, temporarily bypass the execution policy for your active session:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
