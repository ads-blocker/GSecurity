# Enterprise Modular Antivirus & EDR System

![Version](https://img.shields.io/badge/version-4.0--modular-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

A comprehensive, production-grade antivirus and Endpoint Detection and Response (EDR) solution built with a fully modular PowerShell architecture. Features 28 independent detection modules, cloud-based reputation services, real-time system monitoring, and a dedicated unsigned DLL scanner.

## 🏗️ Modular Architecture

### System Components

1. **Antivirus.ps1** - Main launcher and job orchestration engine
2. **28 Detection Modules (.psm1)** - Independent, hot-swappable detection engines
3. **UnsignedDLL-Scanner** - Integrated but separate signature verification scanner

### Why Modular?

- **🔧 Easy Maintenance** - Update individual modules without touching core
- **⚡ Performance** - Enable only what you need
- **🔄 Hot-Reload** - Add/remove modules without restart
- **📊 Granular Control** - Configure intervals per module
- **🐛 Isolated Failures** - One module crash doesn't affect others
- **🚀 Scalability** - Add custom modules easily

## 📦 Detection Modules

Each .psm1 file contains one detection function that runs as an independent background job:

| Module File | Function | Interval (s) | Description |
|------------|----------|--------------|-------------|
| `HashDetection.psm1` | Hash scanning + cloud reputation | 15 | CIRCL, Cymru, MalwareBazaar APIs |
| `LOLBinDetection.psm1` | Living-off-the-Land binary abuse | 15 | certutil, bitsadmin, mshta, etc. |
| `ProcessAnomalyDetection.psm1` | Behavioral analysis | 15 | Suspicious process patterns |
| `AMSIBypassDetection.psm1` | AMSI tampering detection | 15 | Anti-malware scan interface |
| `CredentialDumpDetection.psm1` | Credential theft protection | 15 | Mimikatz, lsass access |
| `WMIPersistenceDetection.psm1` | WMI event persistence | 15 | Event filters & consumers |
| `ScheduledTaskDetection.psm1` | Task scheduler abuse | 120 | Suspicious scheduled tasks |
| `RegistryPersistenceDetection.psm1` | Registry auto-start keys | 120 | Run/RunOnce monitoring |
| `DLLHijackingDetection.psm1` | DLL search order hijacking | 90 | Unsigned module loading |
| `TokenManipulationDetection.psm1` | Token theft & impersonation | 60 | Privilege escalation |
| `DNSExfiltrationDetection.psm1` | DNS tunneling detection | 30 | Long subdomain analysis |
| `NamedPipeMonitoring.psm1` | Inter-process communication | 15 | Suspicious pipe names |
| `NetworkAnomalyDetection.psm1` | Suspicious connections | 30 | C2 port detection |
| `MemoryScanning.psm1` | Memory anomaly detection | 15 | Excessive memory usage |
| `FilelessDetection.psm1` | Fileless malware detection | 15 | Encoded PowerShell |
| `ProcessHollowingDetection.psm1` | Process injection | 30 | Hollow process detection |
| `KeyloggerDetection.psm1` | Keyboard logger detection | 45 | user32.dll hooks |
| `RootkitDetection.psm1` | Kernel-mode rootkits | 180 | Driver validation |
| `ClipboardMonitoring.psm1` | Sensitive data in clipboard | 30 | Password/token detection |
| `COMMonitoring.psm1` | COM object abuse | 120 | Recent COM modifications |
| `RansomwareDetection.psm1` | Ransomware behavior | 15 | vssadmin, shadow deletion |
| `BrowserExtensionMonitoring.psm1` | Malicious extensions | 300 | Chrome/Firefox/Edge |
| `ShadowCopyMonitoring.psm1` | Volume shadow protection | 30 | Deletion detection |
| `USBMonitoring.psm1` | USB threat detection | 20 | BadUSB, autorun |
| `EventLogMonitoring.psm1` | Log tampering detection | 60 | Log clearing, brute force |
| `FirewallRuleMonitoring.psm1` | Firewall changes | 120 | Unauthorized rules |
| `ServiceMonitoring.psm1` | Service creation detection | 60 | New Windows services |
| **UnsignedDLL-Scanner** | Signature verification | Continuous | Dedicated DLL scanner |

## 🚀 Quick Start

### Installation

```powershell
# 1. Download all files
git clone https://github.com/your-repo/antivirus-modular.git
cd antivirus-modular

# 2. Run as Administrator (THIS IS THE ONLY FILE YOU NEED TO RUN)
powershell.exe -ExecutionPolicy Bypass -File .\Antivirus.ps1
```

**Important: Only run `Antivirus.ps1` - it automatically loads all .psm1 modules and launches the DLL scanner.**

The core script will automatically:
1. Create `C:\ProgramData\AntivirusProtection` directory structure
2. Copy all .psm1 modules to `Modules\` subfolder
3. Launch enabled detection modules as background jobs
4. Start the Unsigned DLL Scanner in a separate runspace
5. Begin monitoring

### Verify Installation

```powershell
# Check running jobs
Get-Job | Where-Object { $_.Name -like "AV_*" }

# Check modules directory
Get-ChildItem "C:\ProgramData\AntivirusProtection\Modules"

# View logs
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" -Tail 20
```

## ⚙️ Configuration

Edit `Antivirus.ps1` to customize:

### Enable/Disable Modules

```powershell
$Config = @{
    # Toggle any module on/off
    EnableHashDetection = $true
    EnableLOLBinDetection = $true
    EnableProcessAnomalyDetection = $true
    EnableBrowserExtensionMonitoring = $true
    EnableShadowCopyMonitoring = $true
    EnableUSBMonitoring = $true
    EnableEventLogMonitoring = $true
    EnableFirewallRuleMonitoring = $true
    EnableServiceMonitoring = $true
    EnableUnsignedDLLScanner = $true
    
    # ... 18 more modules
}
```

### Adjust Scan Intervals

```powershell
$Script:ManagedJobConfig = @{
    MalwareScanIntervalSeconds = 15             # Hash detection
    ProcessAnomalyIntervalSeconds = 15          # Behavior analysis
    NetworkAnomalyIntervalSeconds = 30          # Network scanning
    BrowserExtensionIntervalSeconds = 300       # Browser checks (5 min)
    ServiceMonitorIntervalSeconds = 60          # Service monitoring
    # ... customize any interval
}
```

### Cloud Reputation APIs

```powershell
$Config = @{
    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"
}
```

### Response Actions

```powershell
$Config = @{
    AutoKillThreats = $true      # Automatically terminate malicious processes
    AutoQuarantine = $true       # Automatically quarantine threats
    MaxMemoryUsageMB = 500       # Memory limit per module
}
```

## 🔧 Module Development

### Creating a Custom Module

Create `CustomDetection.psm1`:

```powershell
function Invoke-CustomDetection {
    param(
        [string]$LogPath,
        [bool]$AutoKillThreats = $true
    )
    
    # Your detection logic here
    Write-Output "[CustomDetection] Running custom checks..."
    
    # Return findings
    Write-Output "[CustomDetection] THREAT: Found something suspicious!"
}

Export-ModuleMember -Function Invoke-CustomDetection
```

### Register in Core

Edit `Antivirus.ps1`:

```powershell
# Add to config
$Config.EnableCustomDetection = $true

# Add interval
$Script:ManagedJobConfig.CustomDetectionIntervalSeconds = 30

# Register job
if ($Config.EnableCustomDetection) {
    Start-ManagedJob -ModuleName "CustomDetection" -IntervalSeconds 30
}
```

### Module Guidelines

1. **Function Name**: Must be `Invoke-<ModuleName>`
2. **Parameters**: Accept config parameters (LogPath, AutoKillThreats, etc.)
3. **Output**: Use `Write-Output` for log messages
4. **Error Handling**: Wrap logic in try/catch
5. **Export**: Use `Export-ModuleMember -Function Invoke-<ModuleName>`

## 🛡️ Unsigned DLL Scanner

The DLL scanner runs as a completely separate component within the same process:

### Features

- Scans all drives for unsigned DLLs
- Real-time file system monitoring
- Automatic quarantine of unsigned libraries
- Process termination for DLL-using processes
- Hash-based deduplication
- Aggressive permission takeover

### Configuration

The scanner is **untouched code** that runs independently. Its configuration is embedded:

```powershell
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\dll_scanner_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
```

### Exclusions

Automatically excludes:
- `*\assembly\*` folders
- ctfmon-related files (`msctf.dll`, `msutb.dll`)
- `C:\Windows\System32\config`

### Logs

```powershell
# View DLL scanner logs
Get-Content "C:\Quarantine\dll_scanner_log.txt" -Tail 50
```

## 📊 Monitoring & Management

### Check Module Status

```powershell
# List all running modules
Get-Job | Where-Object { $_.Name -like "AV_*" } | Format-Table Name, State, HasMoreData

# Check specific module
Get-Job -Name "AV_HashDetection"

# View module output
Receive-Job -Name "AV_HashDetection" -Keep
```

### View Real-Time Logs

```powershell
# Main log
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" -Wait -Tail 10

# DLL Scanner log
Get-Content "C:\Quarantine\dll_scanner_log.txt" -Wait -Tail 10
```

### Performance Monitoring

```powershell
# Check memory usage
Get-Job | Where-Object { $_.Name -like "AV_*" } | ForEach-Object {
    $_.ChildJobs[0] | Select-Object @{N='Name';E={$_.Name}}, @{N='Memory';E={$_.PSBeginTime}}
}

# Check job health
Get-Job | Where-Object { $_.Name -like "AV_*" -and $_.State -eq "Failed" }
```

## 📁 Directory Structure

```
C:\ProgramData\AntivirusProtection\
├── Antivirus.ps1               # Main launcher
├── Modules\                         # Detection modules
│   ├── HashDetection.psm1
│   ├── LOLBinDetection.psm1
│   ├── ProcessAnomalyDetection.psm1
│   ├── ... (25 more modules)
│   └── ServiceMonitoring.psm1
├── Data\
│   ├── database.json                # Threat database
│   ├── whitelist.json               # Exclusions
│   ├── db_integrity.hmac            # Integrity key
│   └── antivirus.pid                # Process ID
├── Logs\
│   └── antivirus_log.txt            # Unified log
├── Quarantine\                      # Isolated threats
└── Reports\                         # Security reports

C:\Quarantine\                       # DLL Scanner
├── dll_scanner_log.txt              # DLL scanner log
├── scanned_files.txt                # Hash database
└── <quarantined_files>              # Unsigned DLLs
```

## 🔄 Hot-Reload Modules

### Update a Module Without Restart

```powershell
# 1. Stop specific module
Stop-Job -Name "AV_HashDetection"
Remove-Job -Name "AV_HashDetection" -Force

# 2. Update the .psm1 file
# Edit: C:\ProgramData\AntivirusProtection\Modules\HashDetection.psm1

# 3. Restart module (while Core is still running)
Start-ManagedJob -ModuleName "HashDetection" -IntervalSeconds 15
```

### Add New Module Dynamically

```powershell
# 1. Copy new module
Copy-Item ".\MyNewDetection.psm1" "C:\ProgramData\AntivirusProtection\Modules\"

# 2. Register and start (add to running Core)
Start-ManagedJob -ModuleName "MyNewDetection" -IntervalSeconds 30
```

## 🛑 Stopping the System

### Graceful Shutdown

```powershell
# Press Ctrl+C in the Core window, or:

# Stop all jobs
Get-Job | Where-Object { $_.Name -like "AV_*" } | Stop-Job
Get-Job | Where-Object { $_.Name -like "AV_*" } | Remove-Job -Force
```

### Uninstallation

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Antivirus.ps1 -Uninstall
```

This will:
- Stop all running modules
- Remove core script
- Remove modules directory
- Preserve quarantine and logs for forensics

## 🎯 Use Cases

### Minimal Resource Mode

Only enable critical modules:

```powershell
$Config = @{
    EnableHashDetection = $true
    EnableProcessAnomalyDetection = $true
    EnableRansomwareDetection = $true
    # All others = $false
}
```

### Maximum Protection Mode

Enable everything:

```powershell
# All detection modules enabled by default
$Config.EnableUnsignedDLLScanner = $true
```

### Custom Enterprise Deployment

Disable aggressive modules for enterprise:

```powershell
$Config = @{
    EnableUnsignedDLLScanner = $false    # Avoid false positives with custom apps
    EnableKeyloggerDetection = $false     # Avoid conflicts with monitoring tools
    EnableRootkitDetection = $false       # Skip if you have kernel AV
    # Enable rest
}
```

## 🐛 Troubleshooting

### Module Not Starting

```powershell
# Check if module file exists
Test-Path "C:\ProgramData\AntivirusProtection\Modules\HashDetection.psm1"

# Check for syntax errors
Import-Module "C:\ProgramData\AntivirusProtection\Modules\HashDetection.psm1" -Force

# View error details
Get-Job -Name "AV_HashDetection" | Receive-Job
```

### High CPU Usage

```powershell
# Increase scan intervals in config
$Script:ManagedJobConfig.MalwareScanIntervalSeconds = 60  # Slower scanning
```

### Module Keeps Failing

```powershell
# View failure reason
Get-Job -Name "AV_ModuleName" | Format-List *

# Check logs
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" | Select-String "ModuleName"
```

### DLL Scanner Too Aggressive

Edit scanner exclusions in `Antivirus.ps1`:

```powershell
# Find the $Script:UnsignedDLLScannerCode block
# Add to Should-ExcludeFile function:
if ($lowerPath -like "*\your-app\*") {
    return $true
}
```

## 📊 Logging

### Log Format

```
[TIMESTAMP] [LEVEL] [MODULE] Message
[2025-01-01 12:00:00] [THREAT] [HashDetection] THREAT: malware.exe | Confidence: 90%
[2025-01-01 12:00:01] [ACTION] [HashDetection] Quarantined: malware.exe
```

### Log Levels

- **INFO** - Normal operations
- **WARN** - Suspicious activity
- **THREAT** - Confirmed threats
- **ACTION** - Response actions taken
- **ERROR** - Module errors

### Viewing Logs

```powershell
# All threats
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" | Select-String "THREAT"

# Specific module
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" | Select-String "HashDetection"

# Last hour
Get-Content "C:\ProgramData\AntivirusProtection\Logs\antivirus_log.txt" | 
    Select-String (Get-Date).AddHours(-1).ToString("yyyy-MM-dd HH")
```

## 🔐 Security Features

### Module Isolation

- Each module runs in separate runspace
- Module crash doesn't affect Core or other modules
- Automatic restart on failure (3 attempts)

### Database Integrity

- HMAC-SHA256 signatures
- Protected key storage
- Tamper detection

### Self-Protection

- Mutex-based single instance
- PID file tracking
- Core process monitoring

### Whitelisting

```powershell
# Add to whitelist via database
$Whitelist = Get-Content "C:\ProgramData\AntivirusProtection\Data\whitelist.json" | ConvertFrom-Json
$Whitelist += @{
    FilePath = "C:\MyApp\app.exe"
    ProcessName = "app"
    Hash = "abc123..."
    Reason = "Trusted application"
}
$Whitelist | ConvertTo-Json | Set-Content "C:\ProgramData\AntivirusProtection\Data\whitelist.json"
```

## 📈 Performance

### Resource Usage

- **Core Process**: ~50MB RAM
- **Per Module**: ~20-30MB RAM (28 modules = ~600-800MB total)
- **CPU**: <5% average (spikes during scans)
- **Disk I/O**: Minimal (caching enabled)

### Optimization Tips

1. **Disable Unused Modules** - Only enable what you need
2. **Increase Intervals** - Reduce scan frequency for low-priority modules
3. **Cache Management** - Monitor cache hit rate
4. **Log Rotation** - Archive old logs regularly

## 🤝 Contributing

### Adding Detection Modules

1. Create `YourDetection.psm1` in `Modules\` folder
2. Follow module guidelines (see Module Development section)
3. Test independently before integration
4. Submit PR with module + documentation

### Improving Core

- Job management enhancements
- Performance optimizations
- Error handling improvements
- Configuration management

### Module Ideas

- **ML-based detection** - Anomaly scoring
- **Sandbox integration** - Automated sample analysis
- **YARA rules** - Pattern-based scanning
- **Threat intelligence feeds** - Real-time IoC updates
- **Email scanning** - Attachment analysis
- **Web traffic inspection** - HTTPS inspection

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

This software is provided for educational and research purposes. Test thoroughly before production deployment. The authors are not responsible for any damages resulting from use of this software.

**Important Warnings**:
- Unsigned DLL Scanner can be aggressive - configure exclusions
- Some modules may cause false positives - tune thresholds
- Always test in non-production environment first
- Backup system before deployment

## 📞 Support

- **Issues**: Open an issue on GitHub
- **Documentation**: Module inline comments + this README
- **Logs**: Check `C:\ProgramData\AntivirusProtection\Logs\`
- **Community**: Discussions tab

## 🎯 Roadmap

### Version 4.1
- [ ] Web-based dashboard for module management
- [ ] Centralized configuration file (YAML/JSON)
- [ ] Module marketplace/repository
- [ ] Performance profiling tools
- [ ] Machine learning module

### Version 4.2
- [ ] Linux/macOS support
- [ ] Container deployment (Docker)
- [ ] RESTful API for external integration
- [ ] SIEM integration (Splunk, ELK)
- [ ] Automated response playbooks

### Version 5.0
- [ ] Complete GUI rewrite
- [ ] Kernel-mode driver for deeper inspection
- [ ] Cloud-based management console
- [ ] Multi-tenant support
- [ ] Advanced threat hunting

---

**Built with ❤️ for the security community**

**Star ⭐ this repo if you find it useful!**
