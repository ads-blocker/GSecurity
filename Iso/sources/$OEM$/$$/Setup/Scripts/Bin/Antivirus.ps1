param([switch]$Uninstall)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# Modular Antivirus & EDR - Core Launcher
# Author: Gorstak (Enhanced by v0)
# Version: 4.0 - Modular Architecture
# ============================================================================

$Script:InstallPath = "C:\ProgramData\AntivirusProtection"
$Script:ModulesPath = "$Script:InstallPath\Modules"
$Script:ScriptName = "Antivirus.ps1"
$Script:MaxCacheSize = 10000

$Script:ManagedJobConfig = @{
    MalwareScanIntervalSeconds = 15
    CredentialDumpingIntervalSeconds = 15
    RansomwareBehaviorIntervalSeconds = 15
    BehaviorMonitorIntervalSeconds = 15
    ProcessAnomalyIntervalSeconds = 15
    NetworkAnomalyIntervalSeconds = 30
    RegistryPersistenceIntervalSeconds = 120
    ScheduledTaskIntervalSeconds = 120
    ServiceMonitorIntervalSeconds = 60
    BrowserExtensionIntervalSeconds = 300
    ShadowCopyMonitorIntervalSeconds = 30
    USBMonitorIntervalSeconds = 20
    EventLogMonitorIntervalSeconds = 60
    FirewallRuleMonitorIntervalSeconds = 120
    DLLHijackingIntervalSeconds = 90
    TokenManipIntervalSeconds = 60
    ProcessHollowIntervalSeconds = 30
    KeyloggerDetectionIntervalSeconds = 45
    RootkitDetectionIntervalSeconds = 180
    ClipboardMonitorIntervalSeconds = 30
    COMMonitorIntervalSeconds = 120
    RansomwareDetectionIntervalSeconds = 15
    ShadowCopyDetectionIntervalSeconds = 30
    USBDetectionIntervalSeconds = 20
    EventLogDetectionIntervalSeconds = 60
    BrowserExtensionDetectionIntervalSeconds = 300
    FirewallRuleDetectionIntervalSeconds = 120
    ServiceDetectionIntervalSeconds = 60
    UnsignedDLLScannerIntervalSeconds = 300
}

$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "$Script:InstallPath\Logs"
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    WhitelistPath = "$Script:InstallPath\Data\whitelist.json"
    ReportsPath = "$Script:InstallPath\Reports"
    HMACKeyPath = "$Script:InstallPath\Data\db_integrity.hmac"
    PIDFilePath = "$Script:InstallPath\Data\antivirus.pid"
    MutexName = "Local\AntivirusProtection_Mutex"
    
    EnableHashDetection = $true
    EnableLOLBinDetection = $true
    EnableProcessAnomalyDetection = $true
    EnableAMSIBypassDetection = $true
    EnableCredentialDumpDetection = $true
    EnableWMIPersistenceDetection = $true
    EnableScheduledTaskDetection = $true
    EnableRegistryPersistenceDetection = $true
    EnableDLLHijackingDetection = $true
    EnableTokenManipulationDetection = $true
    EnableDNSExfiltrationDetection = $true
    EnableNamedPipeMonitoring = $true
    EnableNetworkAnomalyDetection = $true
    EnableMemoryScanning = $true
    EnableFilelessDetection = $true
    EnableProcessHollowingDetection = $true
    EnableKeyloggerDetection = $true
    EnableRootkitDetection = $true
    EnableClipboardMonitoring = $true
    EnableCOMMonitoring = $true
    EnableRansomwareDetection = $true
    EnableShadowCopyDetection = $true
    EnableUSBDetection = $true
    EnableEventLogDetection = $true
    EnableBrowserExtensionDetection = $true
    EnableFirewallRuleDetection = $true
    EnableServiceDetection = $true
    EnableUnsignedDLLScanner = $true
    
    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"
    
    AutoKillThreats = $true
    AutoQuarantine = $true
    MaxMemoryUsageMB = 500
    EnableSelfDefense = $true
}

$Global:AntivirusState = @{
    Running = $false
    Installed = $false
    Jobs = @{}
    Mutex = $null
    HMACKey = $null
    Database = $null
    Whitelist = @()
    Cache = @{}
    ThreatCount = 0
    FilesScanned = 0
    FilesQuarantined = 0
    ProcessesTerminated = 0
}

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

function Install-Antivirus {
    Write-Host "`n=== Installing Modular Antivirus Protection ===`n" -ForegroundColor Cyan
    
    $Subdirs = @("Data", "Logs", "Quarantine", "Reports", "Modules")
    foreach ($Dir in $Subdirs) {
        $Path = Join-Path $Script:InstallPath $Dir
        if (!(Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Host "[+] Created directory: $Path"
        }
    }
    
    $CurrentScript = $PSCommandPath
    $TargetScript = Join-Path $Script:InstallPath $Script:ScriptName
    
    if ($CurrentScript -ne $TargetScript) {
        Copy-Item -Path $CurrentScript -Destination $TargetScript -Force
        Write-Host "[+] Copied core script to: $TargetScript"
    }
    
    $CurrentDir = Split-Path -Parent $CurrentScript
    $ModuleFiles = Get-ChildItem -Path $CurrentDir -Filter "*.psm1" -ErrorAction SilentlyContinue
    
    $ModuleCount = 0
    foreach ($Module in $ModuleFiles) {
        $TargetModule = Join-Path $Script:ModulesPath $Module.Name
        Copy-Item -Path $Module.FullName -Destination $TargetModule -Force
        Write-Host "[+] Copied module: $($Module.Name)"
        $ModuleCount++
    }
    
    Write-Host "[+] Total modules installed: $ModuleCount" -ForegroundColor Green
    
    try {
        New-EventLog -LogName Application -Source $Config.EDRName -ErrorAction SilentlyContinue
        Write-Host "[+] Registered event log source"
    } catch {}
    
    $Global:AntivirusState.Installed = $true
    Write-Host "`n[+] Installation complete!`n" -ForegroundColor Green
}

function Uninstall-Antivirus {
    Write-Host "`n=== Uninstalling Antivirus Protection ===`n" -ForegroundColor Cyan
    
    Write-Host "[*] Stopping all modules..."
    foreach ($JobName in $Global:AntivirusState.Jobs.Keys) {
        Stop-Job -Name $JobName -ErrorAction SilentlyContinue
        Remove-Job -Name $JobName -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "[*] Removing files..."
    Remove-Item -Path (Join-Path $Script:InstallPath $Script:ScriptName) -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $Script:ModulesPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "`n[+] Uninstallation complete!`n" -ForegroundColor Green
    exit 0
}

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    $LogFilePath = Join-Path $Config.LogPath "antivirus_log.txt"
    Add-Content -Path $LogFilePath -Value $LogEntry -ErrorAction SilentlyContinue
    
    $EventID = switch($Level) { "ERROR" {1001}; "WARN" {1002}; "THREAT" {1003}; default {1000} }
    Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Information -EventId $EventID -Message $Message -ErrorAction SilentlyContinue
}

function Initialize-Mutex {
    try {
        try {
            $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $Config.MutexName)
            $Acquired = $Global:AntivirusState.Mutex.WaitOne(500)
            
            if (!$Acquired) {
                throw "Another instance is already running (mutex check)"
            }
        } catch {
            # Fallback to PID file check if mutex fails
            Write-AVLog "Mutex creation failed, using PID file fallback: $_" "WARN"
            
            if (Test-Path $Config.PIDFilePath) {
                $ExistingPID = Get-Content $Config.PIDFilePath -ErrorAction SilentlyContinue
                $ExistingProcess = Get-Process -Id $ExistingPID -ErrorAction SilentlyContinue
                
                if ($ExistingProcess -and $ExistingProcess.ProcessName -like "*powershell*") {
                    throw "Another instance is already running (PID: $ExistingPID)"
                }
            }
        }
        
        $PID | Out-File -FilePath $Config.PIDFilePath -Force
        $Global:AntivirusState.Running = $true
        Write-AVLog "Antivirus protection started (PID: $PID)"
    } catch {
        Write-AVLog "Initialization failed: $_" "ERROR"
        throw
    }
}

function Initialize-HMACKey {
    $KeyPath = $Config.HMACKeyPath
    if (Test-Path $KeyPath) {
        $Global:AntivirusState.HMACKey = [Convert]::FromBase64String((Get-Content $KeyPath -Raw))
    } else {
        $Key = New-Object byte[] 32
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
        $Global:AntivirusState.HMACKey = $Key
        [Convert]::ToBase64String($Key) | Set-Content $KeyPath
    }
    Write-AVLog "Database integrity system initialized"
}

function Initialize-Database {
    $DBPath = Join-Path $Config.DatabasePath "database.json"
    if (!(Test-Path $DBPath)) {
        $DB = @{ Threats = @(); Scans = @(); Version = 1 }
        $DB | ConvertTo-Json -Depth 10 | Set-Content $DBPath
    }
    
    $Global:AntivirusState.Database = Get-Content $DBPath -Raw | ConvertFrom-Json
    
    if (Test-Path $Config.WhitelistPath) {
        $Global:AntivirusState.Whitelist = Get-Content $Config.WhitelistPath | ConvertFrom-Json
    } else {
        $Global:AntivirusState.Whitelist = @()
        @() | ConvertTo-Json | Set-Content $Config.WhitelistPath
    }
    
    Write-AVLog "Database loaded"
}

function Start-ManagedJob {
    param(
        [string]$ModuleName,
        [int]$IntervalSeconds,
        [hashtable]$Parameters = @{}
    )
    
    $JobName = "AV_$ModuleName"
    
    if (Get-Job -Name $JobName -ErrorAction SilentlyContinue) {
        Write-AVLog "Job $JobName already running" "WARN"
        return
    }
    
    $Job = Start-Job -Name $JobName -ScriptBlock {
        param($ModulePath, $Interval, $Params, $ConfigData)
        
        Import-Module $ModulePath -Force
        $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($ModulePath)
        $FunctionName = "Invoke-$ModuleName"
        
        while ($true) {
            try {
                & $FunctionName @Params @ConfigData
            } catch {
                Write-Output "[$ModuleName] Error: $_"
            }
            Start-Sleep -Seconds $Interval
        }
    } -ArgumentList (Join-Path $Script:ModulesPath "$ModuleName.psm1"), $IntervalSeconds, $Parameters, $Config
    
    $Global:AntivirusState.Jobs[$JobName] = $Job
    Write-AVLog "Started job: $JobName (Interval: ${IntervalSeconds}s)"
}

function Monitor-Jobs {
    while ($Global:AntivirusState.Running) {
        foreach ($JobName in @($Global:AntivirusState.Jobs.Keys)) {
            $Job = $Global:AntivirusState.Jobs[$JobName]
            
            if ($Job.State -eq "Failed") {
                Write-AVLog "Job $JobName failed, restarting..." "WARN"
                Remove-Job -Name $JobName -Force
                $Global:AntivirusState.Jobs.Remove($JobName)
            }
            
            $Output = Receive-Job -Job $Job -ErrorAction SilentlyContinue
            if ($Output) {
                foreach ($Line in $Output) {
                    Write-AVLog $Line
                }
            }
        }
        
        Start-Sleep -Seconds 5
    }
}

# ============================================================================
# UNSIGNED DLL SCANNER (UNTOUCHED - RUNS SEPARATELY)
# ============================================================================

function Start-UnsignedDLLScanner {
    if (-not $Config.EnableUnsignedDLLScanner) {
        return
    }
    
    $UnsignedDLLPath = Join-Path $Script:ModulesPath "UnsignedDLL-Scanner.ps1"
    
    if (-not (Test-Path $UnsignedDLLPath)) {
        Write-AVLog "Unsigned DLL Scanner not found at $UnsignedDLLPath" "WARN"
        return
    }
    
    $Job = Start-Job -Name "AV_UnsignedDLLScanner_Standalone" -FilePath $UnsignedDLLPath
    Write-AVLog "Started Unsigned DLL Scanner as standalone process"
    Write-Host "[+] Started Unsigned DLL Scanner (Standalone)" -ForegroundColor Green
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if ($Uninstall) {
    Uninstall-Antivirus
}

try {
    Write-Host "`n======================================" -ForegroundColor Cyan
    Write-Host "  Modular Antivirus Protection v4.0" -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan
    
    Install-Antivirus
    Initialize-Mutex
    Initialize-HMACKey
    Initialize-Database
    
    Write-Host "`n[*] Discovering and loading detection modules..." -ForegroundColor Cyan
    
    $DiscoveredModules = Get-ChildItem -Path $Script:ModulesPath -Filter "*.psm1" -ErrorAction SilentlyContinue
    
    $LoadedCount = 0
    foreach ($ModuleFile in $DiscoveredModules) {
        $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($ModuleFile.Name)
        
        # Get interval from config or use default
        $IntervalKey = "${ModuleName}IntervalSeconds"
        $IntervalSeconds = if ($Script:ManagedJobConfig.$IntervalKey) {
            $Script:ManagedJobConfig.$IntervalKey
        } else {
            30  # Default interval for unknown modules
        }
        
        try {
            Start-ManagedJob -ModuleName $ModuleName -IntervalSeconds $IntervalSeconds
            Write-Host "[+] Loaded: $ModuleName (Interval: ${IntervalSeconds}s)" -ForegroundColor Green
            $LoadedCount++
        } catch {
            Write-Host "[!] Failed to load $ModuleName : $_" -ForegroundColor Red
            Write-AVLog "Failed to load module $ModuleName : $_" "ERROR"
        }
    }
    
    Write-Host "`n[+] Successfully loaded $LoadedCount/$($DiscoveredModules.Count) detection modules!" -ForegroundColor Green
    
    Write-Host "`n[*] Starting Unsigned DLL Scanner..." -ForegroundColor Cyan
    Start-UnsignedDLLScanner
    
    Write-Host "[*] Monitoring active - Press Ctrl+C to stop`n" -ForegroundColor Yellow
    
    Monitor-Jobs

} catch {
    $ErrorMsg = $_.Exception.Message
    Write-Host "[!] Error during initialization: $ErrorMsg" -ForegroundColor Red
    Write-AVLog "Initialization error: $ErrorMsg" "ERROR"
    
    # Only exit if it's a critical error (another instance running)
    if ($ErrorMsg -like "*already running*") {
        Write-Host "[!] Exiting - another instance is running" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[*] Attempting to continue despite error..." -ForegroundColor Yellow
} finally {
    if ($Global:AntivirusState.Mutex) {
        $Global:AntivirusState.Mutex.ReleaseMutex()
        $Global:AntivirusState.Mutex.Dispose()
    }
    foreach ($JobName in $Global:AntivirusState.Jobs.Keys) {
        Stop-Job -Name $JobName -ErrorAction SilentlyContinue
        Remove-Job -Name $JobName -Force -ErrorAction SilentlyContinue
    }
}
