param([switch]$Uninstall)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# Production Hardened Antivirus & EDR
# Author: Gorstak
# ============================================================================

$Script:InstallPath = "C:\ProgramData\AntivirusProtection"
$Script:ScriptName = "Antivirus.ps1"
$Script:MaxTerminationAttempts = 5
$Script:TerminationAttemptCount = 0
$Script:AutoRestart = $false
$Script:MaxCacheSize = 10000
$Script:MaxRestartAttempts = 3

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
    MaxRestartAttempts = 3
    RestartDelaySeconds = 5
    ScannedFilesMaxCount = 5000
}

$Config = @{
    EDRName = "MalwareDetector"
    LogPath = "$Script:InstallPath\Logs"
    QuarantinePath = "$Script:InstallPath\Quarantine"
    DatabasePath = "$Script:InstallPath\Data"
    WhitelistPath = "$Script:InstallPath\Data\whitelist.json"
    ScannedFilesPath = "$Script:InstallPath\Data\scanned_files.txt"
    ReportsPath = "$Script:InstallPath\Reports"
    HMACKeyPath = "$Script:InstallPath\Data\db_integrity.hmac"
    PIDFilePath = "$Script:InstallPath\Data\antivirus.pid"
    MutexName = "Global\AntivirusProtection_Mutex"
    
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
    EnableShadowCopyMonitoring = $false
    EnableUSBMonitoring = $false
    EnableEventLogMonitoring = $false
    EnableBrowserExtensionMonitoring = $false
    EnableFirewallRuleMonitoring = $false
    
    AutoKillThreats = $true
    AutoQuarantine = $true
    EnableDatabaseIntegrity = $true
    IntegrityCheckInterval = 3600
    MaxMemoryUsageMB = 500
    CacheExpirationHours = 24
    LogRotationDays = 30
    EnableSelfDefense = $true
    EnableAntiTamper = $true
    AddToStartup = $true
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
    CacheHits = 0
    CacheMisses = 0
    StartTime = [DateTime]::Now
}

# ============================================================================
# INSTALLATION & SETUP
# ============================================================================

function Install-Antivirus {
    Write-Host "`n=== Installing Antivirus Protection ===`n" -ForegroundColor Cyan
    
    if (!(Test-Path $Script:InstallPath)) {
        New-Item -ItemType Directory -Path $Script:InstallPath -Force | Out-Null
        Write-Host "[+] Created installation directory: $Script:InstallPath"
    }
    
    $Subdirs = @("Data", "Logs", "Quarantine", "Reports")
    foreach ($Dir in $Subdirs) {
        $Path = Join-Path $Script:InstallPath $Dir
        if (!(Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Host "[+] Created directory: $Path"
        }
    }
    
    $CurrentScript = $MyInvocation.PSCommandPath
    $TargetScript = Join-Path $Script:InstallPath $Script:ScriptName
    
    if ($CurrentScript -ne $TargetScript) {
        Copy-Item -Path $CurrentScript -Destination $TargetScript -Force
        Write-Host "[+] Copied script to: $TargetScript"
    }
    
    
    try {
        New-EventLog -LogName Application -Source $Config.EDRName -ErrorAction SilentlyContinue
        Write-Host "[+] Registered event log source"
    } catch {}
    
    $Global:AntivirusState.Installed = $true
    Write-Host "`n[+] Installation complete!`n" -ForegroundColor Green
    
    if ($CurrentScript -ne $TargetScript) {
        Write-Host "[!] Relaunching from installation directory...`n" -ForegroundColor Yellow
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$TargetScript`"" -Verb RunAs
        exit 0
    }
}

function Uninstall-Antivirus {
    Write-Host "`n=== Uninstalling Antivirus Protection ===`n" -ForegroundColor Cyan
    
    Write-Host "[*] Stopping running instances..."
    Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*AntivirusProtection*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    
    
    Write-Host "[*] Removing installation directory..."
    Write-Host "    Note: Quarantine and logs are preserved. Delete manually if needed."
    Remove-Item -Path (Join-Path $Script:InstallPath $Script:ScriptName) -Force -ErrorAction SilentlyContinue
    
    Write-Host "`n[+] Uninstallation complete!`n" -ForegroundColor Green
    exit 0
}

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO", [string]$LogFile = "antivirus_log.txt")
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    $LogFilePath = Join-Path $Config.LogPath $LogFile
    Add-Content -Path $LogFilePath -Value $LogEntry -ErrorAction SilentlyContinue
    
    $EventID = switch($Level) { "ERROR" {1001}; "WARN" {1002}; "THREAT" {1003}; default {1000} }
    Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Information -EventId $EventID -Message $Message -ErrorAction SilentlyContinue
}

function Initialize-Mutex {
    try {
        $PIDFile = $Config.PIDFilePath
        
        if (Test-Path $PIDFile) {
            $OldPID = Get-Content $PIDFile -ErrorAction SilentlyContinue
            if ($OldPID) {
                $Process = Get-Process -Id $OldPID -ErrorAction SilentlyContinue
                if (!$Process -or $Process.ProcessName -ne "powershell") {
                    Remove-Item $PIDFile -Force -ErrorAction SilentlyContinue
                    try {
                        $StaleMutex = [System.Threading.Mutex]::OpenExisting($Config.MutexName)
                        $StaleMutex.Dispose()
                    } catch {}
                }
            }
        }
        
        $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $Config.MutexName)
        $Acquired = $Global:AntivirusState.Mutex.WaitOne(500)
        
        if (!$Acquired) {
            throw "Another instance of Antivirus is already running"
        }
        
        $PID | Out-File -FilePath $PIDFile -Force
        $Global:AntivirusState.Running = $true
        Write-AVLog "Antivirus protection started"
    } catch {
        Write-AVLog "Mutex initialization failed: $_" "ERROR"
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
        
        try {
            $Acl = Get-Acl $KeyPath
            $Acl.SetAccessRuleProtection($true, $false)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
            $Acl.AddAccessRule($Rule)
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
            $Acl.AddAccessRule($Rule)
            Set-Acl $KeyPath $Acl
        } catch {}
    }
    Write-AVLog "Database integrity system initialized"
}

function Get-HMAC {
    param([string]$Data)
    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
    $HMAC.Key = $Global:AntivirusState.HMACKey
    return [BitConverter]::ToString($HMAC.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))).Replace("-","")
}

function Initialize-Database {
    $DBPath = Join-Path $Config.DatabasePath "database.json"
    if (!(Test-Path $DBPath)) {
        $DB = @{ Threats = @(); Scans = @(); Version = 1 }
        $JSON = $DB | ConvertTo-Json -Depth 10
        $Signature = Get-HMAC -Data $JSON
        @{ Data = $JSON; Signature = $Signature } | ConvertTo-Json | Set-Content $DBPath
    }
    
    $Content = Get-Content $DBPath -Raw | ConvertFrom-Json
    $Signature = Get-HMAC -Data $Content.Data
    if ($Signature -ne $Content.Signature) {
        Write-AVLog "Database integrity check failed" "ERROR"
        exit 1
    }
    
    $Global:AntivirusState.Database = $Content.Data | ConvertFrom-Json
    
    $WhitelistPath = $Config.WhitelistPath
    if (Test-Path $WhitelistPath) {
        $Global:AntivirusState.Whitelist = Get-Content $WhitelistPath | ConvertFrom-Json
    } else {
        $Global:AntivirusState.Whitelist = @()
        @() | ConvertTo-Json | Set-Content $WhitelistPath
    }
    
    Write-AVLog "Database loaded and verified"
}

function Save-Database {
    $DBPath = Join-Path $Config.DatabasePath "database.json"
    $JSON = $Global:AntivirusState.Database | ConvertTo-Json -Depth 10
    $Signature = Get-HMAC -Data $JSON
    @{ Data = $JSON; Signature = $Signature } | ConvertTo-Json | Set-Content $DBPath
}

function Add-ToWhitelist {
    param(
        [string]$FilePath,
        [string]$ProcessName,
        [string]$Reason = "User approved",
        [string]$Category = "Approved"
    )
    
    $Entry = @{
        Timestamp = Get-Date
        FilePath = $FilePath
        ProcessName = $ProcessName
        Hash = if ($FilePath) { (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { $null }
        Reason = $Reason
        Category = $Category
    }
    
    $Global:AntivirusState.Whitelist += $Entry
    $Global:AntivirusState.Whitelist | ConvertTo-Json | Set-Content $Config.WhitelistPath
    Write-AVLog "Added to whitelist: $FilePath$ProcessName - $Reason"
}

function Remove-FromWhitelist {
    param([string]$Identifier)
    
    $Global:AntivirusState.Whitelist = $Global:AntivirusState.Whitelist | Where-Object {
        $_.Hash -ne $Identifier -and $_.FilePath -ne $Identifier -and $_.ProcessName -ne $Identifier
    }
    
    $Global:AntivirusState.Whitelist | ConvertTo-Json | Set-Content $Config.WhitelistPath
    Write-AVLog "Removed from whitelist: $Identifier"
}

function Test-Whitelist {
    param([string]$Path, [string]$Hash, [string]$ProcessName)
    
    foreach ($Entry in $Global:AntivirusState.Whitelist) {
        if (($Entry.FilePath -eq $Path) -or ($Entry.Hash -eq $Hash) -or ($Entry.ProcessName -eq $ProcessName)) {
            return $true
        }
    }
    return $false
}

function Get-FileHashFast {
    param([string]$Path)
    
    $CacheKey = "$Path|$(( Get-Item $Path -ErrorAction SilentlyContinue).LastWriteTime.Ticks)"
    
    if ($Global:AntivirusState.Cache.ContainsKey($CacheKey)) {
        $Global:AntivirusState.CacheHits++
        return $Global:AntivirusState.Cache[$CacheKey]
    }
    
    $Global:AntivirusState.CacheMisses++
    
    try {
        $Hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        
        if ($Global:AntivirusState.Cache.Count -ge $Script:MaxCacheSize) {
            $OldestKey = $Global:AntivirusState.Cache.Keys | Select-Object -First 1
            $Global:AntivirusState.Cache.Remove($OldestKey)
        }
        
        $Global:AntivirusState.Cache[$CacheKey] = $Hash
        return $Hash
    } catch {
        return $null
    }
}

function Move-ToQuarantine {
    param([string]$Path, [string]$Reason)
    
    $FileName = [System.IO.Path]::GetFileName($Path)
    $QuarantineFile = "$($Config.QuarantinePath)\$([DateTime]::Now.Ticks)_$FileName"
    
    try {
        [System.IO.File]::Move($Path, $QuarantineFile)
        $Global:AntivirusState.FilesQuarantined++
        Write-AVLog "Quarantined: $Path (Reason: $Reason)" "THREAT"
        return $true
    } catch {
        Write-AVLog "Quarantine failed for $Path : $_" "ERROR"
        return $false
    }
}

function Stop-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    
    if ($ProcessId -eq $PID) { return }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        $Global:AntivirusState.ProcessesTerminated++
        Write-AVLog "Terminated threat process: $ProcessName (PID: $ProcessId)" "ACTION"
    } catch {
        Write-AVLog "Failed to terminate process $ProcessName : $_" "ERROR"
    }
}

# ============================================================================
# DETECTION ENGINES (Enterprise-grade implementations)
# ============================================================================

function Invoke-HashDetection {
    $KnownMalwareHashes = @{
        MD5 = @("44D88612FEA8A8F36DE82E1278ABB02F", "3395856CE81F2B7382DEE72602F798B6", "B3215C06647BC550406A9C8CACA1E7FD", "E6F87D2B5D7A0C8F1E4D3A9B8C7F2E1D")
        SHA256 = @("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", "5F4DCC3B5AA765D61D8327DEB882CF99")
    }
    $ScanPaths = @("$env:TEMP", "$env:USERPROFILE\Downloads", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")
    $SuspiciousExtensions = @(".exe", ".dll", ".scr", ".vbs", ".js", ".ps1", ".bat", ".cmd", ".msi", ".jar")
    
    foreach ($Path in $ScanPaths) {
        if (-not (Test-Path $Path)) { continue }
        $Files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue -Depth 2 | 
                 Where-Object { $SuspiciousExtensions -contains $_.Extension }
        
        foreach ($File in $Files) {
            $Global:AntivirusState.FilesScanned++
            try {
                # Multi-algorithm hash check
                $MD5Hash = (Get-FileHash -Path $File.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                $SHA256Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                
                # Known malware signature check
                if ($KnownMalwareHashes.MD5 -contains $MD5Hash -or $KnownMalwareHashes.SHA256 -contains $SHA256Hash) {
                    Write-AVLog "CRITICAL: Known malware detected - File: $($File.FullName) | MD5: $MD5Hash | SHA256: $SHA256Hash" "THREAT" "behavior_detections.log"
                    $Global:AntivirusState.ThreatCount++
                    if ($Config.AutoQuarantine) { Move-ToQuarantine -Path $File.FullName -Reason "Known malware signature match" }
                    continue
                }
                
                # Entropy analysis for packed/encrypted executables
                if ($File.Extension -in @(".exe", ".dll")) {
                    $Bytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    if ($Bytes.Length -gt 1024) {
                        $Entropy = 0
                        $FreqTable = @{}
                        foreach ($Byte in $Bytes[0..1023]) {
                            if (-not $FreqTable.ContainsKey($Byte)) { $FreqTable[$Byte] = 0 }
                            $FreqTable[$Byte]++
                        }
                        foreach ($Freq in $FreqTable.Values) {
                            $Probability = $Freq / 1024.0
                            $Entropy -= $Probability * [Math]::Log($Probability, 2)
                        }
                        
                        # High entropy indicates encryption/packing (>7.2 is suspicious)
                        if ($Entropy -gt 7.2) {
                            Write-AVLog "Suspicious packed/encrypted file detected - File: $($File.FullName) | Entropy: $([Math]::Round($Entropy, 2)) | Size: $($File.Length)" "WARNING" "behavior_detections.log"
                            if ($Entropy -gt 7.8) {
                                $Global:AntivirusState.ThreatCount++
                                if ($Config.AutoQuarantine) { Move-ToQuarantine -Path $File.FullName -Reason "Extremely high entropy ($([Math]::Round($Entropy, 2)))" }
                            }
                        }
                    }
                }
                
                # Suspicious file creation time analysis (created in last hour in temp directories)
                if ($File.CreationTime -gt (Get-Date).AddHours(-1) -and $File.DirectoryName -match "Temp|tmp") {
                    if ($File.Extension -in @(".exe", ".dll", ".scr")) {
                        Write-AVLog "Suspicious recent file creation - File: $($File.FullName) | Created: $($File.CreationTime)" "WARNING" "behavior_detections.log"
                    }
                }
                
            } catch {
                Write-AVLog "Hash detection error for $($File.FullName): $_" "ERROR"
            }
        }
    }
}

function Invoke-LOLBinDetection {
    $LOLBinPatterns = @{
        "certutil" = @{
            Patterns = @("-decode", "-urlcache", "-verifyctl", "-encode")
            Severity = "HIGH"
            Description = "Certutil abuse for download/decode"
        }
        "bitsadmin" = @{
            Patterns = @("transfer", "addfile", "/download")
            Severity = "HIGH"
            Description = "BITS abuse for download"
        }
        "mshta" = @{
            Patterns = @("http://", "https://", "javascript:", "vbscript:")
            Severity = "CRITICAL"
            Description = "MSHTA remote code execution"
        }
        "regsvr32" = @{
            Patterns = @("scrobj.dll", "/s", "/u", "http://", "https://")
            Severity = "HIGH"
            Description = "Regsvr32 squiblydoo attack"
        }
        "rundll32" = @{
            Patterns = @("javascript:", "http://", "https://", "shell32.dll,Control_RunDLL")
            Severity = "MEDIUM"
            Description = "Rundll32 proxy execution"
        }
        "wmic" = @{
            Patterns = @('process call create', '/node:', 'format:"http', 'xsl:http')
            Severity = "HIGH"
            Description = "WMIC remote execution or XSL abuse"
        }
        "powershell" = @{
            Patterns = @("-enc ", "-encodedcommand", "downloadstring", "iex ", "invoke-expression", "-nop", "-w hidden", "bypass")
            Severity = "HIGH"
            Description = "PowerShell obfuscation and evasion"
        }
        "sc" = @{
            Patterns = @("create", "config", "binpath=")
            Severity = "MEDIUM"
            Description = "Service manipulation"
        }
        "msiexec" = @{
            Patterns = @("/quiet", "/q", "http://", "https://")
            Severity = "MEDIUM"
            Description = "Silent MSI installation from remote"
        }
    }
    
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID) { continue }
        $CmdLine = $Proc.CommandLine
        if (-not $CmdLine) { continue }
        
        $ProcessName = $Proc.Name -replace '\.exe$', ''
        
        foreach ($LOLBin in $LOLBinPatterns.Keys) {
            if ($ProcessName -like "*$LOLBin*") {
                $MatchedPatterns = @()
                foreach ($Pattern in $LOLBinPatterns[$LOLBin].Patterns) {
                    if ($CmdLine -match [regex]::Escape($Pattern)) {
                        $MatchedPatterns += $Pattern
                    }
                }
                
                if ($MatchedPatterns.Count -gt 0) {
                    $Severity = $LOLBinPatterns[$LOLBin].Severity
                    $Description = $LOLBinPatterns[$LOLBin].Description
                    Write-AVLog "LOLBin detected [$Severity] - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Attack: $Description | Patterns: $($MatchedPatterns -join ', ') | Command: $CmdLine" "THREAT" "behavior_detections.log"
                    $Global:AntivirusState.ThreatCount++
                    
                    if ($Config.AutoKillThreats -and $Severity -in @("HIGH", "CRITICAL")) {
                        Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name
                    }
                }
            }
        }
    }
}

function Invoke-FilelessDetection {
    $FilelessIndicators = @{
        MemoryInjection = @("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtQueueApcThread", "RtlCreateUserThread")
        ReflectiveLoading = @("Assembly.Load", "[Reflection.Assembly]::Load", "LoadLibraryA", "GetProcAddress")
        Obfuscation = @("IEX", "Invoke-Expression", "FromBase64String", "DownloadString", "WebClient", "Net.WebClient")
        ProcessInjection = @("OpenProcess", "ZwUnmapViewOfSection", "NtUnmapViewOfSection", "VirtualProtect")
    }
    
    $ScriptProcesses = Get-Process powershell*, cmd, wscript, cscript, mshta -ErrorAction SilentlyContinue
    
    foreach ($Proc in $ScriptProcesses) {
        if ($Proc.Id -eq $PID) { continue }
        
        try {
            $ProcessInfo = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)" -ErrorAction SilentlyContinue
            $CmdLine = $ProcessInfo.CommandLine
            if (-not $CmdLine) { continue }
            
            $DetectionScore = 0
            $MatchedIndicators = @()
            
            # Check for memory injection techniques
            foreach ($Indicator in $FilelessIndicators.MemoryInjection) {
                if ($CmdLine -match [regex]::Escape($Indicator)) {
                    $DetectionScore += 3
                    $MatchedIndicators += "MemoryInjection:$Indicator"
                }
            }
            
            # Check for reflective loading
            foreach ($Indicator in $FilelessIndicators.ReflectiveLoading) {
                if ($CmdLine -match [regex]::Escape($Indicator)) {
                    $DetectionScore += 2
                    $MatchedIndicators += "ReflectiveLoading:$Indicator"
                }
            }
            
            # Check for obfuscation
            foreach ($Indicator in $FilelessIndicators.Obfuscation) {
                if ($CmdLine -match [regex]::Escape($Indicator)) {
                    $DetectionScore += 1
                    $MatchedIndicators += "Obfuscation:$Indicator"
                }
            }
            
            # Check for process injection
            foreach ($Indicator in $FilelessIndicators.ProcessInjection) {
                if ($CmdLine -match [regex]::Escape($Indicator)) {
                    $DetectionScore += 3
                    $MatchedIndicators += "ProcessInjection:$Indicator"
                }
            }
            
            # Check for parent process anomalies
            $Parent = Get-Process -Id $ProcessInfo.ParentProcessId -ErrorAction SilentlyContinue
            if ($Parent -and $Parent.ProcessName -notin @("explorer", "services", "svchost", "wmiprvse")) {
                $DetectionScore += 1
                $MatchedIndicators += "SuspiciousParent:$($Parent.ProcessName)"
            }
            
            # Alert based on detection score
            if ($DetectionScore -ge 4) {
                Write-AVLog "CRITICAL fileless attack detected - Process: $($Proc.Name) (PID: $($Proc.Id)) | Score: $DetectionScore | Indicators: $($MatchedIndicators -join ', ') | Command: $($CmdLine.Substring(0, [Math]::Min(200, $CmdLine.Length)))" "THREAT" "behavior_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.Id -ProcessName $Proc.Name }
            }
            elseif ($DetectionScore -ge 2) {
                Write-AVLog "Suspicious fileless activity - Process: $($Proc.Name) (PID: $($Proc.Id)) | Score: $DetectionScore | Indicators: $($MatchedIndicators -join ', ')" "WARNING" "behavior_detections.log"
            }
            
        } catch {
            Write-AVLog "Fileless detection error for PID $($Proc.Id): $_" "ERROR"
        }
    }
}

function Invoke-MemoryScanning {
    $SuspiciousModules = @("mimikatz", "pwdump", "gsecdump", "wce.exe", "procdump")
    $TargetProcesses = Get-Process powershell*, cmd, wscript, cscript, rundll32, regsvr32 -ErrorAction SilentlyContinue
    
    foreach ($Proc in $TargetProcesses) {
        if ($Proc.Id -eq $PID) { continue }
        
        try {
            # Check working set size anomalies
            $WS = $Proc.WorkingSet64
            if ($WS -gt 500MB) {
                Write-AVLog "Memory anomaly: Process $($Proc.Name) (PID: $($Proc.Id)) has unusually large working set: $([Math]::Round($WS/1MB, 2)) MB" "WARNING"
            }
            
            # Check for suspicious modules loaded
            $Modules = $Proc.Modules | Where-Object { $_.ModuleName -match ($SuspiciousModules -join '|') }
            if ($Modules) {
                Write-AVLog "Suspicious module loaded - Process: $($Proc.Name) (PID: $($Proc.Id)) | Module: $($Modules.ModuleName -join ', ')" "THREAT" "behavior_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.Id -ProcessName $Proc.Name }
            }
            
            # Check for unsigned modules in critical processes
            foreach ($Module in $Proc.Modules) {
                try {
                    $Signature = Get-AuthenticodeSignature -FilePath $Module.FileName -ErrorAction SilentlyContinue
                    if ($Signature -and $Signature.Status -ne "Valid" -and $Module.FileName -notmatch "Windows\\System32") {
                        Write-AVLog "Unsigned module detected - Process: $($Proc.Name) (PID: $($Proc.Id)) | Module: $($Module.FileName) | Status: $($Signature.Status)" "WARNING"
                    }
                } catch {}
            }
            
            # Analyze command line for memory manipulation APIs
            $ProcessInfo = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)" -ErrorAction SilentlyContinue
            if ($ProcessInfo.CommandLine -match "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|QueueUserAPC") {
                Write-AVLog "Memory injection API detected - Process: $($Proc.Name) (PID: $($Proc.Id)) | Command: $($ProcessInfo.CommandLine)" "THREAT" "behavior_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.Id -ProcessName $Proc.Name }
            }
            
        } catch {
            Write-AVLog "Memory scanning error for PID $($Proc.Id): $_" "ERROR"
        }
    }
}

function Invoke-ProcessAnomalyDetection {
    $Processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $AnomalyScore = @{}
    
    foreach ($Proc in $Processes) {
        if ($Proc.ProcessId -eq $PID) { continue }
        $Score = 0
        $Anomalies = @()
        
        # Parent process analysis
        $Parent = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($Parent) {
            # Office spawning scripts
            if ($Parent.Name -match "winword|excel|powerpnt|outlook" -and $Proc.Name -match "powershell|cmd|wscript|cscript") {
                $Score += 5
                $Anomalies += "OfficeSpawnScript"
            }
            
            # Explorer spawning hidden scripts
            if ($Parent.Name -eq "explorer.exe" -and $Proc.CommandLine -match "-w hidden|-windowstyle hidden|-nop|-enc") {
                $Score += 4
                $Anomalies += "ExplorerHiddenScript"
            }
            
            # Service host spawning unexpected processes
            if ($Parent.Name -eq "svchost.exe" -and $Proc.Name -notmatch "dllhost|conhost|rundll32") {
                $Score += 3
                $Anomalies += "SvchostUnexpectedChild"
            }
        }
        
        # Path validation
        $ProcPath = $Proc.ExecutablePath
        if ($ProcPath) {
            # Executables in user directories
            if ($ProcPath -match "Users\\.*\\AppData|Users\\.*\\Downloads|Users\\.*\\Desktop" -and $Proc.Name -match "exe$") {
                $Score += 2
                $Anomalies += "UserDirExecution"
            }
            
            # System binaries in wrong locations
            if ($Proc.Name -in @("svchost.exe", "lsass.exe", "csrss.exe", "smss.exe") -and $ProcPath -notmatch "C:\\Windows\\System32") {
                $Score += 6
                $Anomalies += "SystemBinaryWrongLocation"
            }
        }
        
        # Command line analysis
        if ($Proc.CommandLine) {
            # Base64 encoded commands
            if ($Proc.CommandLine -match "-enc |-encodedcommand |FromBase64String") {
                $Score += 3
                $Anomalies += "Base64Encoding"
            }
            
            # Execution policy bypass
            if ($Proc.CommandLine -match "-exec bypass|-executionpolicy bypass|-ep bypass") {
                $Score += 2
                $Anomalies += "ExecutionPolicyBypass"
            }
            
            # Download cradles
            if ($Proc.CommandLine -match "DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget |curl ") {
                $Score += 3
                $Anomalies += "DownloadCradle"
            }
        }
        
        # Report anomalies
        if ($Score -ge 6) {
            Write-AVLog "CRITICAL process anomaly - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Parent: $($Parent.Name) | Score: $Score | Anomalies: $($Anomalies -join ', ') | Path: $ProcPath | Command: $($Proc.CommandLine)" "THREAT" "behavior_detections.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
        elseif ($Score -ge 3) {
            Write-AVLog "Process anomaly detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Score: $Score | Anomalies: $($Anomalies -join ', ')" "WARNING" "behavior_detections.log"
        }
    }
}

function Invoke-AMSIBypassDetection {
    $AMSIBypassPatterns = @{
        ClassPatch = @("AmsiUtils", "amsiInitFailed", "amsiContext")
        DLLUnload = @("Amsi.dll", "FreeLibrary.*amsi")
        MemoryPatch = @("\[Ref\]\.Assembly\.GetType.*Amsi", "AmsiScanBuffer")
        Reflection = @("System.Management.Automation.AmsiUtils", "Automation\.Amsi")
        ETWBypass = @("EtwEventWrite", "ntdll.*Etw")
    }
    
    $ScriptProcesses = Get-Process powershell*, pwsh -ErrorAction SilentlyContinue
    
    foreach ($Proc in $ScriptProcesses) {
        if ($Proc.Id -eq $PID) { continue }
        
        try {
            $ProcessInfo = Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)" -ErrorAction SilentlyContinue
            $CmdLine = $ProcessInfo.CommandLine
            if (-not $CmdLine) { continue }
            
            $BypassDetected = $false
            $BypassMethods = @()
            
            foreach ($Category in $AMSIBypassPatterns.Keys) {
                foreach ($Pattern in $AMSIBypassPatterns[$Category]) {
                    if ($CmdLine -match $Pattern) {
                        $BypassDetected = $true
                        $BypassMethods += "$Category`:$Pattern"
                    }
                }
            }
            
            if ($BypassDetected) {
                Write-AVLog "AMSI bypass attempt detected - Process: $($Proc.Name) (PID: $($Proc.Id)) | Methods: $($BypassMethods -join ', ') | Command: $($CmdLine.Substring(0, [Math]::Min(200, $CmdLine.Length)))" "THREAT" "behavior_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.Id -ProcessName $Proc.Name }
            }
            
        } catch {
            Write-AVLog "AMSI bypass detection error for PID $($Proc.Id): $_" "ERROR"
        }
    }
}

function Invoke-CredentialDumpDetection {
    $CredentialTools = @("mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce.exe", "procdump", "dumpert", "nanodump", "lsassy")
    $LSASSAccess = @("lsass", "LSASS")
    
    # Monitor for processes accessing LSASS
    $LsassProc = Get-Process lsass -ErrorAction SilentlyContinue
    if ($LsassProc) {
        $AccessingProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -match "lsass" -and $_.ProcessId -ne $LsassProc.Id -and $_.ProcessId -ne $PID
        }
        
        foreach ($Proc in $AccessingProcesses) {
            Write-AVLog "LSASS access detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
    
    # Detect credential dumping tools
    $AllProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $AllProcesses) {
        if ($Proc.ProcessId -eq $PID) { continue }
        
        # Check process name and command line
        foreach ($Tool in $CredentialTools) {
            if ($Proc.Name -like "*$Tool*" -or $Proc.CommandLine -match $Tool) {
                Write-AVLog "Credential dumping tool detected - Tool: $Tool | Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
                $Global:AntivirusState.ThreatCount++
                if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
            }
        }
        
        # Check for memory dump creation
        if ($Proc.CommandLine -match "MiniDump|CreateDump|dmp") {
            Write-AVLog "Memory dump creation detected - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "WARNING" "credential_dumping_detections.log"
        }
    }
    
    # Check for SAM/SYSTEM/SECURITY registry hive access
    $RegKeyAccess = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "SAM|SYSTEM|SECURITY" -and $_.CommandLine -match "reg save|reg export"
    }
    
    foreach ($Proc in $RegKeyAccess) {
        if ($Proc.ProcessId -eq $PID) { continue }
        Write-AVLog "Registry credential hive access - Process: $($Proc.Name) (PID: $($Proc.ProcessId)) | Command: $($Proc.CommandLine)" "THREAT" "credential_dumping_detections.log"
        $Global:AntivirusState.ThreatCount++
        if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
    }
}


function Invoke-WMIPersistenceDetection {
    try {
        $Consumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
        foreach ($Consumer in $Consumers) {
            if ($Consumer.CommandLineTemplate -match "powershell|cmd") {
                Write-AVLog "WMI persistence: $($Consumer.Name)" "THREAT"
                $Global:AntivirusState.ThreatCount++
            }
        }
    } catch {}
}

function Invoke-ScheduledTaskDetection {
    try {
        $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
        foreach ($Task in $Tasks) {
            $Action = $Task.Actions | Select-Object -First 1
            if ($Action -and ($Action.Execute + " " + $Action.Arguments) -match "powershell.*-enc|regsvr32.*scrobj") {
                Write-AVLog "Suspicious task: $($Task.TaskName)" "THREAT"
                $Global:AntivirusState.ThreatCount++
            }
        }
    } catch {}
}

function Invoke-DNSExfiltrationDetection {
    try {
        $Connections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 53 }
        if ($Connections.Count -gt 100) {
            Write-AVLog "DNS exfiltration suspected: $($Connections.Count) queries" "THREAT" "network_anomalies.log"
            $Global:AntivirusState.ThreatCount++
        }
    } catch {}
}

function Invoke-NamedPipeMonitoring {
    try {
        $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        foreach ($Pipe in $Pipes) {
            $PipeName = [System.IO.Path]::GetFileName($Pipe)
            if ($PipeName -match "msagent_|MSSE-|postex_|status_") {
                Write-AVLog "Suspicious named pipe: $PipeName" "THREAT" "network_anomalies.log"
                $Global:AntivirusState.ThreatCount++
            }
        }
    } catch {}
}

function Invoke-RegistryPersistenceDetection {
    $Keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    foreach ($Key in $Keys) {
        try {
            $Entries = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
            foreach ($Entry in $Entries.PSObject.Properties) {
                if ($Entry.Value -match "powershell.*-enc|regsvr32.*http") {
                    Write-AVLog "Registry persistence: $Key - $($Entry.Name)" "THREAT"
                    $Global:AntivirusState.ThreatCount++
                }
            }
        } catch {}
    }
}

function Invoke-DLLHijackingDetection {
    $Dirs = @("C:\Windows\System32", "C:\Windows\SysWOW64")
    $SuspiciousDLLs = @("version.dll", "msvcr100.dll", "dwmapi.dll")
    foreach ($Dir in $Dirs) {
        foreach ($DLL in $SuspiciousDLLs) {
            $Path = Join-Path $Dir $DLL
            if (Test-Path $Path) {
                $File = Get-Item $Path
                if ($File.LastWriteTime -gt (Get-Date).AddHours(-1)) {
                    Write-AVLog "Potential DLL hijacking: $Path" "THREAT"
                    $Global:AntivirusState.ThreatCount++
                }
            }
        }
    }
}

function Invoke-TokenManipulationDetection {
    $Procs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Procs) {
        if ($Proc.ProcessId -eq $PID) { continue }
        if ($Proc.CommandLine -match "DuplicateTokenEx|ImpersonateLoggedOnUser") {
            Write-AVLog "Token manipulation: $($Proc.Name) PID: $($Proc.ProcessId)" "THREAT"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
}

function Invoke-ProcessHollowingDetection {
    $Procs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Procs) {
        if ($Proc.ProcessId -eq $PID) { continue }
        if ($Proc.CommandLine -match "CREATE_SUSPENDED|NtUnmapViewOfSection") {
            Write-AVLog "Process hollowing: $($Proc.Name) PID: $($Proc.ProcessId)" "THREAT"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
}

function Invoke-KeyloggerDetection {
    $Procs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Procs) {
        if ($Proc.ProcessId -eq $PID) { continue }
        if ($Proc.CommandLine -match "SetWindowsHookEx|GetAsyncKeyState") {
            Write-AVLog "Keylogger: $($Proc.Name) PID: $($Proc.ProcessId)" "THREAT"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.ProcessId -ProcessName $Proc.Name }
        }
    }
}

function Invoke-RansomwareDetection {
    $Procs = Get-Process vssadmin, bcdedit, wbadmin -ErrorAction SilentlyContinue
    foreach ($Proc in $Procs) {
        $CmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)" -ErrorAction SilentlyContinue).CommandLine
        if ($CmdLine -match "delete shadows|delete catalog") {
            Write-AVLog "Ransomware behavior: $($Proc.Name) deleting backups" "THREAT"
            $Global:AntivirusState.ThreatCount++
            if ($Config.AutoKillThreats) { Stop-ThreatProcess -ProcessId $Proc.Id -ProcessName $Proc.Name }
        }
    }
}

function Invoke-NetworkAnomalyDetection {
    try {
        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $Groups = $Connections | Group-Object -Property OwningProcess | Where-Object { $_.Count -gt 50 }
        foreach ($Group in $Groups) {
            $Proc = Get-Process -Id $Group.Name -ErrorAction SilentlyContinue
            if ($Proc -and $Proc.Id -ne $PID) {
                Write-AVLog "Network anomaly: $($Proc.Name) has $($Group.Count) connections" "THREAT" "network_anomalies.log"
                $Global:AntivirusState.ThreatCount++
            }
        }
    } catch {}
}

function Invoke-RootkitDetection {
    $WmiProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessId
    $VisibleProcs = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
    $Hidden = Compare-Object -ReferenceObject $WmiProcs -DifferenceObject $VisibleProcs | Where-Object { $_.SideIndicator -eq "<=" }
    
    foreach ($Pid in $Hidden.InputObject) {
        Write-AVLog "Rootkit: Hidden process PID: $Pid" "THREAT"
        $Global:AntivirusState.ThreatCount++
    }
}

function Invoke-ClipboardMonitoring {
    $Procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "clip|kbd" -and $_.Id -ne $PID }
    foreach ($Proc in $Procs) {
        Write-AVLog "Clipboard access: $($Proc.Name) PID: $($Proc.Id)" "INFO"
    }
}

function Invoke-COMMonitoring {
    $Procs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    foreach ($Proc in $Procs) {
        if ($Proc.ProcessId -eq $PID) { continue }
        if ($Proc.CommandLine -match "WScript\.Shell|Shell\.Application" -and $Proc.Name -notmatch "explorer|iexplore") {
            Write-AVLog "Suspicious COM: $($Proc.Name) PID: $($Proc.ProcessId)" "THREAT"
            $Global:AntivirusState.ThreatCount++
        }
    }
}

# Stub functions for disabled modules
function Invoke-ShadowCopyMonitoring {}
function Invoke-USBMonitoring {}
function Invoke-EventLogMonitoring {}
function Invoke-BrowserExtensionMonitoring {}
function Invoke-FirewallRuleMonitoring {}

# ============================================================================
# JOB MANAGEMENT
# ============================================================================

function Register-AVJob {
    param([string]$Name, [int]$Interval, [string]$FunctionName)
    $Global:AntivirusState.Jobs[$Name] = @{
        Name = $Name
        FunctionName = $FunctionName
        Interval = $Interval
        LastRun = [DateTime]::MinValue
    }
}

function Start-AllMonitoring {
    Write-Host "`n=== Initializing Detection Modules ===`n" -ForegroundColor Cyan
    
    if ($Config.EnableHashDetection) { Register-AVJob -Name "HashDetection" -Interval $Script:ManagedJobConfig.MalwareScanIntervalSeconds -FunctionName "Invoke-HashDetection" }
    if ($Config.EnableLOLBinDetection) { Register-AVJob -Name "LOLBin" -Interval 15 -FunctionName "Invoke-LOLBinDetection" }
    if ($Config.EnableFilelessDetection) { Register-AVJob -Name "Fileless" -Interval 20 -FunctionName "Invoke-FilelessDetection" }
    if ($Config.EnableMemoryScanning) { Register-AVJob -Name "Memory" -Interval 60 -FunctionName "Invoke-MemoryScanning" }
    if ($Config.EnableProcessAnomalyDetection) { Register-AVJob -Name "ProcessAnomaly" -Interval $Script:ManagedJobConfig.ProcessAnomalyIntervalSeconds -FunctionName "Invoke-ProcessAnomalyDetection" }
    if ($Config.EnableAMSIBypassDetection) { Register-AVJob -Name "AMSIBypass" -Interval 45 -FunctionName "Invoke-AMSIBypassDetection" }
    if ($Config.EnableCredentialDumpDetection) { Register-AVJob -Name "CredentialDump" -Interval $Script:ManagedJobConfig.CredentialDumpingIntervalSeconds -FunctionName "Invoke-CredentialDumpDetection" }
    if ($Config.EnableWMIPersistenceDetection) { Register-AVJob -Name "WMIPersistence" -Interval 60 -FunctionName "Invoke-WMIPersistenceDetection" }
    if ($Config.EnableScheduledTaskDetection) { Register-AVJob -Name "ScheduledTask" -Interval $Script:ManagedJobConfig.ScheduledTaskIntervalSeconds -FunctionName "Invoke-ScheduledTaskDetection" }
    if ($Config.EnableDNSExfiltrationDetection) { Register-AVJob -Name "DNSExfiltration" -Interval 30 -FunctionName "Invoke-DNSExfiltrationDetection" }
    if ($Config.EnableNamedPipeMonitoring) { Register-AVJob -Name "NamedPipe" -Interval 20 -FunctionName "Invoke-NamedPipeMonitoring" }
    if ($Config.EnableRegistryPersistenceDetection) { Register-AVJob -Name "RegistryPersistence" -Interval $Script:ManagedJobConfig.RegistryPersistenceIntervalSeconds -FunctionName "Invoke-RegistryPersistenceDetection" }
    if ($Config.EnableDLLHijackingDetection) { Register-AVJob -Name "DLLHijacking" -Interval 30 -FunctionName "Invoke-DLLHijackingDetection" }
    if ($Config.EnableTokenManipulationDetection) { Register-AVJob -Name "TokenManipulation" -Interval 25 -FunctionName "Invoke-TokenManipulationDetection" }
    if ($Config.EnableProcessHollowingDetection) { Register-AVJob -Name "ProcessHollowing" -Interval 20 -FunctionName "Invoke-ProcessHollowingDetection" }
    if ($Config.EnableKeyloggerDetection) { Register-AVJob -Name "Keylogger" -Interval 15 -FunctionName "Invoke-KeyloggerDetection" }
    if ($Config.EnableRansomwareDetection) { Register-AVJob -Name "Ransomware" -Interval $Script:ManagedJobConfig.RansomwareBehaviorIntervalSeconds -FunctionName "Invoke-RansomwareDetection" }
    if ($Config.EnableNetworkAnomalyDetection) { Register-AVJob -Name "NetworkAnomaly" -Interval $Script:ManagedJobConfig.NetworkAnomalyIntervalSeconds -FunctionName "Invoke-NetworkAnomalyDetection" }
    if ($Config.EnableRootkitDetection) { Register-AVJob -Name "Rootkit" -Interval 120 -FunctionName "Invoke-RootkitDetection" }
    if ($Config.EnableClipboardMonitoring) { Register-AVJob -Name "Clipboard" -Interval 30 -FunctionName "Invoke-ClipboardMonitoring" }
    if ($Config.EnableCOMMonitoring) { Register-AVJob -Name "COM" -Interval 60 -FunctionName "Invoke-COMMonitoring" }
    
    Write-Host "[+] $($Global:AntivirusState.Jobs.Count) detection modules initialized`n" -ForegroundColor Green
    Write-AVLog "$($Global:AntivirusState.Jobs.Count) detection modules initialized"
}

function Invoke-AllJobs {
    foreach ($Job in $Global:AntivirusState.Jobs.Values) {
        if (((Get-Date) - $Job.LastRun).TotalSeconds -ge $Job.Interval) {
            try {
                & $Job.FunctionName
            } catch {
                Write-AVLog "Job error ($($Job.Name)): $_" "ERROR"
            }
            $Job.LastRun = Get-Date
        }
    }
}

# ============================================================================
# INTERACTIVE FEATURES
# ============================================================================

function Show-Help {
    Write-Host "`n=== Antivirus Protection - Help ===`n" -ForegroundColor Cyan
    Write-Host "Keyboard Commands:"
    Write-Host "  [H]       - Show this help menu"
    Write-Host "  [M]       - Open Exclusion Manager (whitelist)"
    Write-Host "  [R]       - Generate security report"
    Write-Host "  [Ctrl+C]  - Stop antivirus (requires $Script:MaxTerminationAttempts attempts)"
    Write-Host "`nStatus:"
    Write-Host "  Uptime:       $((Get-Date) - $Global:AntivirusState.StartTime)"
    Write-Host "  Threats:      $($Global:AntivirusState.ThreatCount)"
    Write-Host "  Files Scanned: $($Global:AntivirusState.FilesScanned)"
    Write-Host "  Quarantined:  $($Global:AntivirusState.FilesQuarantined)"
    Write-Host "  Active Jobs:  $($Global:AntivirusState.Jobs.Count)"
    Write-Host "  Cache Hit Rate: $(if($Global:AntivirusState.CacheHits + $Global:AntivirusState.CacheMisses -gt 0){[Math]::Round(($Global:AntivirusState.CacheHits/($Global:AntivirusState.CacheHits+$Global:AntivirusState.CacheMisses))*100,1)}else{0})%"
    Write-Host ""
}

function Show-ExclusionManager {
    while ($true) {
        Write-Host "`n=== Exclusion Manager ===`n" -ForegroundColor Cyan
        Write-Host "1. Add file to whitelist"
        Write-Host "2. Add process to whitelist"
        Write-Host "3. Remove from whitelist"
        Write-Host "4. View whitelist"
        Write-Host "5. Back to monitoring"
        Write-Host ""
        
        $Choice = Read-Host "Select option (1-5)"
        
        switch ($Choice) {
            "1" {
                $Path = Read-Host "Enter full file path"
                $Reason = Read-Host "Enter reason"
                Add-ToWhitelist -FilePath $Path -Reason $Reason
                Write-Host "[+] Added to whitelist" -ForegroundColor Green
            }
            "2" {
                $ProcessName = Read-Host "Enter process name (for example notepad.exe)"
                $Reason = Read-Host "Enter reason"
                Add-ToWhitelist -ProcessName $ProcessName -Reason $Reason
                Write-Host "[+] Added to whitelist" -ForegroundColor Green
            }
            "3" {
                $Id = Read-Host "Enter hash, path, or process name to remove"
                Remove-FromWhitelist -Identifier $Id
                Write-Host "[+] Removed from whitelist" -ForegroundColor Green
            }
            "4" {
                Write-Host "`nWhitelist Entries:" -ForegroundColor Yellow
                $Global:AntivirusState.Whitelist | Format-Table -AutoSize
            }
            "5" { return }
        }
    }
}

function New-SecurityReport {
    param([string]$ReportType = "Manual")
    
    $Report = @{
        Timestamp = Get-Date
        ReportType = $ReportType
        Uptime = ((Get-Date) - $Global:AntivirusState.StartTime).ToString()
        TotalThreats = $Global:AntivirusState.ThreatCount
        FilesScanned = $Global:AntivirusState.FilesScanned
        FilesQuarantined = $Global:AntivirusState.FilesQuarantined
        ProcessesTerminated = $Global:AntivirusState.ProcessesTerminated
        CacheSize = $Global:AntivirusState.Cache.Count
        CacheHitRate = if($Global:AntivirusState.CacheHits + $Global:AntivirusState.CacheMisses -gt 0){
            [Math]::Round(($Global:AntivirusState.CacheHits/($Global:AntivirusState.CacheHits+$Global:AntivirusState.CacheMisses))*100,2)
        }else{0}
        ActiveJobs = $Global:AntivirusState.Jobs.Count
        MemoryUsageMB = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
        RecentDetections = $Global:AntivirusState.Database.Threats | Select-Object -Last 10
    }
    
    $ReportPath = Join-Path $Config.ReportsPath "report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $Report | ConvertTo-Json -Depth 10 | Set-Content $ReportPath
    
    Write-Host "`n[+] Security report generated: $ReportPath`n" -ForegroundColor Green
    Write-AVLog "Security report generated ($ReportType)"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

$CurrentLocation = $MyInvocation.PSCommandPath
$ExpectedLocation = Join-Path $Script:InstallPath $Script:ScriptName

if ($Uninstall) {
    Uninstall-Antivirus
}

if ($CurrentLocation -ne $ExpectedLocation) {
    Install-Antivirus
}

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Production Hardened Antivirus & EDR  " -ForegroundColor Cyan
    Write-Host "  Author: Gorstak                      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Initialize-Mutex
    Initialize-HMACKey
    Initialize-Database
    Start-AllMonitoring
    
    Write-Host "=== Antivirus Protection Active ===" -ForegroundColor Green
    Write-Host "Press [H] for help, [M] for exclusions, [R] for report`n"
    
    $Script:TerminationAttemptCount = 0
    
    [Console]::TreatControlCAsInput = $true
    
    while ($true) {
        Invoke-AllJobs
        
        if ([Console]::KeyAvailable) {
            $Key = [Console]::ReadKey($true)
            
            if ($Key.Key -eq "C" -and $Key.Modifiers -eq "Control") {
                $Script:TerminationAttemptCount++
                Write-Host "`n[!] Termination attempt $Script:TerminationAttemptCount of $Script:MaxTerminationAttempts" -ForegroundColor Yellow
                
                if ($Script:TerminationAttemptCount -ge $Script:MaxTerminationAttempts) {
                    Write-Host "[!] Stopping antivirus...`n" -ForegroundColor Red
                    break
                }
            }
            elseif ($Key.Key -eq "H") {
                Show-Help
            }
            elseif ($Key.Key -eq "M") {
                Show-ExclusionManager
            }
            elseif ($Key.Key -eq "R") {
                New-SecurityReport
            }
        }
        
        Start-Sleep -Milliseconds 100
    }
    
} catch {
    Write-Host "`n[!] Critical error: $_`n" -ForegroundColor Red
    Write-AVLog "Critical error: $_" "ERROR"
} finally {
    Write-Host "`n[*] Shutting down antivirus protection...`n" -ForegroundColor Yellow
    
    $Global:AntivirusState.Jobs.Clear()
    
    if ($Global:AntivirusState.Mutex -and $Global:AntivirusState.Running) {
        try {
            $Global:AntivirusState.Mutex.ReleaseMutex()
            $Global:AntivirusState.Mutex.Dispose()
            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    
    Write-AVLog "Antivirus protection stopped"
    Write-Host "[+] Antivirus stopped successfully" -ForegroundColor Green
    Write-Host ""
}
