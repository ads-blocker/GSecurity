param([switch]$Uninstall)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# Modular Antivirus & EDR - Core Launcher (STABILITY FIXES)
# Author: Gorstak (Enhanced by v0)
# Version: 5.1 - Stability & Persistence Update
# ============================================================================

$Script:InstallPath = "C:\ProgramData\AntivirusProtection"
$Script:ModulesPath = "$Script:InstallPath\Modules"
$Script:ScriptName = Split-Path -Leaf $PSCommandPath
$Script:MaxCacheSize = 10000
$Script:MaxRestartAttempts = 3
$Script:StabilityLogPath = "$Script:InstallPath\Logs\stability_log.txt"

$Script:ManagedJobConfig = @{
    HashDetectionIntervalSeconds = 15
    LOLBinDetectionIntervalSeconds = 15
    ProcessAnomalyDetectionIntervalSeconds = 15
    AMSIBypassDetectionIntervalSeconds = 15
    CredentialDumpDetectionIntervalSeconds = 15
    WMIPersistenceDetectionIntervalSeconds = 120
    ScheduledTaskDetectionIntervalSeconds = 120
    RegistryPersistenceDetectionIntervalSeconds = 120
    DLLHijackingDetectionIntervalSeconds = 90
    TokenManipDetectionIntervalSeconds = 60
    ProcessHollowDetectionIntervalSeconds = 30
    KeyloggerDetectionIntervalSeconds = 45
    KeyScramblerManagementIntervalSeconds = 60
    RansomwareDetectionIntervalSeconds = 15
    NetworkAnomalyDetectionIntervalSeconds = 30
    NetworkTrafficMonitoringIntervalSeconds = 45
    RootkitDetectionIntervalSeconds = 180
    ClipboardMonitorIntervalSeconds = 30
    COMMonitorIntervalSeconds = 120
    BrowserExtensionMonitoringIntervalSeconds = 300
    ShadowCopyMonitoringIntervalSeconds = 30
    USBMonitoringIntervalSeconds = 20
    EventLogMonitoringIntervalSeconds = 60
    FirewallRuleMonitoringIntervalSeconds = 120
    ServiceMonitoringIntervalSeconds = 60
    FilelessMalwareDetectionIntervalSeconds = 20
    MemoryScanningIntervalSeconds = 90
    NamedPipeMonitoringIntervalSeconds = 45
    DNSExfiltrationDetectionIntervalSeconds = 30
    PasswordManagementIntervalSeconds = 120
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
    MutexName = "Local\AntivirusProtection_Mutex_{0}_{1}" -f $env:COMPUTERNAME, $env:USERNAME
    
    CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/"
    
    ExclusionPaths = @()
    ExclusionProcesses = @("powershell", "pwsh")
    
    EnableUnsignedDLLScanner = $true
    AutoKillThreats = $true
    AutoQuarantine = $true
    MaxMemoryUsageMB = 500
    EnableSelfDefense = $true
}

$Config.ExclusionPaths = @(
    $Script:InstallPath,
    $Script:ModulesPath,
    "$Script:InstallPath\Logs",
    "$Script:InstallPath\Quarantine",
    "$Script:InstallPath\Reports",
    "$Script:InstallPath\Data"
)

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
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    $currentPath = $PSCommandPath
    
    if ($currentPath -eq $targetScript) {
        Write-Host "[+] Running from install location" -ForegroundColor Green
        $Global:AntivirusState.Installed = $true
        # Still need to setup persistence if not already done
        Install-Persistence
        return $true
    }
    
    Write-Host "`n=== Installing Antivirus ===`n" -ForegroundColor Cyan
    
    # Create directory structure
    @("Data","Logs","Quarantine","Reports","Modules") | ForEach-Object {
        $p = Join-Path $Script:InstallPath $_
        if (!(Test-Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            Write-Host "[+] Created: $p"
        }
    }
    
    # Copy main script
    Copy-Item -Path $PSCommandPath -Destination $targetScript -Force
    Write-Host "[+] Copied main script to $targetScript"
    
    # Copy all .psm1 modules
    $sourceDir = Split-Path -Path $PSCommandPath -Parent
    Get-ChildItem -Path $sourceDir -Filter "*.psm1" -File -ErrorAction SilentlyContinue | ForEach-Object {
        $dest = Join-Path $Script:ModulesPath $_.Name
        Copy-Item -Path $_.FullName -Destination $dest -Force
        Write-Host "[+] Module: $($_.Name)"
    }
    
    # Copy UnsignedDLL-Scanner if exists
    $srcScanner = Join-Path $sourceDir "UnsignedDLL-Scanner.ps1"
    if (Test-Path $srcScanner) {
        Copy-Item -Path $srcScanner -Destination (Join-Path $Script:ModulesPath "UnsignedDLL-Scanner.ps1") -Force
        Write-Host "[+] Copied UnsignedDLL-Scanner.ps1"
    }
    
    # Setup persistence for auto-start after reboot
    Install-Persistence
    
    Write-Host "`n[+] Installation complete. Continuing in this instance...`n" -ForegroundColor Green
    $Global:AntivirusState.Installed = $true
    return $true
}

function Install-Persistence {
    Write-Host "`n[*] Setting up persistence for automatic startup...`n" -ForegroundColor Cyan
    
    try {
        # Remove existing task if it exists
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue | 
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        
        # Create scheduled task for auto-start at boot and login
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($Script:InstallPath)\$($Script:ScriptName)`""
        $taskTrigger = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
        $taskTriggerBoot = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
        
        Register-ScheduledTask -TaskName "AntivirusProtection" -Action $taskAction -Trigger $taskTrigger,$taskTriggerBoot -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop
        
        Write-Host "[+] Scheduled task created for automatic startup" -ForegroundColor Green
        Write-StabilityLog "Persistence setup completed - scheduled task created"
    }
    catch {
        Write-Host "[!] Failed to create scheduled task: $_" -ForegroundColor Red
        Write-StabilityLog "Persistence setup failed: $_" "ERROR"
        
        # Fallback: Create startup shortcut
        try {
            $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            $shortcutPath = Join-Path $startupFolder "AntivirusProtection.lnk"
            
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = "powershell.exe"
            $shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$($Script:InstallPath)\$($Script:ScriptName)`""
            $shortcut.WorkingDirectory = $Script:InstallPath
            $shortcut.Save()
            
            Write-Host "[+] Fallback: Created startup shortcut" -ForegroundColor Yellow
            Write-StabilityLog "Fallback persistence: startup shortcut created"
        }
        catch {
            Write-Host "[!] Both scheduled task and shortcut failed: $_" -ForegroundColor Red
            Write-StabilityLog "All persistence methods failed: $_" "ERROR"
        }
    }
}

function Uninstall-Antivirus {
    Write-Host "`n=== Uninstalling Antivirus ===`n" -ForegroundColor Cyan
    Write-StabilityLog "Starting uninstall process"
    
    # Stop all jobs
    foreach ($job in $Global:AntivirusState.Jobs.Values) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    
    # Remove scheduled task
    try {
        Get-ScheduledTask -TaskName "AntivirusProtection" -ErrorAction SilentlyContinue | 
            Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Removed scheduled task" -ForegroundColor Green
        Write-StabilityLog "Removed scheduled task during uninstall"
    }
    catch {
        Write-Host "[!] Failed to remove scheduled task: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove scheduled task: $_" "WARN"
    }
    
    # Remove startup shortcut
    try {
        $shortcutPath = Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" "AntivirusProtection.lnk"
        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed startup shortcut" -ForegroundColor Green
            Write-StabilityLog "Removed startup shortcut during uninstall"
        }
    }
    catch {
        Write-Host "[!] Failed to remove startup shortcut: $_" -ForegroundColor Yellow
        Write-StabilityLog "Failed to remove startup shortcut: $_" "WARN"
    }
    
    # Remove installation directory
    if (Test-Path $Script:InstallPath) {
        Remove-Item -Path $Script:InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed installation directory" -ForegroundColor Green
        Write-StabilityLog "Removed installation directory during uninstall"
    }
    
    Write-Host "[+] Uninstall complete." -ForegroundColor Green
    Write-StabilityLog "Uninstall process completed"
    exit 0
}

function Write-AVLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    $logFile = Join-Path $Config.LogPath "antivirus_log.txt"
    
    if (!(Test-Path $Config.LogPath)) { 
        New-Item -ItemType Directory -Path $Config.LogPath -Force | Out-Null 
    }
    
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    
    $eid = switch ($Level) {
        "ERROR" { 1001 }
        "WARN" { 1002 }
        "THREAT" { 1003 }
        default { 1000 }
    }
    
    Write-EventLog -LogName Application -Source $Config.EDRName -EntryType Information -EventId $eid -Message $Message -ErrorAction SilentlyContinue
}

function Write-StabilityLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] [STABILITY] $Message"
    
    if (!(Test-Path (Split-Path $Script:StabilityLogPath -Parent))) { 
        New-Item -ItemType Directory -Path (Split-Path $Script:StabilityLogPath -Parent) -Force | Out-Null 
    }
    
    Add-Content -Path $Script:StabilityLogPath -Value $entry -ErrorAction SilentlyContinue
    Write-Host $entry -ForegroundColor $(switch($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} default {"White"} })
}

function Initialize-Mutex {
    $mutexName = $Config.MutexName
    
    Write-StabilityLog "Initializing mutex and PID checks"
    
    # Check if PID file exists and process is still running
    if (Test-Path $Config.PIDFilePath) {
        try {
            $existingPID = Get-Content $Config.PIDFilePath -ErrorAction Stop
            $existingProcess = Get-Process -Id $existingPID -ErrorAction SilentlyContinue
            
            if ($existingProcess) {
                Write-StabilityLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                Write-Host "[!] Another instance is already running (PID: $existingPID)" -ForegroundColor Yellow
                Write-AVLog "Blocked duplicate instance - existing PID: $existingPID" "WARN"
                throw "Another instance is already running (PID: $existingPID)"
            }
            else {
                # Stale PID file, remove it
                Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                Write-StabilityLog "Removed stale PID file (process $existingPID not running)"
                Write-AVLog "Removed stale PID file (process $existingPID not running)"
            }
        }
        catch {
            if ($_.Exception.Message -like "*already running*") {
                throw
            }
            # PID file exists but can't be read or is invalid, remove it
            Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
            Write-StabilityLog "Removed invalid PID file"
        }
    }
    
    try {
        $Global:AntivirusState.Mutex = New-Object System.Threading.Mutex($false, $mutexName)
        $acquired = $Global:AntivirusState.Mutex.WaitOne(3000)
        
        if (!$acquired) {
            Write-StabilityLog "Failed to acquire mutex - another instance is running" "ERROR"
            Write-Host "[!] Failed to acquire mutex - another instance is running" -ForegroundColor Yellow
            throw "Another instance is already running (mutex locked)"
        }
        
        # Write PID file
        $PID | Out-File -FilePath $Config.PIDFilePath -Force
        $Global:AntivirusState.Running = $true
        Write-StabilityLog "Mutex acquired, PID file written: $PID"
        Write-AVLog "Antivirus started (PID: $PID)"
        Write-Host "[+] Process ID: $PID" -ForegroundColor Green
        
        # Register cleanup on exit
        Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
            try {
                Write-StabilityLog "PowerShell exiting - cleaning up mutex and PID"
                if ($Global:AntivirusState.Mutex) {
                    $Global:AntivirusState.Mutex.ReleaseMutex()
                    $Global:AntivirusState.Mutex.Dispose()
                }
                if (Test-Path $Config.PIDFilePath) {
                    Remove-Item $Config.PIDFilePath -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-StabilityLog "Cleanup error: $_" "ERROR"
            }
        } | Out-Null
        
    }
    catch {
        Write-StabilityLog "Mutex initialization failed: $_" "ERROR"
        throw
    }
}

function Start-ManagedJob {
    param(
        [string]$ModuleName,
        [int]$IntervalSeconds = 30
    )
    
    $jobName = "AV_$ModuleName"
    
    if ($Global:AntivirusState.Jobs.ContainsKey($jobName)) { 
        return 
    }
    
    $modulePath = Join-Path $Script:ModulesPath "$ModuleName.psm1"
    
    if (!(Test-Path $modulePath)) { 
        Write-AVLog "Module not found: $modulePath" "WARN"
        return 
    }
    
    try {
        $testImport = Import-Module $modulePath -PassThru -ErrorAction Stop
        Remove-Module $testImport.Name -ErrorAction SilentlyContinue
    }
    catch {
        Write-AVLog "Module validation failed: $ModuleName - $_" "ERROR"
        return
    }
    
    # Start the job
    $job = Start-Job -Name $jobName -ScriptBlock {
        param($modPath, $cfg)
        
        try {
            Import-Module $modPath -Force -ErrorAction Stop
            $modName = [IO.Path]::GetFileNameWithoutExtension($modPath)
            $func = "Invoke-$modName"
            
            if (Get-Command $func -ErrorAction SilentlyContinue) {
                & $func @cfg
            }
            else {
                Write-Output "[$modName ERROR] Function $func not found in module"
            }
        }
        catch {
            Write-Output "[$modName ERROR] $_"
        }
    } -ArgumentList $modulePath, $Config
    
    $Global:AntivirusState.Jobs[$jobName] = @{
        Job = $job
        IntervalSeconds = $IntervalSeconds
        LastRun = Get-Date
        Module = $ModuleName
    }
    
    Write-AVLog "Started job: $jobName (${IntervalSeconds}s interval)"
}

function Monitor-Jobs {
    Write-Host "`n[*] Monitoring started. Press Ctrl+C to stop.`n" -ForegroundColor Cyan
    Write-StabilityLog "Entering main monitoring loop"
    Write-AVLog "Entering main monitoring loop"
    
    $iteration = 0
    $lastStabilityCheck = Get-Date
    $consecutiveErrors = 0
    $maxConsecutiveErrors = 10
    
    try {
        while ($true) {
            $iteration++
            $now = Get-Date
            
            # Stability check every 5 minutes
            if (($now - $lastStabilityCheck).TotalMinutes -ge 5) {
                try {
                    $activeJobs = Get-Job -Name "AV_*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Running" }
                    Write-StabilityLog "Stability check: $($activeJobs.Count) active jobs, iteration $iteration"
                    $lastStabilityCheck = $now
                    $consecutiveErrors = 0  # Reset error counter on successful check
                }
                catch {
                    $consecutiveErrors++
                    Write-StabilityLog "Stability check failed: $_" "WARN"
                }
            }
            
            # Too many consecutive errors - trigger recovery
            if ($consecutiveErrors -ge $maxConsecutiveErrors) {
                Write-StabilityLog "Too many consecutive errors ($consecutiveErrors), triggering recovery" "ERROR"
                Start-RecoverySequence
                $consecutiveErrors = 0
            }
            
            # Heartbeat every minute
            if ($iteration % 12 -eq 0) {
                try {
                    Write-Host "[v0] Monitoring active - $($Global:AntivirusState.Jobs.Count) jobs running" -ForegroundColor DarkGray
                    Write-StabilityLog "Heartbeat: $($Global:AntivirusState.Jobs.Count) jobs, iteration $iteration"
                    Write-AVLog "Heartbeat: $($Global:AntivirusState.Jobs.Count) jobs active"
                }
                catch {
                    $consecutiveErrors++
                    Write-StabilityLog "Heartbeat failed: $_" "WARN"
                }
            }
            
            $jobNames = @($Global:AntivirusState.Jobs.Keys)
            
            foreach ($jobName in $jobNames) {
                try {
                    if (-not $Global:AntivirusState.Jobs.ContainsKey($jobName)) {
                        continue
                    }
                    
                    $jobInfo = $Global:AntivirusState.Jobs[$jobName]
                    if (-not $jobInfo) {
                        continue
                    }
                    
                    $job = $null
                    try {
                        $job = Get-Job -Name $jobName -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-StabilityLog "Get-Job failed for $jobName : $_" "WARN"
                        continue
                    }
                    
                    if (-not $job) {
                        # Job doesn't exist, recreate it
                        try {
                            $elapsed = ($now - $jobInfo.LastRun).TotalSeconds
                            if ($elapsed -ge $jobInfo.IntervalSeconds) {
                                Write-StabilityLog "Recreating missing job: $jobName"
                                $Global:AntivirusState.Jobs.Remove($jobName)
                                Start-ManagedJob -ModuleName $jobInfo.Module -IntervalSeconds $jobInfo.IntervalSeconds
                            }
                        }
                        catch {
                            Write-StabilityLog "Failed to recreate job $jobName : $_" "ERROR"
                            $consecutiveErrors++
                        }
                    }
                    elseif ($job.State -eq 'Completed') {
                        # Collect output safely
                        try {
                            $output = Receive-Job -Job $job -ErrorAction SilentlyContinue
                            if ($output) {
                                foreach ($line in $output) {
                                    try {
                                        if ($line) {
                                            $lineStr = $line.ToString()
                                            Write-AVLog "[$jobName] $lineStr"
                                        }
                                    }
                                    catch {
                                        Write-StabilityLog "Failed to process output line from $jobName" "WARN"
                                    }
                                }
                            }
                        }
                        catch {
                            Write-StabilityLog "Failed to receive output from $jobName : $_" "ERROR"
                            $consecutiveErrors++
                        }
                        
                        # Clean up and restart job
                        try {
                            Remove-Job -Name $jobName -Force -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-StabilityLog "Failed to remove completed job $jobName" "WARN"
                        }
                        
                        try {
                            $elapsed = ($now - $jobInfo.LastRun).TotalSeconds
                            if ($elapsed -ge $jobInfo.IntervalSeconds) {
                                $Global:AntivirusState.Jobs.Remove($jobName)
                                Start-ManagedJob -ModuleName $jobInfo.Module -IntervalSeconds $jobInfo.IntervalSeconds
                            }
                        }
                        catch {
                            Write-StabilityLog "Failed to restart completed job $jobName : $_" "ERROR"
                            $consecutiveErrors++
                        }
                    }
                    elseif ($job.State -in 'Failed','Stopped') {
                        Write-StabilityLog "Job $jobName failed (State: $($job.State))" "WARN"
                        Write-AVLog "Job $jobName failed (State: $($job.State))" "WARN"
                        
                        # Try to get error output
                        try {
                            $output = Receive-Job -Job $job -ErrorAction SilentlyContinue
                            if ($output) {
                                Write-StabilityLog "[$jobName ERROR] $output" "ERROR"
                                Write-AVLog "[$jobName ERROR] $output" "ERROR"
                            }
                        }
                        catch {
                            Write-StabilityLog "Can't get error output from $jobName" "WARN"
                        }
                        
                        try {
                            Remove-Job -Name $jobName -Force -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-StabilityLog "Failed to remove failed job $jobName" "WARN"
                        }
                        
                        # Restart after interval
                        try {
                            $elapsed = ($now - $jobInfo.LastRun).TotalSeconds
                            if ($elapsed -ge $jobInfo.IntervalSeconds) {
                                $Global:AntivirusState.Jobs.Remove($jobName)
                                Start-ManagedJob -ModuleName $jobInfo.Module -IntervalSeconds $jobInfo.IntervalSeconds
                            }
                        }
                        catch {
                            Write-StabilityLog "Failed to restart failed job $jobName : $_" "ERROR"
                            $consecutiveErrors++
                        }
                    }
                    elseif ($job.State -eq 'Running') {
                        # Check if job is stuck (running too long)
                        try {
                            $elapsed = ($now - $jobInfo.LastRun).TotalSeconds
                            if ($elapsed -gt ($jobInfo.IntervalSeconds * 3)) {
                                Write-StabilityLog "Job $jobName appears stuck, restarting" "WARN"
                                Write-AVLog "Job $jobName appears stuck, restarting" "WARN"
                                Stop-Job -Name $jobName -ErrorAction SilentlyContinue
                                Remove-Job -Name $jobName -Force -ErrorAction SilentlyContinue
                                $Global:AntivirusState.Jobs.Remove($jobName)
                                Start-ManagedJob -ModuleName $jobInfo.Module -IntervalSeconds $jobInfo.IntervalSeconds
                            }
                        }
                        catch {
                            Write-StabilityLog "Failed to handle stuck job $jobName" "WARN"
                        }
                    }
                }
                catch {
                    $consecutiveErrors++
                    Write-StabilityLog "Job processing error for $jobName : $_" "ERROR"
                    try {
                        Write-AVLog "Job processing error for $jobName : $_" "ERROR"
                    }
                    catch {
                        # Even logging failed, just continue
                    }
                }
            }
            
            # Reset error counter on successful iteration
            if ($consecutiveErrors -gt 0) {
                $consecutiveErrors = [Math]::Max(0, $consecutiveErrors - 1)
            }
            
            Start-Sleep -Seconds 5
        }
    }
    catch {
        # Outer loop error - log and continue
        try {
            Write-StabilityLog "Monitor-Jobs outer loop error: $_" "ERROR"
            Write-AVLog "Monitor-Jobs iteration error: $_" "ERROR"
            Write-Host "[!] Monitor iteration error (recovering): $_" -ForegroundColor Yellow
        }
        catch {
            # Can't even log, just sleep and continue
        }
        
        # Don't exit - enter recovery mode
        Start-RecoverySequence
        Start-Sleep -Seconds 5
        
        # Restart monitoring
        Monitor-Jobs
    }
}

function Start-RecoverySequence {
    Write-StabilityLog "Starting recovery sequence" "WARN"
    
    try {
        # Clean up all jobs
        Get-Job -Name "AV_*" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Job $_ -ErrorAction SilentlyContinue
                Remove-Job $_ -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-StabilityLog "Failed to clean up job $($_.Name)" "WARN"
            }
        }
        
        # Clear job state
        $Global:AntivirusState.Jobs.Clear()
        
        # Wait a bit before restarting
        Start-Sleep -Seconds 10
        
        Write-StabilityLog "Recovery sequence completed"
    }
    catch {
        Write-StabilityLog "Recovery sequence failed: $_" "ERROR"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    if ($Uninstall) { 
        Uninstall-Antivirus 
    }
    
    Write-Host "`nModular Antivirus Protection v5.1 (Stability Update)`n" -ForegroundColor Cyan
    Write-StabilityLog "=== Antivirus Starting ==="
    
    Install-Antivirus

    # Initialize mutex
    Initialize-Mutex
    
    # Create event log source
    if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EDRName)) {
        New-EventLog -LogName Application -Source $Config.EDRName -ErrorAction SilentlyContinue
    }
    
    Write-Host "[*] Loading detection modules...`n" -ForegroundColor Cyan
    Write-StabilityLog "Starting module loading phase"

    $loaded = 0
    $failed = 0
    
    # Load all .psm1 modules from Modules directory
    Get-ChildItem -Path $Script:ModulesPath -Filter "*.psm1" -File -ErrorAction SilentlyContinue | ForEach-Object {
        $modName = [IO.Path]::GetFileNameWithoutExtension($_.Name)
        $key = "${modName}IntervalSeconds"
        $interval = if ($Script:ManagedJobConfig.ContainsKey($key)) { 
            $Script:ManagedJobConfig[$key] 
        } else { 
            60 
        }
        
        try {
            Start-ManagedJob -ModuleName $modName -IntervalSeconds $interval
            
            if ($Global:AntivirusState.Jobs.ContainsKey("AV_$modName")) {
                Write-Host "[+] $modName ($interval sec)" -ForegroundColor Green
                Write-StabilityLog "Successfully loaded module: $modName"
                $loaded++
            }
            else {
                Write-Host "[!] $modName - skipped (validation failed)" -ForegroundColor Yellow
                Write-StabilityLog "Module validation failed: $modName" "WARN"
                $failed++
            }
        }
        catch {
            Write-Host "[!] Failed to start $modName : $_" -ForegroundColor Red
            Write-StabilityLog "Module load failed: $modName - $_" "ERROR"
            Write-AVLog "Module load failed: $modName - $_" "ERROR"
            $failed++
        }
    }
    
    Write-Host "`n[+] Loaded $loaded modules" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "[!] $failed modules failed to load" -ForegroundColor Yellow
    }
    
    Write-StabilityLog "Module loading complete: $loaded loaded, $failed failed"

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Antivirus Protection ACTIVE" -ForegroundColor Green
    Write-Host "  Active jobs: $($Global:AntivirusState.Jobs.Count)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "`nPress Ctrl+C to stop`n" -ForegroundColor Yellow
    
    Write-StabilityLog "Antivirus fully started with $($Global:AntivirusState.Jobs.Count) active jobs"
    Write-AVLog "About to enter Monitor-Jobs loop"
    Write-Host "[v0] Entering Monitor-Jobs - script should never exit from here" -ForegroundColor Magenta
    
    Monitor-Jobs
    
    # This line should NEVER be reached since Monitor-Jobs has while($true)
    Write-Host "[!] WARNING: Monitor-Jobs exited unexpectedly!" -ForegroundColor Red
    Write-StabilityLog "Monitor-Jobs exited unexpectedly - entering emergency loop" "ERROR"
    Write-AVLog "Monitor-Jobs exited - entering emergency loop" "ERROR"
    
    # Emergency infinite loop - script must NEVER exit
    Write-Host "[v0] Emergency loop active - script will not exit" -ForegroundColor Yellow
    while ($true) {
        Start-Sleep -Seconds 30
        Write-StabilityLog "Emergency loop heartbeat" "WARN"
        Write-Host "[v0] Emergency loop heartbeat - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor DarkGray
    }
}
catch {
    $err = $_.Exception.Message
    Write-Host "`n[!] Critical error: $err`n" -ForegroundColor Red
    Write-StabilityLog "Critical startup error: $err" "ERROR"
    Write-AVLog "Startup error: $err" "ERROR"
    
    if ($err -like "*already running*") {
        Write-Host "[i] Another instance is running. Exiting.`n" -ForegroundColor Yellow
        Write-StabilityLog "Blocked duplicate instance - exiting" "INFO"
        exit 1
    }
    
    $targetScript = Join-Path $Script:InstallPath $Script:ScriptName
    if ($PSCommandPath -eq $targetScript) {
        Write-Host "[!] Error occurred but keeping script alive (install location)" -ForegroundColor Yellow
        Write-StabilityLog "Entering error recovery loop - script will not exit" "WARN"
        while ($true) {
            Start-Sleep -Seconds 30
            Write-StabilityLog "Error recovery loop heartbeat" "WARN"
            Write-Host "[v0] Error recovery loop - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor DarkGray
        }
    }
    else {
        # Only exit if we're NOT at install location
        Write-StabilityLog "Exiting - not running from install location" "INFO"
        exit 1
    }
}

# This should NEVER be reached
Write-Host "[!] CRITICAL: Script reached end of file!" -ForegroundColor Red
Write-StabilityLog "Script reached EOF - entering final safety loop" "ERROR"
while ($true) { 
    Start-Sleep -Seconds 60 
    Write-StabilityLog "EOF safety loop heartbeat" "ERROR"
    Write-Host "[v0] EOF safety loop" -ForegroundColor Magenta
}
