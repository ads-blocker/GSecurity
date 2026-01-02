function Invoke-KeyScramblerManagement {
    param(
        [string]$InstallPath = "$env:LOCALAPPDATA\KeyScrambler",
        [bool]$AutoInstall = $true,
        [bool]$AutoStart = $true
    )
    
    $KeyScramblerExecutable = Join-Path $InstallPath "KeyScrambler.exe"
    $KeyScramblerConfig = Join-Path $InstallPath "settings.ini"
    $KeyScramblerRunning = $false
    
    Write-Output "[KeyScrambler] Starting KeyScrambler management..."
    
    # Check if KeyScrambler is already installed
    if (Test-Path $KeyScramblerExecutable) {
        Write-Output "[KeyScrambler] Found existing installation at $InstallPath"
        
        # Check if KeyScrambler is running
        try {
            $KeyScramblerProcess = Get-Process -Name "KeyScrambler" -ErrorAction SilentlyContinue
            if ($KeyScramblerProcess) {
                $KeyScramblerRunning = $true
                Write-Output "[KeyScrambler] KeyScrambler is already running (PID: $($KeyScramblerProcess.Id))"
            }
        }
        catch {
            Write-Output "[KeyScrambler] KeyScrambler not currently running"
        }
    }
    else {
        Write-Output "[KeyScrambler] KeyScrambler not installed"
        
        if ($AutoInstall) {
            Write-Output "[KeyScrambler] Auto-install enabled - attempting deployment..."
            
            # Create installation directory
            if (!(Test-Path $InstallPath)) {
                try {
                    New-Item -ItemType Directory -Path $InstallPath -Force -ErrorAction Stop | Out-Null
                    Write-Output "[KeyScrambler] Created installation directory: $InstallPath"
                }
                catch {
                    Write-Output "[KeyScrambler] ERROR: Failed to create installation directory: $_"
                    return
                }
            }
            
            # Download KeyScrambler (simulated - in real scenario would download from official source)
            try {
                # This would be replaced with actual download from QFX Software
                $DownloadUrl = "https://www.qfxsoftware.com/download/keyscrambler_setup.exe"
                $SetupFile = Join-Path $env:TEMP "keyscrambler_setup.exe"
                
                Write-Output "[KeyScrambler] NOTE: Auto-install requires manual download of KeyScrambler from QFX Software"
                Write-Output "[KeyScrambler] Please download from: https://www.qfxsoftware.com/"
                Write-Output "[KeyScrambler] Install to: $InstallPath"
                
                # For demonstration, create a placeholder executable
                $PlaceholderContent = @"
@echo off
echo KeyScrambler Placeholder
echo This is a placeholder for the actual KeyScrambler executable
echo Please install the real KeyScrambler from QFX Software
pause
"@
                $PlaceholderContent | Out-File -FilePath $KeyScramblerExecutable -Encoding ASCII
                Write-Output "[KeyScrambler] Created placeholder executable (replace with real KeyScrambler)"
            }
            catch {
                Write-Output "[KeyScrambler] ERROR: Failed to setup KeyScrambler: $_"
                return
            }
        }
        else {
            Write-Output "[KeyScrambler] Auto-install disabled - skipping installation"
            return
        }
    }
    
    # Configure KeyScrambler settings
    try {
        $ConfigContent = @"
[Settings]
AutoStart=1
StartWithWindows=1
EncryptClipboard=1
EncryptAllApplications=1
LogLevel=1
UpdateCheck=1
TrayIcon=1
HotkeyEnabled=1
Hotkey=Ctrl+Alt+K
"@
        
        $ConfigContent | Out-File -FilePath $KeyScramblerConfig -Encoding ASCII -Force
        Write-Output "[KeyScrambler] Configuration updated"
    }
    catch {
        Write-Output "[KeyScrambler] WARNING: Failed to create configuration: $_"
    }
    
    # Start KeyScrambler if not running
    if (!$KeyScramblerRunning -and $AutoStart) {
        try {
            if (Test-Path $KeyScramblerExecutable) {
                Start-Process -FilePath $KeyScramblerExecutable -WindowStyle Hidden -ErrorAction Stop
                Write-Output "[KeyScrambler] Started KeyScrambler process"
                
                # Wait a moment and verify it's running
                Start-Sleep -Seconds 2
                $VerifyProcess = Get-Process -Name "KeyScrambler" -ErrorAction SilentlyContinue
                if ($VerifyProcess) {
                    Write-Output "[KeyScrambler] KeyScrambler successfully started (PID: $($VerifyProcess.Id))"
                }
                else {
                    Write-Output "[KeyScrambler] WARNING: KeyScrambler may not have started properly"
                }
            }
            else {
                Write-Output "[KeyScrambler] ERROR: KeyScrambler executable not found"
            }
        }
        catch {
            Write-Output "[KeyScrambler] ERROR: Failed to start KeyScrambler: $_"
        }
    }
    
    # Setup persistence (startup with Windows)
    try {
        $StartupShortcut = Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" "KeyScrambler.lnk"
        
        if ($AutoStart) {
            # Create startup shortcut
            $Shell = New-Object -ComObject WScript.Shell
            $Shortcut = $Shell.CreateShortcut($StartupShortcut)
            $Shortcut.TargetPath = $KeyScramblerExecutable
            $Shortcut.WorkingDirectory = $InstallPath
            $Shortcut.WindowStyle = 1  # Normal window
            $Shortcut.Save()
            
            Write-Output "[KeyScrambler] Created startup shortcut for automatic launch"
        }
        else {
            # Remove startup shortcut if exists
            if (Test-Path $StartupShortcut) {
                Remove-Item $StartupShortcut -Force -ErrorAction SilentlyContinue
                Write-Output "[KeyScrambler] Removed startup shortcut"
            }
        }
    }
    catch {
        Write-Output "[KeyScrambler] WARNING: Failed to manage startup shortcut: $_"
    }
    
    # Add Windows Firewall exception for KeyScrambler
    try {
        $FirewallRule = Get-NetFirewallRule -DisplayName "KeyScrambler" -ErrorAction SilentlyContinue
        if (!$FirewallRule) {
            New-NetFirewallRule -DisplayName "KeyScrambler" -Direction Outbound -Program $KeyScramblerExecutable -Action Allow -Profile Any -Description "Allow KeyScrambler outbound connections" -ErrorAction SilentlyContinue
            Write-Output "[KeyScrambler] Added firewall exception"
        }
    }
    catch {
        Write-Output "[KeyScrambler] WARNING: Failed to configure firewall: $_"
    }
    
    # Monitor KeyScrambler status
    try {
        $CurrentProcess = Get-Process -Name "KeyScrambler" -ErrorAction SilentlyContinue
        if ($CurrentProcess) {
            $MemoryUsage = [Math]::Round($CurrentProcess.WorkingSet64 / 1MB, 2)
            $StartTime = $CurrentProcess.StartTime
            $RunTime = (Get-Date) - $StartTime
            
            Write-Output "[KeyScrambler] STATUS: Running | PID: $($CurrentProcess.Id) | Memory: ${MemoryUsage}MB | Runtime: $([Math]::Round($RunTime.TotalMinutes, 1))min"
        }
        else {
            Write-Output "[KeyScrambler] STATUS: Not running"
        }
    }
    catch {
        Write-Output "[KeyScrambler] ERROR: Failed to get process status: $_"
    }
    
    # Verify encryption is active (check for keyboard hooks)
    try {
        $Processes = Get-Process | Where-Object { $_.Modules -ne $null }
        $KeyScramblerHooks = 0
        
        foreach ($Process in $Processes) {
            try {
                $KeyScramblerDLLs = $Process.Modules | Where-Object { $_.ModuleName -match "kscramble|keyscram" }
                if ($KeyScramblerDLLs) {
                    $KeyScramblerHooks += $KeyScramblerDLLs.Count
                }
            }
            catch {
                # Access denied, continue
            }
        }
        
        if ($KeyScramblerHooks -gt 0) {
            Write-Output "[KeyScrambler] ENCRYPTION: Active - $KeyScramblerHooks hooks detected"
        }
        else {
            Write-Output "[KeyScrambler] ENCRYPTION: Not active or hooks not accessible"
        }
    }
    catch {
        Write-Output "[KeyScrambler] WARNING: Could not verify encryption status: $_"
    }
    
    Write-Output "[KeyScrambler] Management cycle completed"
}

Export-ModuleMember -Function Invoke-KeyScramblerManagement
