function Invoke-PasswordManagement {
    param(
        [bool]$EnablePasswordRotation = $false,
        [int]$RotationMinutes = 10,
        [bool]$ResetOnShutdown = $true
    )
    
    Write-Output "[Password] Starting password management monitoring..."
    
    # Check if running as Administrator
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
        Write-Output "[Password] WARNING: Not running as Administrator - limited functionality"
        $IsAdmin = $false
    }
    else {
        $IsAdmin = $true
        Write-Output "[Password] Running with Administrator privileges"
    }
    
    # Helper functions
    function Test-PasswordSecurity {
        try {
            $CurrentUser = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
            if ($CurrentUser) {
                $PasswordAge = (Get-Date) - $CurrentUser.PasswordLastSet
                $DaysSinceChange = $PasswordAge.Days
                
                # Check if password is too old
                if ($DaysSinceChange -gt 90) {
                    Write-Output "[Password] WARNING: Password is $DaysSinceChange days old - consider rotation"
                }
                
                # Check if password is blank
                if ($CurrentUser.PasswordRequired -eq $false) {
                    Write-Output "[Password] WARNING: Account does not require password"
                }
                
                # Check for weak password indicators
                $PasswordPolicy = Get-LocalUser | Where-Object { $_.Name -eq $env:USERNAME } | Select-Object PasswordRequired, PasswordChangeable, PasswordExpires
                if ($PasswordPolicy) {
                    Write-Output "[Password] INFO: Password policy - Required: $($PasswordPolicy.PasswordRequired), Changeable: $($PasswordPolicy.PasswordChangeable), Expires: $($PasswordPolicy.PasswordExpires)"
                }
                
                return @{
                    DaysSinceChange = $DaysSinceChange
                    PasswordRequired = $CurrentUser.PasswordRequired
                    PasswordLastSet = $CurrentUser.PasswordLastSet
                }
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check password security: $_"
            return $null
        }
    }
    
    function Test-SuspiciousPasswordActivity {
        try {
            # Check for recent password changes
            $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4724,4723,4738} -MaxEvents 10 -ErrorAction SilentlyContinue
            
            $RecentChanges = $SecurityEvents | Where-Object { 
                $_.TimeCreated -gt (Get-Date).AddHours(-1) -and 
                $_.Properties[0].Value -eq $env:USERNAME
            }
            
            if ($RecentChanges.Count -gt 0) {
                Write-Output "[Password] WARNING: Recent password activity detected - $($RecentChanges.Count) events in last hour"
                
                foreach ($Event in $RecentChanges) {
                    $EventType = switch ($Event.Id) {
                        4723 { "Password change attempted" }
                        4724 { "Password reset attempted" }
                        4738 { "Account policy modified" }
                        default { "Unknown event" }
                    }
                    Write-Output "[Password]   - $EventType at $($Event.TimeCreated)"
                }
            }
            
            # Check for failed password attempts
            $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }
            
            $UserFailedLogons = $FailedLogons | Where-Object { 
                $_.Properties[5].Value -eq $env:USERNAME 
            }
            
            if ($UserFailedLogons.Count -gt 5) {
                Write-Output "[Password] THREAT: High number of failed logons - $($UserFailedLogons.Count) failures in last hour"
            }
            
            return @{
                RecentChanges = $RecentChanges.Count
                FailedLogons = $UserFailedLogons.Count
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check suspicious activity: $_"
            return $null
        }
    }
    
    function Test-PasswordDumpingTools {
        try {
            $SuspiciousTools = @("mimikatz", "procdump", "dumpert", "nanodump", "pypykatz", "gsecdump", "cachedump")
            $SuspiciousProcesses = Get-Process | Where-Object { 
                $SuspiciousTools -contains $_.ProcessName.ToLower() 
            }
            
            if ($SuspiciousProcesses.Count -gt 0) {
                Write-Output "[Password] THREAT: Password dumping tools detected"
                foreach ($Process in $SuspiciousProcesses) {
                    Write-Output "[Password]   - $($Process.ProcessName) (PID: $($Process.Id))"
                }
            }
            
            # Check for suspicious command lines
            $PowerShellProcesses = Get-Process -Name "powershell" -ErrorAction SilentlyContinue
            foreach ($Process in $PowerShellProcesses) {
                try {
                    $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                    
                    $PasswordCommands = @("Get-Credential", "ConvertTo-SecureString", "Import-Clixml", "Export-Clixml")
                    foreach ($Command in $PasswordCommands) {
                        if ($CommandLine -match $Command) {
                            Write-Output "[Password] SUSPICIOUS: PowerShell process with password-related command - PID: $($Process.Id)"
                        }
                    }
                }
                catch {
                    # Access denied or process ended
                }
            }
            
            return $SuspiciousProcesses.Count
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check for dumping tools: $_"
            return 0
        }
    }
    
    # Main monitoring logic
    try {
        # Check password security status
        $PasswordStatus = Test-PasswordSecurity
        if ($PasswordStatus) {
            Write-Output "[Password] Security check completed - Password age: $($PasswordStatus.DaysSinceChange) days"
        }
        
        # Check for suspicious activity
        $ActivityStatus = Test-SuspiciousPasswordActivity
        if ($ActivityStatus) {
            Write-Output "[Password] Activity monitoring completed - Recent changes: $($ActivityStatus.RecentChanges), Failed logons: $($ActivityStatus.FailedLogons)"
        }
        
        # Check for password dumping tools
        $DumpingTools = Test-PasswordDumpingTools
        Write-Output "[Password] Dumping tools check completed - Suspicious tools: $DumpingTools"
        
        # Password rotation (if enabled and running as admin)
        if ($EnablePasswordRotation -and $IsAdmin) {
            Write-Output "[Password] Password rotation enabled - every $RotationMinutes minutes"
            
            # This would be implemented with a scheduled task or background job
            # For now, just report the capability
            Write-Output "[Password] INFO: Password rotation requires scheduled task setup"
        }
        
        # Check for password-related registry modifications
        try {
            $RegKeys = @(
                "HKLM:\SAM\SAM\Domains\Account\Users",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            )
            
            foreach ($RegKey in $RegKeys) {
                if (Test-Path $RegKey) {
                    $RecentChanges = Get-ChildItem $RegKey -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) }
                    
                    if ($RecentChanges.Count -gt 0) {
                        Write-Output "[Password] WARNING: Recent registry changes in password-related areas"
                        foreach ($Change in $RecentChanges) {
                            Write-Output "[Password]   - $($Change.PSPath) modified at $($Change.LastWriteTime)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Output "[Password] ERROR: Failed to check registry changes: $_"
        }
        
        Write-Output "[Password] Password management monitoring completed"
    }
    catch {
        Write-Output "[Password] ERROR: Monitoring failed: $_"
    }
}

Export-ModuleMember -Function Invoke-PasswordManagement
