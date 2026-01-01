function Invoke-CredentialDumpDetection {
    param(
        [bool]$AutoKillThreats = $true
    )
    
    $SensitiveProcesses = @("lsass", "csrss", "services")
    $SuspiciousTools = @("mimikatz", "procdump", "dumpert", "nanodump", "pypykatz")
    
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        if ($SuspiciousTools -contains $Process.ProcessName.ToLower()) {
            Write-Output "[CredDump] THREAT: Known credential dumping tool detected | Process: $($Process.ProcessName) | PID: $($Process.Id)"
            
            if ($AutoKillThreats) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                Write-Output "[CredDump] Terminated: $($Process.ProcessName)"
            }
        }
        
        try {
            $Handles = Get-Process -Id $Process.Id -ErrorAction Stop | Select-Object -ExpandProperty Handles
            if ($Handles -gt 1000) {
                foreach ($SensitiveProc in $SensitiveProcesses) {
                    $Target = Get-Process -Name $SensitiveProc -ErrorAction SilentlyContinue
                    if ($Target) {
                        Write-Output "[CredDump] SUSPICIOUS: $($Process.ProcessName) has excessive handles ($Handles) while $SensitiveProc is running"
                    }
                }
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-CredentialDumpDetection
