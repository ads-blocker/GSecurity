function Invoke-RansomwareDetection {
    param([bool]$AutoKillThreats = $true)
    
    $RansomwareIndicators = @(
        "vssadmin delete shadows",
        "wbadmin delete catalog",
        "bcdedit /set {default} recoveryenabled no",
        "wmic shadowcopy delete"
    )
    
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
            
            foreach ($Indicator in $RansomwareIndicators) {
                if ($CommandLine -match [regex]::Escape($Indicator)) {
                    Write-Output "[Ransomware] THREAT: Ransomware behavior detected | Process: $($Process.ProcessName) | PID: $($Process.Id) | Command: $CommandLine"
                    
                    if ($AutoKillThreats) {
                        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                        Write-Output "[Ransomware] Terminated: $($Process.ProcessName)"
                    }
                    break
                }
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-RansomwareDetection
