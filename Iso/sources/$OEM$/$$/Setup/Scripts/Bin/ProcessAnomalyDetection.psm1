function Invoke-ProcessAnomalyDetection {
    param(
        [bool]$AutoKillThreats = $true
    )
    
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        $Score = 0
        $Reasons = @()
        
        if ($Process.Path -notmatch "^C:\\(Windows|Program Files)" -and $Process.ProcessName -match "^(svchost|lsass|csrss|services|smss|wininit)$") {
            $Score += 40
            $Reasons += "System process in non-system location"
        }
        
        try {
            $ParentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop | 
                Select-Object -ExpandProperty ParentProcessId
            $Parent = Get-Process -Id $ParentProcess -ErrorAction SilentlyContinue
            
            if ($Parent -and $Parent.ProcessName -match "^(winword|excel|outlook|powerpnt)$" -and $Process.ProcessName -match "^(powershell|cmd|wscript|cscript)$") {
                $Score += 35
                $Reasons += "Script launched from Office"
            }
        } catch {}
        
        if ($Process.Threads.Count -gt 100) {
            $Score += 15
            $Reasons += "Excessive threads: $($Process.Threads.Count)"
        }
        
        if ($Process.WorkingSet64 -gt 1GB) {
            $Score += 10
            $Reasons += "High memory usage: $([Math]::Round($Process.WorkingSet64/1GB, 2)) GB"
        }
        
        try {
            $Connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
            if ($Connections.Count -gt 50) {
                $Score += 20
                $Reasons += "Excessive connections: $($Connections.Count)"
            }
        } catch {}
        
        if ($Score -ge 50) {
            Write-Output "[ProcessAnomaly] THREAT: $($Process.ProcessName) | PID: $($Process.Id) | Score: $Score | Reasons: $($Reasons -join ', ')"
            
            if ($AutoKillThreats) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                Write-Output "[ProcessAnomaly] Terminated: $($Process.ProcessName) (PID: $($Process.Id))"
            }
        }
    }
}

Export-ModuleMember -Function Invoke-ProcessAnomalyDetection
