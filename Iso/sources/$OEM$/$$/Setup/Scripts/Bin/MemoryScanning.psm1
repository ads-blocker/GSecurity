function Invoke-MemoryScanning {
    param([bool]$AutoKillThreats = $true)
    
    $Processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 100MB }
    
    foreach ($Process in $Processes) {
        try {
            if ($Process.PrivateMemorySize64 -gt $Process.WorkingSet64 * 2) {
                Write-Output "[MemoryScan] SUSPICIOUS: Memory anomaly | Process: $($Process.ProcessName) | PID: $($Process.Id) | Private: $([Math]::Round($Process.PrivateMemorySize64/1MB)) MB"
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-MemoryScanning
