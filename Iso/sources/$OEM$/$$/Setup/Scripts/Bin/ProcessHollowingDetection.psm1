function Invoke-ProcessHollowingDetection {
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        try {
            $Modules = $Process.Modules
            if ($Modules.Count -eq 0) {
                Write-Output "[ProcessHollow] THREAT: Process with no modules | Process: $($Process.ProcessName) | PID: $($Process.Id)"
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-ProcessHollowingDetection
