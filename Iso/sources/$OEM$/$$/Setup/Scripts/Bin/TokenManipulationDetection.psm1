function Invoke-TokenManipulationDetection {
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        try {
            $Owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).GetOwner()
            if ($Owner.Domain -eq "NT AUTHORITY" -and $Process.Path -notmatch "^C:\\Windows") {
                Write-Output "[TokenManip] SUSPICIOUS: Non-system binary running as SYSTEM | Process: $($Process.ProcessName) | Path: $($Process.Path)"
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-TokenManipulationDetection
