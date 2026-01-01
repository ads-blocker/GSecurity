function Invoke-FilelessDetection {
    $PSProcesses = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }
    
    foreach ($Process in $PSProcesses) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
            if ($CommandLine -match "-enc|-EncodedCommand") {
                Write-Output "[Fileless] THREAT: Encoded PowerShell detected | PID: $($Process.Id)"
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-FilelessDetection
