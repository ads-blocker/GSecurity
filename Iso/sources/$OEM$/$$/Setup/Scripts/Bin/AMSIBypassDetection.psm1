function Invoke-AMSIBypassDetection {
    param(
        [bool]$AutoKillThreats = $true
    )
    
    $AMSIBypassPatterns = @(
        "amsiInitFailed",
        "AmsiScanBuffer",
        "amsi.dll",
        "[Ref].Assembly.GetType",
        "System.Management.Automation.AmsiUtils"
    )
    
    $Processes = Get-Process | Where-Object { $_.ProcessName -match "powershell|pwsh" }
    
    foreach ($Process in $Processes) {
        try {
            $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
            
            foreach ($Pattern in $AMSIBypassPatterns) {
                if ($CommandLine -match [regex]::Escape($Pattern)) {
                    Write-Output "[AMSIBypass] THREAT: AMSI bypass detected | PID: $($Process.Id) | Pattern: $Pattern"
                    
                    if ($AutoKillThreats) {
                        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                        Write-Output "[AMSIBypass] Terminated process (PID: $($Process.Id))"
                    }
                    break
                }
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-AMSIBypassDetection
