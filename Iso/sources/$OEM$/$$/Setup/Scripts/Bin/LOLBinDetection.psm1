function Invoke-LOLBinDetection {
    param(
        [bool]$AutoKillThreats = $true
    )
    
    $LOLBins = @{
        "certutil.exe" = @("-decode", "-urlcache", "-split", "http")
        "powershell.exe" = @("-enc", "-EncodedCommand", "bypass", "hidden", "downloadstring", "iex", "invoke-expression")
        "cmd.exe" = @("/c echo", "powershell", "certutil")
        "mshta.exe" = @("http", "javascript:", "vbscript:")
        "rundll32.exe" = @("javascript:", "http", ".dat,", "comsvcs")
        "regsvr32.exe" = @("/s /u /i:http", "scrobj.dll")
        "wscript.exe" = @(".vbs", ".js", "http")
        "cscript.exe" = @(".vbs", ".js", "http")
        "bitsadmin.exe" = @("/transfer", "/download", "http")
        "msiexec.exe" = @("/quiet", "/qn", "http")
        "wmic.exe" = @("process call create", "shadowcopy delete")
        "regasm.exe" = @("/U", "http")
        "regsvcs.exe" = @("/U", "http")
        "installutil.exe" = @("/logfile=", "/U")
    }
    
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        $ProcessName = $Process.ProcessName + ".exe"
        
        if ($LOLBins.ContainsKey($ProcessName)) {
            try {
                $CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).CommandLine
                
                if ($CommandLine) {
                    foreach ($Indicator in $LOLBins[$ProcessName]) {
                        if ($CommandLine -match [regex]::Escape($Indicator)) {
                            Write-Output "[LOLBinDetection] THREAT: $ProcessName | PID: $($Process.Id) | CommandLine: $CommandLine"
                            
                            if ($AutoKillThreats) {
                                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                                Write-Output "[LOLBinDetection] Terminated process: $ProcessName (PID: $($Process.Id))"
                            }
                            break
                        }
                    }
                }
            } catch {}
        }
    }
}

Export-ModuleMember -Function Invoke-LOLBinDetection
