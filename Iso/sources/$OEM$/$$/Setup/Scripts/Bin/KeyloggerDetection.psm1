function Invoke-KeyloggerDetection {
    $Hooks = Get-Process | Where-Object { 
        try {
            $_.Modules.ModuleName -match "user32.dll" -and $_.ProcessName -notmatch "explorer|chrome|firefox"
        } catch { $false }
    }
    
    foreach ($Process in $Hooks) {
        Write-Output "[Keylogger] SUSPICIOUS: Potential keylogger | Process: $($Process.ProcessName) | PID: $($Process.Id)"
    }
}

Export-ModuleMember -Function Invoke-KeyloggerDetection
