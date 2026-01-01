function Invoke-COMMonitoring {
    $COMKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID"
    )
    
    foreach ($Key in $COMKeys) {
        $RecentCOM = Get-ChildItem -Path $Key -ErrorAction SilentlyContinue | 
            Where-Object { $_.PSChildName -match "^\{[A-F0-9-]+\}$" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5
        
        foreach ($COM in $RecentCOM) {
            Write-Output "[COM] Recently modified COM object: $($COM.PSChildName) | Modified: $($COM.LastWriteTime)"
        }
    }
}

Export-ModuleMember -Function Invoke-COMMonitoring
