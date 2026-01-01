function Invoke-EventLogMonitoring {
    $ClearedLogs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=1102} -MaxEvents 10 -ErrorAction SilentlyContinue
    
    foreach ($Event in $ClearedLogs) {
        Write-Output "[EventLog] THREAT: Security log cleared | Time: $($Event.TimeCreated) | User: $($Event.Properties[1].Value)"
    }
    
    $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
    $RecentFailed = $FailedLogons | Group-Object {$_.Properties[5].Value} | Where-Object {$_.Count -gt 5}
    
    foreach ($Account in $RecentFailed) {
        Write-Output "[EventLog] THREAT: Brute force attempt detected | Account: $($Account.Name) | Attempts: $($Account.Count)"
    }
}

Export-ModuleMember -Function Invoke-EventLogMonitoring
