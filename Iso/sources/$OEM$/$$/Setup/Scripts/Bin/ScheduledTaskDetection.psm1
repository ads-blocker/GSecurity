function Invoke-ScheduledTaskDetection {
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.Principal.UserId -notmatch "SYSTEM|Administrator" }
    
    foreach ($Task in $Tasks) {
        $Action = $Task.Actions[0].Execute
        if ($Action -match "powershell|cmd|wscript|cscript|mshta") {
            Write-Output "[ScheduledTask] SUSPICIOUS: $($Task.TaskName) | Action: $Action | User: $($Task.Principal.UserId)"
        }
    }
}

Export-ModuleMember -Function Invoke-ScheduledTaskDetection
