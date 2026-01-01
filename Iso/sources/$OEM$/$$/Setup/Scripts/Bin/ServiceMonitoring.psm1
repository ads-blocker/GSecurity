function Invoke-ServiceMonitoring {
    if (-not $Global:BaselineServices) {
        $Global:BaselineServices = Get-Service | Select-Object -ExpandProperty Name
    }
    
    $CurrentServices = Get-Service | Select-Object -ExpandProperty Name
    $NewServices = $CurrentServices | Where-Object { $_ -notin $Global:BaselineServices }
    
    foreach ($ServiceName in $NewServices) {
        $Service = Get-Service -Name $ServiceName
        $ServiceDetails = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        
        if ($ServiceDetails.PathName -notmatch "^C:\\Windows") {
            Write-Output "[Service] NEW SERVICE: $($Service.DisplayName) | Status: $($Service.Status) | Path: $($ServiceDetails.PathName)"
        }
    }
    
    $Global:BaselineServices = $CurrentServices
}

Export-ModuleMember -Function Invoke-ServiceMonitoring
