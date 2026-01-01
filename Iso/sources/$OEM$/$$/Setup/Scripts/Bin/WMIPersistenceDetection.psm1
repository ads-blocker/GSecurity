function Invoke-WMIPersistenceDetection {
    $Filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $Consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    
    foreach ($Filter in $Filters) {
        Write-Output "[WMI] Event filter found: $($Filter.Name) | Query: $($Filter.Query)"
    }
    
    foreach ($Consumer in $Consumers) {
        Write-Output "[WMI] Command consumer found: $($Consumer.Name) | Command: $($Consumer.CommandLineTemplate)"
    }
}

Export-ModuleMember -Function Invoke-WMIPersistenceDetection
