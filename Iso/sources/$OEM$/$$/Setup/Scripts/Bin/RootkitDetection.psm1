function Invoke-RootkitDetection {
    $Drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue
    
    foreach ($Driver in $Drivers) {
        if ($Driver.ProviderName -notmatch "Microsoft" -and $Driver.ClassName -eq "System") {
            Write-Output "[Rootkit] SUSPICIOUS: Third-party system driver | Driver: $($Driver.DriverName) | Provider: $($Driver.ProviderName)"
        }
    }
}

Export-ModuleMember -Function Invoke-RootkitDetection
