function Invoke-RegistryPersistenceDetection {
    $RunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($Key in $RunKeys) {
        if (Test-Path $Key) {
            $Values = Get-ItemProperty -Path $Key
            foreach ($Property in $Values.PSObject.Properties) {
                if ($Property.Name -notmatch "^PS" -and $Property.Value -match "powershell|cmd|http|\.vbs|\.js") {
                    Write-Output "[Registry] SUSPICIOUS: $Key | Name: $($Property.Name) | Value: $($Property.Value)"
                }
            }
        }
    }
}

Export-ModuleMember -Function Invoke-RegistryPersistenceDetection
