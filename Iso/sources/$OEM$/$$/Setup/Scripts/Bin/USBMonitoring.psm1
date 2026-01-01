function Invoke-USBMonitoring {
    $USBDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue
    
    foreach ($Device in $USBDevices) {
        if ($Device.FriendlyName -match "Keyboard|HID") {
            Write-Output "[USB] ALERT: USB HID device connected | Device: $($Device.FriendlyName) | InstanceId: $($Device.InstanceId)"
        }
        
        if ($Device.FriendlyName -match "Mass Storage") {
            $AutoRunPath = Get-Volume | Where-Object { $_.DriveType -eq "Removable" } | ForEach-Object {
                "$($_.DriveLetter):\autorun.inf"
            }
            
            foreach ($Path in $AutoRunPath) {
                if (Test-Path $Path) {
                    Write-Output "[USB] THREAT: Autorun.inf detected on removable drive | Path: $Path"
                }
            }
        }
    }
}

Export-ModuleMember -Function Invoke-USBMonitoring
