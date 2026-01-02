function Invoke-USBMonitoring {
    $USBDevices = Get-PnpDevice -Class "USB" -Status "OK" -ErrorAction SilentlyContinue
    
    foreach ($Device in $USBDevices) {
        if ($Device.FriendlyName -match "Keyboard|HID") {
            Write-Output "[USB] ALERT: USB HID device connected | Device: $($Device.FriendlyName) | InstanceId: $($Device.InstanceId)"
        }
        
        if ($Device.FriendlyName -match "Mass Storage") {
            $RemovableDrives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
            
            foreach ($Drive in $RemovableDrives) {
                $AutoRunPath = "$($Drive.DeviceID)\autorun.inf"
                if (Test-Path $AutoRunPath) {
                    Write-Output "[USB] THREAT: Autorun.inf detected on removable drive | Path: $AutoRunPath"
                }
            }
        }
    }
}

Export-ModuleMember -Function Invoke-USBMonitoring
