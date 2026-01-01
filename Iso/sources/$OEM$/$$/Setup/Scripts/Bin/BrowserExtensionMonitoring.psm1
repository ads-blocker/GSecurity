function Invoke-BrowserExtensionMonitoring {
    $ExtensionPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    )
    
    foreach ($Path in $ExtensionPaths) {
        if (Test-Path $Path) {
            $Extensions = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
            foreach ($Ext in $Extensions) {
                $ManifestPath = Join-Path $Ext.FullName "manifest.json"
                if (Test-Path $ManifestPath) {
                    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $DangerousPermissions = @("tabs", "webRequest", "cookies", "history", "downloads", "clipboardWrite")
                    
                    $HasDangerous = $false
                    foreach ($Perm in $Manifest.permissions) {
                        if ($DangerousPermissions -contains $Perm) {
                            $HasDangerous = $true
                            break
                        }
                    }
                    
                    if ($HasDangerous) {
                        Write-Output "[BrowserExt] SUSPICIOUS: Extension with dangerous permissions | Name: $($Manifest.name) | Permissions: $($Manifest.permissions -join ', ')"
                    }
                }
            }
        }
    }
}

Export-ModuleMember -Function Invoke-BrowserExtensionMonitoring
