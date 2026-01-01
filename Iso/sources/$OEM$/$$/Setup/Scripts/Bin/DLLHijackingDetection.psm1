function Invoke-DLLHijackingDetection {
    $Processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($Process in $Processes) {
        try {
            $Modules = $Process.Modules | Where-Object { $_.FileName -notmatch "^C:\\Windows" }
            foreach ($Module in $Modules) {
                $Signature = Get-AuthenticodeSignature -FilePath $Module.FileName -ErrorAction SilentlyContinue
                if ($Signature.Status -ne "Valid") {
                    Write-Output "[DLLHijack] SUSPICIOUS: Unsigned DLL loaded | Process: $($Process.ProcessName) | DLL: $($Module.FileName)"
                }
            }
        } catch {}
    }
}

Export-ModuleMember -Function Invoke-DLLHijackingDetection
