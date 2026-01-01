function Invoke-ClipboardMonitoring {
    try {
        $ClipboardText = Get-Clipboard -Format Text -ErrorAction SilentlyContinue
        if ($ClipboardText -match "password|api[_-]?key|token|secret") {
            Write-Output "[Clipboard] WARNING: Sensitive data detected in clipboard"
        }
    } catch {}
}

Export-ModuleMember -Function Invoke-ClipboardMonitoring
