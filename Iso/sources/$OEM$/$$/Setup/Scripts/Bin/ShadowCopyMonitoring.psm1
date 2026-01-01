function Invoke-ShadowCopyMonitoring {
    $ShadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    $CurrentCount = $ShadowCopies.Count
    
    if (-not $Global:BaselineShadowCopyCount) {
        $Global:BaselineShadowCopyCount = $CurrentCount
    }
    
    if ($CurrentCount -lt $Global:BaselineShadowCopyCount) {
        $Deleted = $Global:BaselineShadowCopyCount - $CurrentCount
        Write-Output "[ShadowCopy] THREAT: Shadow copies deleted | Deleted: $Deleted | Remaining: $CurrentCount"
        $Global:BaselineShadowCopyCount = $CurrentCount
    }
}

Export-ModuleMember -Function Invoke-ShadowCopyMonitoring
