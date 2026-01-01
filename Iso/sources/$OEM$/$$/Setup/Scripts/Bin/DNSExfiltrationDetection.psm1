function Invoke-DNSExfiltrationDetection {
    $DNSCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    
    foreach ($Entry in $DNSCache) {
        if ($Entry.Name.Length -gt 50 -and $Entry.Name -match "[0-9a-f]{32,}") {
            Write-Output "[DNSExfil] SUSPICIOUS: Long subdomain detected | Domain: $($Entry.Name)"
        }
    }
}

Export-ModuleMember -Function Invoke-DNSExfiltrationDetection
