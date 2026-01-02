function Invoke-NetworkTrafficMonitoring {
    param(
        [bool]$AutoBlockThreats = $true
    )
    
    # Configuration
    $AllowedDomains = @("google.com", "microsoft.com", "github.com", "stackoverflow.com")
    $AllowedIPs = @()
    $BlockedConnections = @{}
    $MonitoringActive = $true
    $CurrentBrowserConnections = @{}
    
    # Initialize allowed IPs from domains
    foreach ($Domain in $AllowedDomains) {
        try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($IP in $IPs) {
                if ($AllowedIPs -notcontains $IP) {
                    $AllowedIPs += $IP
                }
            }
        }
        catch {
            Write-Output "[NTM] WARNING: Could not resolve domain $Domain to IP"
        }
    }
    
    Write-Output "[NTM] Starting network traffic monitoring..."
    Write-Output "[NTM] Allowed domains: $($AllowedDomains.Count)"
    Write-Output "[NTM] Allowed IPs: $($AllowedIPs.Count)"
    
    # Get current network connections
    try {
        $Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }
        
        $SuspiciousConnections = @()
        $TotalConnections = $Connections.Count
        
        foreach ($Connection in $Connections) {
            $RemoteAddr = $Connection.RemoteAddress
            $RemotePort = $Connection.RemotePort
            $LocalPort = $Connection.LocalPort
            $ProcessId = $Connection.OwningProcess
            
            # Skip if it's an allowed IP
            if ($AllowedIPs -contains $RemoteAddr) {
                continue
            }
            
            # Get process information
            $ProcessName = "Unknown"
            $ProcessPath = "Unknown"
            
            try {
                $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
                if ($Process) {
                    $ProcessName = $Process.ProcessName
                    $ProcessPath = if ($Process.Path) { $Process.Path } else { "Unknown" }
                }
            }
            catch {
                # Process access denied
            }
            
            # Check for suspicious patterns
            $SuspiciousScore = 0
            $Reasons = @()
            
            # High ports (often used by malware)
            if ($RemotePort -gt 10000) {
                $SuspiciousScore += 20
                $Reasons += "High remote port: $RemotePort"
            }
            
            # Common C2 ports
            $C2Ports = @(4444, 8080, 9999, 1337, 31337, 443, 53)
            if ($C2Ports -contains $RemotePort) {
                $SuspiciousScore += 30
                $Reasons += "Known C2 port: $RemotePort"
            }
            
            # Suspicious processes
            $SuspiciousProcesses = @("powershell", "cmd", "wscript", "cscript", "rundll32", "mshta")
            if ($SuspiciousProcesses -contains $ProcessName.ToLower()) {
                $SuspiciousScore += 25
                $Reasons += "Suspicious process: $ProcessName"
            }
            
            # Unknown processes in system locations
            if ($ProcessPath -notmatch "C:\\(Windows|Program Files|Program Files \(x86\))" -and $ProcessPath -ne "Unknown") {
                $SuspiciousScore += 15
                $Reasons += "Process in non-standard location"
            }
            
            # DNS resolution check (if it's an IP, try reverse lookup)
            if ($RemoteAddr -match '^\d+\.\d+\.\d+\.\d+$') {
                try {
                    $HostName = [System.Net.Dns]::GetHostEntry($RemoteAddr).HostName
                    if ($HostName -and $HostName -notmatch ($AllowedDomains -join '|')) {
                        $SuspiciousScore += 10
                        $Reasons += "Unknown hostname: $HostName"
                    }
                }
                catch {
                    $SuspiciousScore += 5
                    $Reasons += "No reverse DNS for IP"
                }
            }
            
            # Check if connection is to known malicious IPs (basic check)
            $PrivateIPRanges = @("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "169.254.")
            $IsPrivateIP = $false
            foreach ($Range in $PrivateIPRanges) {
                if ($RemoteAddr.StartsWith($Range)) {
                    $IsPrivateIP = $true
                    break
                }
            }
            
            if (!$IsPrivateIP -and $AllowedIPs -notcontains $RemoteAddr) {
                $SuspiciousScore += 10
                $Reasons += "Unknown public IP"
            }
            
            # If suspicious enough, add to list
            if ($SuspiciousScore -ge 30) {
                $SuspiciousConnections += @{
                    RemoteAddress = $RemoteAddr
                    RemotePort = $RemotePort
                    LocalPort = $LocalPort
                    ProcessName = $ProcessName
                    ProcessId = $ProcessId
                    ProcessPath = $ProcessPath
                    Score = $SuspiciousScore
                    Reasons = $Reasons
                }
                
                Write-Output "[NTM] SUSPICIOUS: $ProcessName connecting to $RemoteAddr`:$RemotePort | Score: $SuspiciousScore | Reasons: $($Reasons -join ', ')"
            }
        }
        
        # Auto-block threats if enabled
        if ($AutoBlockThreats -and $SuspiciousConnections.Count -gt 0) {
            foreach ($Suspicious in $SuspiciousConnections) {
                try {
                    # Block the IP using Windows Firewall
                    $RuleName = "Block_Malicious_$($Suspicious.RemoteAddress)_$((Get-Date).ToString('yyyyMMddHHmmss'))"
                    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -RemoteAddress $Suspicious.RemoteAddress -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                    
                    Write-Output "[NTM] ACTION: Blocked IP $($Suspicious.RemoteAddress) with firewall rule $RuleName"
                    
                    # Terminate suspicious process if score is very high
                    if ($Suspicious.Score -ge 50) {
                        Stop-Process -Id $Suspicious.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Output "[NTM] ACTION: Terminated suspicious process $($Suspicious.ProcessName) (PID: $($Suspicious.ProcessId))"
                    }
                }
                catch {
                    Write-Output "[NTM] ERROR: Failed to block threat: $_"
                }
            }
        }
        
        # Summary
        Write-Output "[NTM] Monitoring complete: $TotalConnections total connections, $($SuspiciousConnections.Count) suspicious"
        
        if ($SuspiciousConnections.Count -gt 0) {
            Write-Output "[NTM] THREAT SUMMARY:"
            foreach ($Suspicious in $SuspiciousConnections) {
                Write-Output "[NTM]   - $($Suspicious.ProcessName) -> $($Suspicious.RemoteAddress):$($Suspicious.RemotePort) (Score: $($Suspicious.Score))"
            }
        }
        else {
            Write-Output "[NTM] INFO: No suspicious network activity detected"
        }
    }
    catch {
        Write-Output "[NTM] ERROR: Failed to monitor network traffic: $_"
    }
}

Export-ModuleMember -Function Invoke-NetworkTrafficMonitoring
