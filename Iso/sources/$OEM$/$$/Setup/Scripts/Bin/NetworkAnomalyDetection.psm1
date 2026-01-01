function Invoke-NetworkAnomalyDetection {
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    
    foreach ($Conn in $Connections) {
        if ($Conn.RemotePort -in @(4444, 5555, 8080, 1337, 31337)) {
            Write-Output "[Network] SUSPICIOUS: Connection to suspicious port | Remote: $($Conn.RemoteAddress):$($Conn.RemotePort) | PID: $($Conn.OwningProcess)"
        }
    }
}

Export-ModuleMember -Function Invoke-NetworkAnomalyDetection
