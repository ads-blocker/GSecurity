function Invoke-NamedPipeMonitoring {
    $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
    $SuspiciousPipes = @("msagent_", "mojo", "crashpad", "mypipe", "evil")
    
    foreach ($Pipe in $Pipes) {
        foreach ($Pattern in $SuspiciousPipes) {
            if ($Pipe -match $Pattern) {
                Write-Output "[NamedPipe] SUSPICIOUS: $Pipe"
            }
        }
    }
}

Export-ModuleMember -Function Invoke-NamedPipeMonitoring
