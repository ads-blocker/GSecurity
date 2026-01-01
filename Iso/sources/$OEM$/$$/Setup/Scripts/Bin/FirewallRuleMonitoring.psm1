function Invoke-FirewallRuleMonitoring {
    if (-not $Global:BaselineFirewallRules) {
        $Global:BaselineFirewallRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    }
    
    $CurrentRules = Get-NetFirewallRule | Select-Object -ExpandProperty Name
    $NewRules = $CurrentRules | Where-Object { $_ -notin $Global:BaselineFirewallRules }
    
    foreach ($Rule in $NewRules) {
        $RuleDetails = Get-NetFirewallRule -Name $Rule
        Write-Output "[Firewall] NEW RULE: $($RuleDetails.DisplayName) | Action: $($RuleDetails.Action) | Direction: $($RuleDetails.Direction)"
    }
    
    $Global:BaselineFirewallRules = $CurrentRules
}

Export-ModuleMember -Function Invoke-FirewallRuleMonitoring
