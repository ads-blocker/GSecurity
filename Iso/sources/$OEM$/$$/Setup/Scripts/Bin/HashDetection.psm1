function Invoke-HashDetection {
    param(
        [string]$LogPath,
        [string]$QuarantinePath,
        [string]$CirclHashLookupUrl,
        [string]$CymruApiUrl,
        [string]$MalwareBazaarApiUrl,
        [bool]$AutoQuarantine = $true
    )
    
    $SuspiciousPaths = @(
        "$env:TEMP\*",
        "$env:APPDATA\*",
        "$env:LOCALAPPDATA\Temp\*",
        "C:\Windows\Temp\*",
        "$env:USERPROFILE\Downloads\*"
    )
    
    $Files = Get-ChildItem -Path $SuspiciousPaths -Include *.exe,*.dll,*.scr,*.vbs,*.ps1,*.bat,*.cmd -Recurse -ErrorAction SilentlyContinue
    
    foreach ($File in $Files) {
        try {
            $Hash = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            
            $Reputation = @{
                IsMalicious = $false
                Confidence = 0
                Sources = @()
            }
            
            try {
                $CirclResponse = Invoke-RestMethod -Uri "$CirclHashLookupUrl/$Hash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($CirclResponse.KnownMalicious) {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 40
                    $Reputation.Sources += "CIRCL"
                }
            } catch {}
            
            try {
                $MBBody = @{ query = "get_info"; hash = $Hash } | ConvertTo-Json
                $MBResponse = Invoke-RestMethod -Uri $MalwareBazaarApiUrl -Method Post -Body $MBBody -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($MBResponse.query_status -eq "ok") {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 50
                    $Reputation.Sources += "MalwareBazaar"
                }
            } catch {}
            
            try {
                $CymruResponse = Invoke-RestMethod -Uri "$CymruApiUrl/$Hash" -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($CymruResponse.malware -eq $true) {
                    $Reputation.IsMalicious = $true
                    $Reputation.Confidence += 30
                    $Reputation.Sources += "Cymru"
                }
            } catch {}
            
            if ($Reputation.IsMalicious -and $Reputation.Confidence -ge 50) {
                Write-Output "[HashDetection] THREAT: $($File.FullName) | Hash: $Hash | Sources: $($Reputation.Sources -join ', ') | Confidence: $($Reputation.Confidence)%"
                
                if ($AutoQuarantine) {
                    $QuarantineFile = Join-Path $QuarantinePath "$([DateTime]::Now.Ticks)_$($File.Name)"
                    Move-Item -Path $File.FullName -Destination $QuarantineFile -Force -ErrorAction SilentlyContinue
                    Write-Output "[HashDetection] Quarantined: $($File.FullName)"
                }
            }
            
            $Entropy = Measure-FileEntropy -FilePath $File.FullName
            if ($Entropy -gt 7.5 -and $File.Length -lt 1MB) {
                Write-Output "[HashDetection] High entropy detected: $($File.FullName) | Entropy: $([Math]::Round($Entropy, 2))"
            }
            
        } catch {
            Write-Output "[HashDetection] Error scanning $($File.FullName): $_"
        }
    }
}

function Measure-FileEntropy {
    param([string]$FilePath)
    
    try {
        $Bytes = [System.IO.File]::ReadAllBytes($FilePath)[0..4096]
        $Freq = @{}
        foreach ($Byte in $Bytes) {
            if ($Freq.ContainsKey($Byte)) {
                $Freq[$Byte]++
            } else {
                $Freq[$Byte] = 1
            }
        }
        
        $Entropy = 0
        $Total = $Bytes.Count
        foreach ($Count in $Freq.Values) {
            $P = $Count / $Total
            $Entropy -= $P * [Math]::Log($P, 2)
        }
        
        return $Entropy
    } catch {
        return 0
    }
}

Export-ModuleMember -Function Invoke-HashDetection
