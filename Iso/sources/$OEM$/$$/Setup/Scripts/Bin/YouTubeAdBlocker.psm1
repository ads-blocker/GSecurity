# YouTubeAdBlocker.psm1
# Blocks YouTube ads by intercepting traffic through a local proxy
# Integrates with the Modular Antivirus Protection system

function Invoke-YouTubeAdBlocker {
    [CmdletBinding()]
    param()
    
    $Port = 8080
    $results = @()
    
    try {
        # Check if proxy is already running
        $existingJob = Get-Job -Name "YouTubeAdBlockerProxy" -ErrorAction SilentlyContinue
        
        if ($existingJob -and $existingJob.State -eq 'Running') {
            # Proxy is running, just return status
            $results += "[YouTubeAdBlocker] Proxy server running on port $Port"
            return $results
        }
        
        # Clean up any stopped jobs
        Get-Job -Name "YouTubeAdBlockerProxy" -ErrorAction SilentlyContinue | Remove-Job -Force
        
        # Start proxy server as background job
        $proxyJob = Start-Job -Name "YouTubeAdBlockerProxy" -ScriptBlock {
            param($Port)
            
            $ErrorActionPreference = "Continue"
            
            # Ad domains to block
            $BlockedDomains = @(
                "doubleclick.net",
                "googlesyndication.com",
                "googleadservices.com",
                "google-analytics.com",
                "2mdn.net",
                "youtube.com/api/stats/ads",
                "youtube.com/pagead/",
                "youtube.com/ptracking",
                "youtube.com/api/stats/qoe",
                "s.youtube.com/api/stats/qoe",
                "static.doubleclick.net"
            )
            
            # YouTube ad-blocking scriptlet
            $YouTubeScriptlet = @"
<script>
(function() {
    'use strict';
    console.log('[YT-AdBlock] Active');
    if (window.ytInitialPlayerResponse) {
        try {
            if (window.ytInitialPlayerResponse.adPlacements) window.ytInitialPlayerResponse.adPlacements = [];
            if (window.ytInitialPlayerResponse.playerAds) window.ytInitialPlayerResponse.playerAds = [];
        } catch(e) {}
    }
    Object.defineProperty(window, 'ytInitialPlayerResponse', {
        set: function(v) { if(v && typeof v === 'object') { v.adPlacements = []; v.playerAds = []; } this._ytInitialPlayerResponse = v; },
        get: function() { return this._ytInitialPlayerResponse; }
    });
    const removeAds = () => {
        ['.video-ads','.ytp-ad-module','.ytp-ad-overlay-container','ytd-display-ad-renderer','ytd-promoted-sparkles-web-renderer','#masthead-ad','.ytd-compact-promoted-item-renderer','ytd-ad-slot-renderer','yt-mealbar-promo-renderer','ytd-popup-container'].forEach(s => document.querySelectorAll(s).forEach(el => el.remove()));
        const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern');
        if (skipBtn) skipBtn.click();
        const video = document.querySelector('video.html5-main-video');
        const adIndicator = document.querySelector('.ytp-ad-player-overlay');
        if (video && adIndicator) video.currentTime = video.duration;
    };
    setInterval(removeAds, 500);
    new MutationObserver(removeAds).observe(document.body, { childList: true, subtree: true });
})();
</script>
"@
            
            function Test-BlockedDomain {
                param([string]$Url)
                foreach ($domain in $BlockedDomains) {
                    if ($Url -like "*$domain*") { return $true }
                }
                return $false
            }
            
            function Inject-YouTubeScript {
                param([string]$HtmlContent)
                if ($HtmlContent -match '</head>') {
                    return $HtmlContent -replace '</head>', "$YouTubeScriptlet</head>"
                } elseif ($HtmlContent -match '<body[^>]*>') {
                    return $HtmlContent -replace '(<body[^>]*>)', "`$1$YouTubeScriptlet"
                }
                return $HtmlContent
            }
            
            function Handle-Request {
                param($Context)
                $request = $Context.Request
                $response = $Context.Response
                
                try {
                    $method = $request.HttpMethod
                    $requestUrl = $request.RawUrl
                    
                    if ($method -eq "CONNECT") {
                        $response.StatusCode = 501
                        $response.Close()
                        return
                    }
                    
                    $targetUrl = if ($requestUrl -match '^http') { $requestUrl } else { "http://$($request.Headers['Host'])$requestUrl" }
                    
                    if (Test-BlockedDomain -Url $targetUrl) {
                        $response.StatusCode = 204
                        $response.Close()
                        return
                    }
                    
                    $webRequest = [System.Net.HttpWebRequest]::Create($targetUrl)
                    $webRequest.Method = $method
                    $webRequest.UserAgent = $request.UserAgent
                    $webRequest.Timeout = 30000
                    
                    foreach ($header in $request.Headers.AllKeys) {
                        if ($header -notin @('Host', 'Connection', 'Proxy-Connection', 'Content-Length')) {
                            try { $webRequest.Headers.Add($header, $request.Headers[$header]) } catch {}
                        }
                    }
                    
                    if ($method -in @('POST', 'PUT', 'PATCH') -and $request.HasEntityBody) {
                        $webRequest.ContentLength = $request.ContentLength64
                        $webRequest.ContentType = $request.ContentType
                        $requestStream = $webRequest.GetRequestStream()
                        $request.InputStream.CopyTo($requestStream)
                        $requestStream.Close()
                    }
                    
                    try {
                        $webResponse = $webRequest.GetResponse()
                    } catch [System.Net.WebException] {
                        $webResponse = $_.Exception.Response
                        if ($null -eq $webResponse) { throw }
                    }
                    
                    $response.StatusCode = [int]$webResponse.StatusCode
                    $response.StatusDescription = $webResponse.StatusDescription
                    
                    foreach ($header in $webResponse.Headers.AllKeys) {
                        if ($header -notin @('Transfer-Encoding', 'Content-Length')) {
                            try { $response.Headers.Add($header, $webResponse.Headers[$header]) } catch {}
                        }
                    }
                    
                    $responseStream = $webResponse.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($responseStream)
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                    $responseStream.Close()
                    $webResponse.Close()
                    
                    if ($webResponse.ContentType -like "*text/html*") {
                        $content = Inject-YouTubeScript -HtmlContent $content
                    }
                    
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    $response.Close()
                    
                } catch {
                    try {
                        $response.StatusCode = 502
                        $response.Close()
                    } catch {}
                }
            }
            
            $listener = New-Object System.Net.HttpListener
            $listener.Prefixes.Add("http://localhost:$Port/")
            $listener.Prefixes.Add("http://127.0.0.1:$Port/")
            
            try {
                $listener.Start()
                while ($listener.IsListening) {
                    $context = $listener.GetContext()
                    Handle-Request -Context $context
                }
            } catch {
            } finally {
                if ($listener.IsListening) { $listener.Stop() }
                $listener.Close()
            }
        } -ArgumentList $Port
        
        Start-Sleep -Milliseconds 500  # Give proxy time to start
        
        # Configure PAC file
        $pacFile = "$env:TEMP\youtube-adblocker.pac"
        $pacContent = @"
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.youtube.com") || 
        shExpMatch(host, "*.youtu.be") ||
        shExpMatch(host, "youtube.com") ||
        shExpMatch(host, "youtu.be")) {
        return "PROXY 127.0.0.1:$Port";
    }
    return "DIRECT";
}
"@
        
        Set-Content -Path $pacFile -Value $pacContent -Encoding ASCII -ErrorAction Stop
        
        # Set system proxy
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name AutoConfigURL -Value "file:///$($pacFile -replace '\\','/')" -ErrorAction Stop
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0 -ErrorAction Stop
        
        # Refresh proxy settings
        try {
            $signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
            $wininet = Add-Type -MemberDefinition $signature -Name InternetSettings -Namespace Win32 -PassThru
            $wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
            $wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
        } catch {}
        
        $results += "[YouTubeAdBlocker] Proxy server started on port $Port"
        $results += "[YouTubeAdBlocker] PAC file configured for YouTube-only proxying"
        $results += "[YouTubeAdBlocker] Ad blocking active for YouTube traffic"
        
    } catch {
        $results += "[YouTubeAdBlocker] ERROR: $($_.Exception.Message)"
    }
    
    return $results
}

Export-ModuleMember -Function Invoke-YouTubeAdBlocker
