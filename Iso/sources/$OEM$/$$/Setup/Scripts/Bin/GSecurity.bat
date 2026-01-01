@echo off

:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Perms
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%USERPROFILE%\Desktop" /A /R /D y
icacls "%USERPROFILE%\Desktop" /reset
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Users\Public\Desktop" /A /R /D y
icacls "C:\Users\Public\Desktop" /reset
icacls "C:\Users\Public\Desktop" /inheritance:r
icacls "C:\Users\Public\Desktop" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Windows\System32\wbem" /A
icacls "C:\Windows\System32\wbem" /reset
icacls "C:\Windows\System32\wbem" /inheritance:r
takeown /f %windir%\system32\consent.exe /A
icacls %windir%\system32\consent.exe /reset
icacls %windir%\system32\consent.exe /inheritance:r
icacls %windir%\system32\consent.exe /grant:r "Console Logon":RX
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f

:: Services
sc config VNC start= disabled
sc stop VNC
sc config FileZilla Server start= disabled
sc stop FileZilla Server
sc config OpenSSH start= disabled
sc stop OpenSSH
sc config vsftpd start= disabled
sc stop vsftpd
sc config TeamViewer start= disabled
sc stop TeamViewer
sc config AnyDesk start= disabled
sc stop AnyDesk
sc config LogMeIn start= disabled
sc stop LogMeIn
sc config Radmin start= disabled
sc stop Radmin
sc config SsdpSrv start= disabled
sc stop SsdpSrv
sc config upnphost start= disabled
sc stop upnphost
sc config TelnetServer start= disabled
sc stop TelnetServer
sc config sshd start= disabled
sc stop sshd
sc config ftpsvc start= disabled
sc stop ftpsvc
sc config seclogon start= disabled
sc stop seclogon
sc config LanmanWorkstation start= disabled
sc stop LanmanWorkstation
sc config LanmanServer start= disabled
sc stop LanmanServer
sc config WinRM start= disabled
sc stop WinRM
sc config RemoteRegistry start= disabled
sc stop RemoteRegistry
sc config SNMP start= disabled
sc stop SNMP

:: Users
net user defaultuser0 /delete

:: Set global DoH policy to 3 (Automatic)
echo [1/3] Setting global DoH policy...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohSettings" /v DohPolicy /t REG_DWORD /d 3 /f >nul 2>&1
if !errorlevel! equ 0 (
    echo Global DoH policy set successfully
) else (
    echo Warning: Could not set global DoH policy
)
echo.

:: Process ALL network adapters (not just connected ones)
echo [2/3] Configuring network interfaces...
set "adapter_count=0"

:: Query all network interfaces regardless of status
for /f "skip=2 tokens=1-3,*" %%a in ('netsh interface show interface 2^>nul') do (
    set "intname=%%d"
    
    :: Skip loopback
    if not "!intname!"=="Loopback Pseudo-Interface 1" (
        echo.
        echo Processing: !intname! [Status: %%a/%%b]
        
        :: Configure DNS servers WITHOUT validation (critical for offline)
        netsh interface ipv4 set dnsservers "!intname!" static 1.1.1.1 validate=no >nul 2>&1
        netsh interface ipv4 add dnsservers "!intname!" 8.8.8.8 index=2 validate=no >nul 2>&1
        
        if !errorlevel! equ 0 (
            echo   - DNS servers configured
        ) else (
            echo   - Warning: DNS configuration may be pending
        )
        
        :: Find GUID for this interface
        set "found="
        for /f "delims=" %%k in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "\"!intname!\"" /d /e /t REG_SZ 2^>nul ^| find "HKEY"') do (
            set "found=%%k"
        )
        
        if defined found (
            :: Extract GUID
            set "guid=!found:~99,38!"
            
            :: Create base registry path
            set "basekey=HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\!guid!\DohInterfaceSettings\Doh"
            
            :: Configure DoH for Cloudflare (1.1.1.1)
            reg add "!basekey!\1.1.1.1" /v DohTemplate /t REG_SZ /d "https://cloudflare-dns.com/dns-query" /f >nul 2>&1
            reg add "!basekey!\1.1.1.1" /v DohFlags /t REG_QWORD /d 6 /f >nul 2>&1
            
            :: Configure DoH for Google (8.8.8.8)
            reg add "!basekey!\8.8.8.8" /v DohTemplate /t REG_SZ /d "https://dns.google/dns-query" /f >nul 2>&1
            reg add "!basekey!\8.8.8.8" /v DohFlags /t REG_QWORD /d 6 /f >nul 2>&1
            
            echo   - DoH templates configured (GUID: !guid!)
            set /a adapter_count+=1
        ) else (
            echo   - Warning: GUID not found, DoH config skipped
        )
    )
)

:: Restart DNS Cache service to apply changes
net stop Dnscache >nul 2>&1
net start Dnscache >nul 2>&1

:: Script dir
cd /d %~dp0

:: Registry
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    reg import "%%C"
)

:: Tasks
schtasks /Create /TN "Antivirus" /XML "Antivirus.xml" /RU "" /F

:: Restart
shutdown /r /t 0
