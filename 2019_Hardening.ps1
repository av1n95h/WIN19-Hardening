Write-Host "This a Basic Windows 2019 Hardening script" -ForegroundColor Green
      
Write-Host "'n 'r Backing up settings" -ForegroundColor Green 
    Secedit /export /cfg .\GptTmpl_backup.inf
Write-Host "'n 'r Applying the secure Template file" -ForegroundColor Green
    Secedit /configure /db secedit.sdb /cfg .\GptTmpl.inf

Write-Host "'n 'r Setting Audit Policies" -ForegroundColor Green
    auditpol.exe /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    auditpol.exe /set /subcategory:"Security State Change" /success:enable /failure:enable
    auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
    auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable
    auditpol.exe /set /category:"Account Management" /Subcategory:"User Account Management" /success:enable /failure:enable
    auditpol.exe /set /category:"Object Access" /Subcategory:"Other Object Access Events"  /success:enable /failure:enable
    auditpol.exe /set /category:"Account Logon" /Subcategory:"Credential Validation" /failure:enable
    auditpol.exe /set /category:"System" /Subcategory:"Security System Extension" /success:enable 
    auditpol.exe /set /category:"System" /Subcategory:"IPsec Driver" /success:enable /failure:enable
    auditpol.exe /set /category:"Account Management" /Subcategory:"Other Account Management Events" /success:enable
    auditpol.exe /set /category:"Logon/Logoff" /subcategory:"Account Lockout" /failure:enable 
    auditpol.exe /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable
    auditpol.exe /set /category:"Policy change" /Subcategory:"Authorization Policy Change" /success:enable /failure:enable
    auditpol.exe /set /category:"Privilege Use" /Subcategory:"Sensitive Privilege Use" /success:enable /failure:enable


Write-Host "Setting Account Policies" -ForegroundColor Green
#Windows Account Policy Settings
    net accounts /lockoutwindow:15
    net accounts /MiNPWLEN:14
    net accounts /uniquepw:24
    net accounts /minpwage:1
    net accounts /lockoutthreshold:3
    net accounts /lockoutduration:15

Write-Host "'n 'r Seeting Registry Values" -ForegroundColor Green
#Registry Settings
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\" /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" /v DisableInventory /t REG_DWORD /d 1 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" /v AllowBasic  /t REG_DWORD /d 0 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" /v AllowDigest /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" /v AllowBasic  /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" /v EnumerateAdministrators /t REG_DWORD /d 0 /f 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" /v MaxSize /t REG_DWORD /d 32768 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" /v MaxSize /t REG_DWORD /d 196608 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" /v MaxSize /t REG_DWORD /d 32768 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\" /v EnableUserControl /t REG_DWORD /d 0 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v DisablePasswordSaving /t REG_DWORD /d 1 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v  fPromptForPassword /t REG_DWORD /d 1 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" /v DisableRunAs /t REG_DWORD /d 1 /f 
    #reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" /v RequireSecuritySignature /t REG_DWORD /d 1 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" /v EnableSecuritySignature /t REG_DWORD /d 1 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" /v AllowProtectedCreds /t REG_DWORD /d 1 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" /v NoGPOListChanges /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v DCSettingIndex /t REG_DWORD /d 1 /f 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v ACSettingIndex /t REG_DWORD /d 1 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\" /v allownullsessionfallback /t REG_DWORD /d 0 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" /v AllowOnlineID /t REG_DWORD /d 0 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography" /v ForceKeyProtection /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\" /v ConsentPromptBehaviorUser  /t REG_DWORD /d 3 /f 
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v scremoveoption /t REG_SZ /d 0 /f
    reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f 
 

