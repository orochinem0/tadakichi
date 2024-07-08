[String[]]$Folders  = "$env:windir\SoftwareDistribution\",
                      "$env:windir\System32\Catroot2\"

[String[]]$Files    = "$env:windir\winsxs\pending.xml",
                      "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat",
                      "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*.dat"

[String[]]$Services = "bits",
                      "wuauserv",
                      "appidsvc",
                      "cryptsvc",
                      "CcmExec",
                      "winmgmt"

function tasks-services {
    &w32tm /resync
    foreach ($Service in $Services) {
        $servicestatus = (Get-Service -Name $Service).status
        $counter = 1
        $max = 5

        while (($servicestatus -ne "Stopped") -and ($counter -le $max)) {
            if ($counter -lt $max) {
                try {
                    Stop-Service $Service -Force -NoWait -ErrorAction Stop -WarningAction Stop
                }
                catch  {}
            }
            else {
                try {
                    $ErrorActionPreference = 'Stop'
                    taskkill /t /f /fi "SERVICES eq $service"
                    $ErrorActionPreference = 'Continue'
                }
                catch {}
            }
            $servicestatus = (Get-Service -Name $service).status
            $counter++
        }
    }

    foreach ($File in $Files) {
        takeown /f $File /a
        icacls $File /grant administrators:f
        Remove-Item -Path $File -Force
    }

    foreach ($Folder in $Folders) {
        takeown /f $Folder"*" /a
        icacls $Folder"*" /grant administrators:f
        Get-ChildItem $Folder -Recurse | Remove-Item -Force -Recurse
    }
    
    $ErrorActionPreference = 'Stop'
    try {&reg delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f} catch {}
    try {&reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /f} catch {}
    try {&reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f} catch {}
    try {&reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /f} catch {}
    $ErrorActionPreference = 'Continue'

    #sc sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
    #sc sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)

    &cd $env:windir\system32
    &regsvr32 /s atl.dll 
    &regsvr32 /s urlmon.dll 
    &regsvr32 /s mshtml.dll 
    &regsvr32 /s shdocvw.dll 
    &regsvr32 /s browseui.dll 
    &regsvr32 /s jscript.dll 
    &regsvr32 /s vbscript.dll 
    &regsvr32 /s scrrun.dll 
    &regsvr32 /s msxml.dll 
    &regsvr32 /s msxml3.dll 
    &regsvr32 /s msxml6.dll 
    &regsvr32 /s actxprxy.dll 
    &regsvr32 /s softpub.dll 
    &regsvr32 /s wintrust.dll 
    &regsvr32 /s dssenh.dll 
    &regsvr32 /s rsaenh.dll 
    &regsvr32 /s gpkcsp.dll 
    &regsvr32 /s sccbase.dll 
    &regsvr32 /s slbcsp.dll 
    &regsvr32 /s cryptdlg.dll 
    &regsvr32 /s oleaut32.dll 
    &regsvr32 /s ole32.dll 
    &regsvr32 /s shell32.dll 
    &regsvr32 /s initpki.dll 
    &regsvr32 /s wuapi.dll 
    &regsvr32 /s wuaueng.dll 
    &regsvr32 /s wuaueng1.dll 
    &regsvr32 /s wucltui.dll 
    &regsvr32 /s wups.dll 
    &regsvr32 /s wups2.dll 
    &regsvr32 /s wuweb.dll 
    &regsvr32 /s qmgr.dll 
    &regsvr32 /s qmgrprxy.dll 
    &regsvr32 /s wucltux.dll 
    &regsvr32 /s muweb.dll 
    &regsvr32 /s wuwebv.dll
    &regsvr32 /s wudriver.dll

    Start-Service $services

    &gpupdate /force
}

function tasks-DISM {

    &SFC /scannow

    Repair-WindowsImage -Online -NoRestart -CheckHealth
    Repair-WindowsImage -Online -NoRestart -ScanHealth
    Repair-WindowsImage -Online -NoRestart -RestoreHealth    

    if ((Get-Service -Name "TrustedInstaller").status -ne "Running") {
        &net start TrustedInstaller
    }

    &DISM /Online /Cleanup-Image /AnalyzeComponentStore
    &DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
    &DISM /Online /Cleanup-Image /SPSuperseded
}

function tasks-dismhost {
    param ($DISMhost)
    $DISMSource = '\\'+$DISMhost+'\c$\windows\winsxs'
    Repair-WindowsImage -Online -NoRestart -RestoreHealth -Source $DISMSource -LimitAccess
}

#tasks-services
#tasks-DISM

Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}"
&$env:windir\CCM\ccmeval
&$env:windir\CCM\ClientUX\SCClient
