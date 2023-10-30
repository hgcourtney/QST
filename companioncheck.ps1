<#Info Test
Created by Henry Courtney
Updated 26 OCT 2023
#>

#create Temp folder on C
new-item -Type Directory -Path C:\temp\ -ErrorAction SilentlyContinue
try {
    $deviceID = ((Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent' -Name Appliance_IDs).Appliance_IDs -split ",")[0] 
}
catch {
    $deviceID = ''
}
$date = get-date -Format yyyy_MM_dd_hh_mm_ss
$outfolder = ($env:USERNAME, $env:COMPUTERNAME, $deviceID, $date -join "_") 
$OutDIR = Join-Path -Path C:\temp\ -ChildPath $outfolder

#all Files will be saved in here Then zipped up
new-item -Type Directory -path $OutDIR -ErrorAction SilentlyContinue
$FullReport = New-Object System.Collections.ArrayList

#region Test Funtions

function Test-ByPassDNSServerResolution {
    $propertiesconf = (Get-Content "C:\Program Files (x86)\FamilyZone\MobileZoneAgent\conf\properties.conf") | ConvertFrom-Json 
    $localDNSServers = (($propertiesconf.dns_settings | ConvertTo-Json -Depth 5 |  Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.Value)
    #test first bypass DNS server for Google DNS A Record with valid IP address
    foreach ($localDNSServer in $localDNSServers) {
        $TestArray = New-Object PSObject
        $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Bypass Server for Google Resolution'
        $TheTest = (((Resolve-DnsName -name www.google.com -Server $localDNSServer).IP4Address)  |  Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).count -gt 0
        if ($TheTest) {
            $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
            $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ($localDNSServer) 
        }
        else {
            $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
            $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Server IP ' + ($localDNSServer) + 'failed to rewsolve www.google.com') 
        }
        $FullReport.Add($TestArray) | Out-Null
    }
}
function Test-LocalDNSLoopBackIP {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Loopback DNS IP on NIC'
    $TheTest = ((Get-DnsClientServerAddress | ConvertTo-Json -Depth 99  |  Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.Value) -contains '127.0.0.1'
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Companion Mode uses DNS for filtering the OS. Check filter is installed correctly. Check if dns is avaiable on 127.0.0.1'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-NCSINetworkTestWeb {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Microsoft Connect Test'
    $TheTest = ((Invoke-WebRequest -uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing).content -eq 'Microsoft Connect Test')
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Not able to access http://www.msftconnecttest.com/connecttest.txt try in a web browser'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-NotPurpleBlock {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Check NotPurple.com is Blocked'
    $TheTest = ((Invoke-WebRequest -uri notpurple.com -UseBasicParsing).content -notmatch 'faq.html' )
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Notpurple.com is a standard block for testing. Please add it to URL block all or Check Filtering'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-GoogleDotComAccess {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Check www.Google.com'
    $TheTest = (Invoke-WebRequest -uri https://www.google.com/ -UseBasicParsing).StatusCode -eq 200
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Not able to load www.google.com page. Check in web browser'
    }
    $FullReport.Add($TestArray) | Out-Null
}

function Test-LoopbackDNSResolution {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Test Loopback DNS Resolution'
    $TheTest = ((Resolve-DnsName -name dns-filter.familyzone.com -Server 127.0.0.1).IPAddress).count -ge 1
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Companion Mode uses DNS for filtering the OS. Check filter is installed correctly. Check if dns is avaiable on 127.0.0.1'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-CompanionChromeExtension {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Companion Chrome Extension'
    #test if any extesino are force installed
    if (Test-Path 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist') {
        #get Device
        $deviceID = ((Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent' -Name Appliance_IDs).Appliance_IDs -split ",")[0]
        $extensionDeviceID = 'ifinpabiejbjobcphhaomiifjibpkjlf;https://download.qoria.com/browser/' + $deviceID
        #test For DeviceID Extension
        if ((get-Itemproperty -path  'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist') -match $extensionDeviceID) {
            $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
            $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'

            #check for Extension wihtout Device ID
        }
        elseif ((get-Itemproperty -path  'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist') -match 'ifinpabiejbjobcphhaomiifjibpkjlf;https://download.qoria.com/browser/') {
            $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
            $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Extension Installed Not Device ID ' + $deviceID )
        }

    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'No Chrome Extensions are force Installed'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-CompanionEdgeExtension {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Companion Edge Extension'
    #test if any extesino are force installed
    if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist') {
        #get Device
        $deviceID = ((Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent' -Name Appliance_IDs).Appliance_IDs -split ",")[0]
        $extensionDeviceID = 'ifinpabiejbjobcphhaomiifjibpkjlf;https://download.qoria.com/browser/' + $deviceID
        #test For DeviceID Extension
        if ((get-Itemproperty -path  'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist') -match $extensionDeviceID) {
            $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
            $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value -Value 'None'

            #check for Extension wihtout Device ID
        }
        elseif ((get-Itemproperty -path  'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist') -match 'ifinpabiejbjobcphhaomiifjibpkjlf;https://download.qoria.com/browser/') {
            $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
            $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Extension Installed Not Device ID ' + $deviceID )
        }
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'No Edge Extensions are force Installed'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-ConnectTrayAppRunning {
        $TestArray = New-Object PSObject
        $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Tray App Running'
    $TheTest = ((Get-Process -name java*  | Where-Object { $_.Path -like 'C:\Program Files (x86)\FamilyZone\MobileZoneAgent\lib\java\bin\javaw.exe' })).count -gt 0
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Tray App is not Running Check the system Tray. Reboot. Then Check Antivirus Exceptions'
    }
    $FullReport.Add($TestArray) | Out-Null  
}
function Test-LWFilterProccess {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Filter Process Status'
    $TheTest = ((Get-Process | Where-Object ProcessName -Match 'fc-system-service_windows-amd64').count) -eq 1
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'fc-system-service_windows-amd64 is not running check the Filter Service'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-LWFilterService {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Filter Agent Service'
    $Service = Get-Service -Name fz-system-service
    #check if service name is instgalled
    if ( $Service.DisplayName -ne 'Network Management Service') {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Service is not installed or service is corrupt'
        break
    }
    #check status of service
    if ($Service.Status -eq 'Running') {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    elseif ($Service.Status -eq 'Stopped') {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Service is stopped. Startup Type: ' + ($Service.StartType)) 
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Service status is currently' + ($Service.status)) 
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-LWAuthProccess {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Auth Process Status'
    $TheTest = ((Get-Process | Where-Object ProcessName -Match 'fc-authentication-agent_windows-amd64').count) -ne 0
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'fc-authentication-agent_windows-amd64 is not running check the Auth Service'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-LWAuthService {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Authentication Agent Service'
    $Service = Get-Service -Name 'Authentication Agent' 
    #check if service name is instgalled
    if ( $Service.DisplayName -ne 'School Manager Authentication Agent') {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Service is not installed or service is corrupt'
        break
    }
    #check status of service
    if ($Service.Status -eq 'Running') {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    elseif ($Service.Status -eq 'stopped') {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Service is stopped. Startup Type: ' + ($Service.StartType)) 
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value ('Service status is currently' + ($Service.status)) 
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-GatewayPing {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Ping Default Gateway'
    $TheTest = (Test-Connection (Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).NextHop -Count 1 -Quiet) 
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'The computer can not connect to the default gateway. Check the network connection'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-HostFileNCSIfix {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'Check Hostfile for dns.msftncsi.com'
    $TheTest = ([bool]((Get-Content -Path "C:\Windows\System32\drivers\etc\hosts") -like '*131.107.255.255       dns.msftncsi.com*'))
    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Window 10 can show offline while still connected to the internet'
    }
    $FullReport.Add($TestArray) | Out-Null
}
function Test-NCSIActiveProbingRegistry {
(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet").EnableActiveProbing -eq '1'
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'NCSI Active Probe'
    $TheTest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet").EnableActiveProbing -eq '1'
    if ($TheTest ) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Window 10 can show offline while still connected to the internet'
    }
    $FullReport.Add($TestArray) | Out-Null
} 
function Test-LWClouDDNSConnectivity {
    $TestArray = New-Object PSObject
    $TestArray | Add-Member -MemberType NoteProperty -Name "Test" -Value 'LW CloudDNS Connectivity'
    $binaryData = [Byte[]] (0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x04, 0x67, 0x75, 0x6e, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01)
    $TheTest = ((Invoke-WebRequest  -UseBasicParsing -Uri 'https://dns-filter.familyzone.com/dns-query' -Method Post -Headers @{"X-FamilyZone-ClientID" = "00:50:56:ae:aa:a3"; "X-FamilyZone-DeviceIP" = "192.168.9.102"; "X-Familyzone-ApiRegion" = "syd-1"; "X-Familyzone-Applianceid" = "PHYS-SMIC-US-0000-0263"; "X-Familyzone-Username" = "user"; "Fz-Tx-Id" = "6fa28010-732f-47c4-96c2-06b692506a31" } -UserAgent "dns-filter-test-client" -ContentType "application/dns-udpwireformat" -Body $binaryData).RawContent) -match 'sphirewall.application.blocklist.weapons'

    if ($TheTest) {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Pass'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'None'
    }
    else {
        $TestArray | Add-Member -MemberType NoteProperty -Name "Result" -Value 'Fail'
        $TestArray | Add-Member -MemberType NoteProperty -Name "Notes" -Value 'Unable to access https://dns-filter.familyzone.com/dns-query Check for other filtering'
    }
    $FullReport.Add($TestArray) | Out-Null
}


Test-GatewayPing
Test-LocalDNSLoopBackIP
Test-LoopbackDNSResolution
Test-GoogleDotComAccess
Test-NCSINetworkTestWeb
Test-HostfileNCSIfix
Test-ByPassDNSServerResolution
Test-NotPurpleBlock
Test-LWCloudDNSConnectivity
Test-ConnectTrayAppRunning 
Test-LWFilterService
Test-LWFilterProccess
Test-LWAuthService
Test-LWAuthProccess
Test-CompanionChromeExtension 
Test-CompanionEdgeExtension 
Test-NCSIActiveProbingRegistry

Set-Location $OutDIR
 ($env:USERNAME, $env:COMPUTERNAME, $deviceID, $date -join " ") | Out-File Linewize_report.txt ascii
$FullReport  | Sort-Object Result,Test | Format-Table -AutoSize -Wrap | Out-File Linewize_report.txt ascii -Append
$FullReport |Where-Object {$_.Result -Match 'Fail'} | Out-File Linewize_report_Failed_only.txt ascii 




Start-Process $OutDIR
Start-Process $OutDIR\Linewize_report.txt
