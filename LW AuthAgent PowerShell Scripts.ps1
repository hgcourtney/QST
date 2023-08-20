c:\"Program Files (x86)"\FamilyZone\MobileZoneAgent\bin\fc-system-service_windows-amd64.exe --service enroll --appliance-id PHYS-SMIC-US-0000-1946 --sam-account lgadmin --api-region syd-1 --appliance-secret 'C@pU5d2023!Ca'


#stop Service
C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\bin\fc-authentication-agent_windows-amd64.exe --service stop

#or
stop-service -Name "Authentication Agent"


#start Service
C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\bin\fc-authentication-agent_windows-amd64.exe --service start
#or
start-service -Name "Authentication Agent"


#REstart Service
C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\bin\fc-authentication-agent_windows-amd64.exe --service restart
Restart-Service -Name "Authentication Agent"


#Uninstall Service (Keeps program installed)

C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\bin\fc-authentication-agent_windows-amd64.exe --service uninstall

#Install Service (Requires program to be installed)
C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\bin\fc-authentication-agent_windows-amd64.exe --service install

#open Auth bin Folder
start-process C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\bin\

#check if service is install / running
get-service -Name "Authentication Agent"

#check if Process is install / running
get-process -name fc-authentication-agent_windows-amd64

#reset logs. Service must be stopped
Move-Item "C:\Program Files (x86)\FamilyZone\AuthenticationAgent\log" "C:\Program Files (x86)\FamilyZone\AuthenticationAgent\log2"

#open Auth Log Folder
start-process C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\log\

#get auth gs last 10 lines
get-content C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\log\agent.log -Tail 10


#get Auth Panic logs last 10 lines
get-content C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\log\agent.panic.log -Tail 10


#get auth gs last 10 lines and Wait for new until stopped. May want to run in new windows
get-content C:\"Program Files (x86)"\FamilyZone\AuthenticationAgent\log\agent.log -Tail 10 -wait

#check if audit pol is logging successfull login event id 4624
auditpol /get /subcategory:Logon

#manual set to allow. Should be turned on via GPO. 
auditpol /set /subcategory:Logon /SUCCESS:ENABLE /FAILURE:ENABLE

#turn on Debug

#turn off debug

#registry get auth key
Get-ItemPropertyValue -Path HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\ -name Secret_Key

#registry get device IDS
Get-ItemPropertyValue -Path HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\ -name Appliance_ID

#get whoami.linewize.net
Invoke-WebRequest -UseBasicParsing -uri http://whoami.linewize.net

#get whoami from machine. This will be different if you have ran powershell as a different user.
whoami

#get whoami from machine using pwoershell. This will be different if you have ran powershell as a different user. 
$env:USERNAME

#get Powershell logon server 
$env:Logonserver

#enrollment Token DeviceID ( Not appliace ID)
Get-ItemPropertyValue -Path HKLM:\SOFTWARE\FamilyZone\MobileZone -name DeviceID


#remove enrollment Token. 
Set-ItemProperty  -Path HKLM:\SOFTWARE\FamilyZone\MobileZone -name DeviceID -value ""

#enrollment Token DeviceID ( Not appliace ID)
Get-ItemPropertyValue -Path HKLM:\SOFTWARE\FamilyZone\MobileZone -name DeviceToken

#remove enrollment Token. 
Set-ItemProperty  -Path HKLM:\SOFTWARE\FamilyZone\MobileZone -name DeviceToken -value ""

#Test if AV Is setup for Auth Agent Path
#download Test file
iwr -UseBasicParsing -uri 'https://secure.eicar.org/eicar.com.txt' -OutFile 'C:\Program Files (x86)\FamilyZone\AuthenticationAgent\bin\avtest.txt'

#check for content in the file. should have 'EICAR-STANDARD-ANTIVIRUS'
Get-Content 'C:\Program Files (x86)\FamilyZone\AuthenticationAgent\bin\avtest.txt'

#Clean up the AV Test file 
Remove-Item 'C:\Program Files (x86)\FamilyZone\AuthenticationAgent\bin\avtest.txt'


#Turn ON Debug Mode
$authkey = Get-ItempropertyValue -path 'HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\' -Name 'Secret_Key' 
$debugkey = $authkey + '_0'
#get sha256 has has of debugkey
$stringAsStream = [System.IO.MemoryStream]::new()
$writer = [System.IO.StreamWriter]::new($stringAsStream)
$writer.write("$debugkey")
$writer.Flush()
$stringAsStream.Position = 0
$debugkey256 = ((Get-FileHash -InputStream $stringAsStream).hash).ToLower()
Set-Itemproperty -path 'HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\' -Name 'Log_Level' -value "$debugkey256"
Restart-Service -Name "Authentication Agent"

#remove debug          
Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\" -Name "Log_Level" ; Restart-Service -Name 'Authentication Agent'
Restart-Service -Name "Authentication Agent"
