#region Setup
#need to run as admin to allow restart of service. 

$outfile = 'c:\temp\authlog.txt'

#region Funtions
function Get-DateFormated {
    return(Get-Date -Format "hh:mm:ss dd-MMM-yyyy") 
}  
function Clear-AllEventLogs {
    wevtutil el | Foreach-Object { wevtutil cl "$_" }
}
function Get-WhoamiLinewizeNet {
    try {
        # return(  (Invoke-WebRequest -uri 'http://ip.jsontest.com/' -UseBasicParsing).Content )
        return(  (Invoke-WebRequest -uri 'http://whoami.linewize.ne' -UseBasicParsing).Content )
    }
    catch {
        <#Do this if a terminating exception happens#>
        return($null)
    }
}
function Set-LWAuthDebugEnabled {
    $authkey = Get-ItempropertyValue -path 'HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\' -Name 'Secret_Key'
    # add _0 as needed for key
    $debugkey = $authkey + '_0'

    #get sha256 has has of debugkey
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    $writer.write("$debugkey")
    $writer.Flush()
    $stringAsStream.Position = 0
  
    $debugkey256 = (Get-FileHash -InputStream $stringAsStream).hash
    #to lower the value
    $debugkey256 = $debugkey256.ToLower()
 
    Set-Itemproperty -path 'HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\' -Name 'Log_Level' -value "$debugkey256"
    Restart-Service  'Authentication Agent'  
}

function Set-LWAuthDebugDisable {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\FamilyZone\AuthenticationAgent\" -Name "Log_Level"
    Restart-Service  'Authentication Agent' 
}
function Reset-LWAuthLogs {
    Stop-Service 'Authentication Agent'  
    Start-Sleep 1 
    Remove-Item  'C:\Program Files (x86)\FamilyZone\AuthenticationAgent\log\*' -Force -Verbose
    Start-Service 'Authentication Agent'  
    #wait for service to start 
    start-sleep 5
}
# $LogFile = $LWAuthLogFiles[0]
function Get-LWAuthRecentLogs {
    $LWAuthLogFiles = Get-ChildItem 'C:\Program Files (x86)\FamilyZone\AuthenticationAgent\log\*'
    foreach ($LogFile in $LWAuthLogFiles) {
        Add-LineBreakToFile
        Add-TextToFile (Get-DateFormated)

        Add-TextToFile ("Logfile Path: " + ($LogFile.fullname))
        Add-TextToFile (Get-Content $LogFile.FullName | Select-Object -Last 20)
    }
}

function Get-EventLogs {
    $Start = (Get-Date).addseconds(-120)
    $End = Get-Date
    # (Get-WinEvent -ListLog *  |Where-Object {$_.RecordCount -gt 0}).count
    Get-WinEvent -ListLog * | Where-Object { ($_.LastWriteTime -gt $Start) -AND ($_.RecordCount -gt 0) } | ForEach-Object { Get-WinEvent -FilterHashTable @{LogName = $_.LogName; StartTime = $Start; EndTime = $End } } | Sort-Object timecreated | Out-String
}


function Add-LineBreakToFile {
    Add-Content -Path $outfile -value "`n ------- `n "
}

function Start-LogFile {
    Set-Content $outfile  'Starting Linewize Auth Monitoring Test'
}
function Get-FCAuthProccesID {
    (Get-Process -Name fc-authentication-agent_windows-amd64).id
}
function Add-TextToFile {
    param (
        [String]$Text
    )
    write-host $text
    add-Content $outfile  $Text -Encoding Ascii
}

function Add-TextToScreen {
    param (
        [String]$Text
    )
    write-host $text
}

function Compare-Proccesses {
    Add-TextToFile "Compare Poccesses List"
    #Get Curent PRocess
    $currentproccesses = Get-Process 

    Add-TextToFile "2 Seconds Ago Proccess List"
    $processesSnapshot | ft | Out-String | out-file $outfile -Encoding ASCII -Append
    # $processesSnapshot >> $outfile 

    # add-Content -path $outfile  $processesSnapshot

    # add-Content -path $outfile  $currentproccesses

    Add-TextToFile "Current Proccess List"
    $currentproccesses | ft | Out-String | out-file $outfile -Encoding ASCII -Append

    #combine process list
    $Allproccesses = $currentproccesses + $processesSnapshot 

    #get IDs of current process
    $currentproccessesID = $currentproccesses.id  | Sort-Object  

    #get IDs of Snapshot process
    $processesSnapshotId = $processesSnapshot.Id | Sort-Object   

    #Compare Poccess list to find new
    $proccessIDNew = $processesSnapshotId | Where-Object { $currentproccessesID -NotContains $_ }

    Add-TextToFile "New Poccess"
    Add-TextToFile (($Allproccesses | Sort-Object id -Descending | Where-Object { $proccessIDNew -contains $_.Id }) | Out-String)

    #Compare Poccess list to find killed
    $proccessIDKilled = $currentproccessesID  | Where-Object { $processesSnapshotId -NotContains $_ }

    Add-TextToFile "Killed Poccess"
    Add-TextToFile (($Allproccesses | Sort-Object id -Descending | Where-Object { $proccessIDKilled -contains $_.Id }) | Out-String)
}
function Get-AllLogInfo{
    Add-LineBreakToFile
    Add-LineBreakToFile

    Add-TextToFile "Getting AllLogInfo"
    Add-TextToFile (Get-DateFormated) 

    Add-TextToFile  (get-service 'Authentication Agent' | Format-List * | Out-String)
    Add-TextToFile ("Proccess IDs  `n Old ID: " + $FCAuthProccesid + "`n New ID: " + $FCAuthProccesidCurrent)

    Compare-Proccesses
    get-process  | Format-Table -Property Name, Id, HandleCount, Path, CPU, ProductVersion, StartTime, Responding  | Out-String 


    Add-TextToFile "Event Logs last 120 seconds"
    Add-TextToFile  (Get-EventLogs)
    Add-TextToFile  "Agent Service Status" 

    Add-TextToFile  (get-service 'Authentication Agent' | Format-List * | Out-String)

    #reset procces id
    $FCAuthProccesid = Get-FCAuthProccesID
    Add-TextToFile (Get-DateFormated) 

    Get-LWAuthRecentLogs

    Add-LineBreakToFile
    Add-LineBreakToFile
    $Filedate = get-date -Format "hh_mm_ss-dd_MMM_yyyy"
    $env:computername
    $env:username
    $logfilecopy = ($outfile.split(".")[0]) , $Filedate, $env:computername, $env:username, ".txt" -join "-"
    Copy-Item $outfile  $logfilecopy 

}


function Start-Setup {
    write-host 'Running Setup Steps'
    Set-LWAuthDebugEnabled
    Clear-AllEventLogs 
    Reset-LWAuthLogs 
    New-Item -Path 'c:\temp' -ItemType Directory -ErrorAction SilentlyContinue 
    write-host 'Setup Complete'

}
#endregion

#Region Loop
function Start-LWauthLogMonitor {
    
    Start-LogFile
    Add-TextToFile (Get-DateFormated)
    Add-TextToFile "Whoami.linewize.net Results"
    Add-TextToFile (Get-WhoamiLinewizeNet)
    Add-LineBreakToFile

    #get Process ID to start
    $FCAuthProccesid = Get-FCAuthProccesID 
    while ($True) {
        Start-Sleep 2
        $processesSnapshot = Get-Process
        $FCAuthProccesidCurrent = Get-FCAuthProccesID
    
        #check if Process id has changed
        if ($FCAuthProccesidCurrent -eq $FCAuthProccesid) {
            Add-TextToScreen  ((Get-DateFormated) + " Auth Agent EXE running ProccessID: " + $FCAuthProccesid )
        }
    
        if ($FCAuthProccesidCurrent -ne $FCAuthProccesid) {
            # write-host (Get-DateFormated) "process id changed OLD" $FCAuthProccesid  "New ID " $FCAuthProccesidCurrent "at"  (Get-DateFormated)
            Get-AllLogInfo

            #reset Process ID
            $FCAuthProccesid = $FCAuthProccesidCurrent
            Start-Sleep 5

            #open the log file to show there has been an event
            Start-Process $outfile
        }
    
        #check if Service is running
        if ((get-service 'Authentication Agent').Status -eq 'running') {
            Add-TextToScreen   ((Get-DateFormated) + " Auth Agent Service running ")
        }
    
        # check if Service is NOT running
        if ((get-service 'Authentication Agent').Status -ne 'running') {
            Get-AllLogInfo
            Start-service 'Authentication Agent'
            Add-TextToFile  "Agent Service Status" 
            Add-TextToFile  (get-service 'Authentication Agent' | Format-List * | Out-String)
            Start-Sleep 5
            #open the log file to show there has been an event
            Start-Process $outfile
    
        }
    }
}

#endregion

<# Debugging 
get-content $outfile 
get-content $outfile  |select-object -last 25
Start-Process $outfile 
taskkill /F /PID (Get-FCAuthProccesID)
Get-FCAuthProccesID  
#>

#Start here 
Start-Setup

#Start Monitoring
Start-LWauthLogMonitor



