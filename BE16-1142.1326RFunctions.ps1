[CmdletBinding()]
param()

#Notes from last run:
#  powershell -ExecutionPolicy Unrestricted BE16-1142.1325RFunctions.ps1
#  
#

#The below 2 lines are for debugging or running specific functions where BEMCLI env is req. (normally commented out)
#this script is now best run from a 2.0 powershell admin instance and follow for reference in ISE seperately
#ipmo "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI"
#ipmo "C:\P-scripts\BEMCLI.RedPill.psm1"


    $pshost = Get-Host              # Get the PowerShell Host.
    $pswindow = $pshost.UI.RawUI    # Get the PowerShell Host's UI.

    $newsize = $pswindow.BufferSize # Get the UI's current Buffer Size.
    $newsize.width = 150            # Set the new buffer's width to 150 columns.
    $pswindow.buffersize = $newsize # Set the new Buffer Size as active.

    $newsize = $pswindow.windowsize # Get the UI's current Window Size.
    $newsize.width = 150            # Set the new Window Width to 150 columns.
    $pswindow.windowsize = $newsize # Set the new Window Size as active.

    Write-Host "Press any key to continue..."
    [void][System.Console]::ReadKey($true)

function WriteLogEntry($logEntry)
{
    Write-Host (Get-Date).ToString()
    Write-Host ("**************************  " + $logEntry + "  **************************")
    Write-Host ""
    Write-Host ""
    Write-Host ""
}


function InstallBEonCAS
{   
    $PSVersionTable

    Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 2048
    Get-ChildItem -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB

Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

    WriteLogEntry("Start Installing CAS")

    #This maps a drive to \\gertrude\products or \\hrousqarep\qarep depending on if we are using a release build or not.
    $hroPassword = "freebe123!"
    $net = new-object -ComObject WScript.Network
    #EBagwell this was changed to use BETrunk with the latest FP5 build...  need to chg this back to Gertrude builds folder for production test.
    $net.MapNetworkDrive("Y:", "\\gertrudesc.htr.ven.veritas.com\products", $false, "hrous\#qauser", $hroPassword)
    #$net.MapNetworkDrive("Y:", "\\hrousqarep.htr.ven.veritas.com\qarep", $false, "hrous\#qauser", $hroPassword)

    #This is where you enter the appropriate Project name & Build number.
    $projectName = "GAGA"
    $latestBuild = "1142.1326R"
    Write-Host "$projectName"
    Write-Host "$latestBuild"
   
    #This will copy BE to a folder called BESetup on the local machine.
    #EBagwell Change this to use BETrunk with the latest FP5 build... or need to chg this back to Gertrude builds folder for production runs.
    Copy-Item -Path "\\gertrudesc.htr.ven.veritas.com\products\be\$projectName\$latestBuild\dvd-layout\BE_DVD\BE\WinNT\Install" -Recurse -Destination "\\p-caso\c$\BESetup"
    #Copy-Item -Path "\\hrousqarep.htr.ven.veritas.com\qarep\BE\BETrunk\$latestBuild\dvd-layout\BE_DVD\BE\WinNT\Install" -Recurse -Destination "\\p-caso\c$\BESetup"

    #This will start the install of BE on the local machine with licenses located in a folder on the c: drive.
    $setupPath = "C:\BESetup\BEx64\setup.exe"
    $agentServer = @("p-caso.hrosl.local")
    $beLicenses = "c:\belicenses\285355337.slf,c:\belicenses\285355147.slf,c:\belicenses\285354577.slf,c:\belicenses\285354747.slf,c:\belicenses\285355127.slf"
    Start-Process -FilePath $setupPath -ArgumentList " /SVR:$agentServer /SLF:$beLicenses /USER:scaleadmin /PASS:Engit123! /DOM:hrosl /ENTSERVER: /CASO: /S: /BOOT:"

    WriteLogEntry("CAS Install started: $latestBuild. 20 minutes then install MMS's. Remember to load BE and set Media Overwright to none")
}


function InstallBEonMBES
{
    WriteLogEntry("Start Installing all MMS machines  ~35 Minutes")

    $computers = Get-Content "c:\p-scripts\computers.txt"

    $password = ConvertTo-SecureString "Engit123!" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("hrosl\scaleadmin", $password)
    $session = New-PSSession -ComputerName $computers -Credential $cred


    Foreach ($computer in $computers)
    {
        Copy-Item -Path "c:\BESetup" -Recurse -Destination "\\$computer\c$"
        Copy-Item -Path "c:\BELicenses" -Recurse -Destination "\\$computer\c$"
        Write-Host "copying $computer"
    
    }
    
        Invoke-Command -Session $session -scriptblock { Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 2048 }
        Invoke-Command -Session $session -scriptblock { Get-ChildItem -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB }
        Invoke-Command -Session $session -scriptblock { start-process "c:\besetup\bex64\setup.exe" -argumentlist " /SLF:c:\belicenses\285355337.slf,c:\belicenses\285354577.slf,c:\belicenses\285354747.slf,c:\belicenses\285355127.slf /USER:scaleadmin /PASS:Engit123! /DOM:hrosl /MMS:p-caso /S: /BOOT:" }
        Write-Host "installing $computers"
        Write-Host "Setup files copied and setup process now started on each MBES."
    

    WriteLogEntry("Finishing Installing all MMS machines. good time to check MMS's is in 20 minutes.  ~30 Minutes then install RAWS next")

}


function PushInstallRemoteAgents
{
    WriteLogEntry("Start Installing RAWS. ~15 Min")

    Invoke-Command {Import-Module "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI\BEMCLI","c:\P-scripts\BEMCLI.RedPill.psm1"}
    $AgentServers = @("P-2016FILESVR.hrosl.local","P-FILESVR.hrosl.local","P-SPS2013.hrosl.local","P-SQL2014.hrosl.local","P-XCHG2013a.hrosl.local","P-VMAGENT.hrosl.local","P-HVAGENT.hrosl.local","ENSLHV2012R2.hrosl.local")
    $BELogon = Get-BELogonAccount "System Logon Account"
    $AgentServers | Install-BEWindowsAgentServer -LogonAccount $BELogon -RestartAutomaticallyIfNecessary -UpgradeAutomatically -Force | Wait-BEJob
    
    WriteLogEntry("Finishing Installing RAWS.  Waiting to ensure remote completions.  ~15 Min then add ESX Host")
}


function CopyModulesToAgents
{
 
    WriteLogEntry("Start copying $latestBuild Modules to each RAWs machine for GatherMem scripts BEMCLI usage  ~25 Minutes")

    $AgentComputers = Get-Content "c:\p-scripts\Agents.txt"

    $password = ConvertTo-SecureString "Engit123!" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("hrosl\scaleadmin", $password)
    $session = New-PSSession -ComputerName $AgentComputers -Credential $cred


    Foreach ($AgentComputer in $AgentComputers)
    {
        Copy-Item -Path "C:\Program Files\Veritas\Backup Exec\Modules" -Recurse -Destination "\\$AgentComputer\c$\Program Files\Veritas\Backup Exec"
        Write-Host "copying $AgentComputer this will take several minutes."
    
    }
    
    WriteLogEntry("Finishing copying Modules directory to each RAWs machine for GatherMem scripts BEMCLI usage  ~1 Minutes")
}


function AddEsxHost
{
    WriteLogEntry("Start Adding ESX Host")
    
    $account = Get-BELogonAccount | Where-Object {$_.Name -eq "root"}
    if($account -eq $null)
    {
        Write-Host "$account Account does not exist, it will be created."
        $ss = ConvertTo-SecureString "Engit123!" -AsPlainText -Force
	    $cred = new-object System.Management.Automation.PSCredential "root", $ss
	    $account = New-BELogonAccount -Name root -AccountType Common -AccountCredential $cred
    }
    else
    {
        Write-Host "$account Account does exist, it will not be created.  CHECK for Clean P-CASO image?"
    }

    Add-BEVMwareAgentServer -Name "10.67.83.248" -LogonAccount "$account"
   
    WriteLogEntry("Finishing Adding ESX Host. ~10 Min then Create Dudupe devices. ")
}


function CreateDedupeDevices
{
    WriteLogEntry("Creating dedupe devices")
    
    Write-Host "Creating a logon account for dedup"
    $logonaccount = Get-BELogonAccount | Where-Object {$_.Name -eq "PDDE"}
    if($logonaccount -eq $null)
    {
	    $ss = "dedupe" | ConvertTo-SecureString -AsPlainText -Force
	    $cred = new-object System.Management.Automation.PSCredential "PDDE", $ss
	    $logonaccount = New-BELogonAccount -Name PDDE -AccountCredential $cred
    }
    else 
    {
        Write-Host "$logonaccount LOGON Account ALREADY EXISTS!!, it will not be created.  CHECK for Clean P-CASO image?"
    }

    Write-Host "Creating all the dedup devices"    
    New-BEDeduplicationDiskStorageDevice -Name "P-CASO-Dedupe" -StoragePath "F:\pdde" -LogonAccount $logonaccount -BackupExecServer P-CASO –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-FILESVR-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-FILESVR –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-2016-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-2016 –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-SPS-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-SPS –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-SQL-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-SQL –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-XCHG-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-XCHG –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-HVAGENT-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-HVAGENT –force
    New-BEDeduplicationDiskStorageDevice -Name "P-MBES-VMAGENT-Dedupe" -StoragePath "D:\pdde" -LogonAccount $logonaccount -BackupExecServer P-MBES-VMAGENT –force

    sleep -Seconds 120
    Write-Host "Restarting all MBES & Agent services"   
   
    #restart services
    $sessions = New-PSSession (Get-BEBackupExecServer *P* | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {Import-Module "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI\BEMCLI"} -Session $sessions
    Invoke-Command {Stop-BEService} -Session $sessions -ThrottleLimit 4
    Invoke-Command {Start-BEService} -Session $sessions -ThrottleLimit 1
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished creating all dedupe devices. ~20 Min Then Setup Sharing")
}


function ConfigureSharingForDedup
{
    WriteLogEntry("Now Sharing dedup devices")

    $itemCriteria = [ref](New-Object BackupExec.Management.Objects.ItemCriteria)
    $dedupDevices = $BEConnection.QueryDeduplicationDiskStorage($itemCriteria) | where {$_.name -match "P-CASO"}
 
    #Since we're sharing your dedup on all your servers, and a dedupe exists on your CAS as well, lets get all the media servers to share each one with.
    $mediaServers = $BEConnection.QueryMediaServer($itemCriteria)  
 
    #Loop through all the dedup devices.  If you wanted to exclude your CAS logic would be needed for that.
    foreach($dedupDevice in $dedupDevices)
    {
        $dedupDevice.SharingInformation.Clear()
 
        foreach ($mediaServer in $mediaServers)
        {
            
            $mediaServerSharingRecord = New-BEManagementObject MediaServerSharingContext
            $mediaServerSharingRecord.MediaServerID = $mediaServer.ID
 
            #If the name of the media server matches the hostserver (the server who created the dedup), then we want to make that server the preferred server.
            if($mediaServer.Name -eq $dedupDevice.HostServer)
            {
                    $mediaServerSharingRecord.State = $mediaServerSharingRecord.State -bor 0x00000008
            }
 
            $dedupDevice.SharingInformation.Add($mediaServerSharingRecord)
        }
     
        
        $BEConnection.UpdateDeduplicationDiskStorage($dedupDevice)
    }
    
    sleep -Seconds 120
    Write-Host "Sharing setup completed, now restarting MBES services"

    $sessions = New-PSSession (Get-BEBackupExecServer *MBES* | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {Import-Module "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI\BEMCLI"} -Session $sessions
    Invoke-Command {Stop-BEService} -Session $sessions -ThrottleLimit 4
    Invoke-Command {Start-BEService} -Session $sessions -ThrottleLimit 1
    Remove-PSSession -Session $sessions


    WriteLogEntry("Finishing sharing all dedup devices.  ~20Min then Create File Server Jobs.")
}


function CreateFileServerJobs
{
    WriteLogEntry("Creating backup jobs for P-FILESVR")

    $fsjob = New-BEFileSystemSelection "D:\*.*" -Recurse
    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "P-Filesvr.hrosl.local"
	$name = $as.Name
    
    $as | New-BEBackupDefinition -FileSystemSelection $fsjob -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly | 
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-filesvr*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-filesvr*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition
                
    WriteLogEntry("Finished creating jobs for P-FILESVR  ~2Min then next server")
}


function Create2016FileServerJobs
{
    WriteLogEntry("Creating backup jobs for P-2016FILESVR")

    $fsjob = New-BEFileSystemSelection "D:\*.*" -Recurse
    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "P-2016filesvr.hrosl.local"
	$name = $as.Name
    
    $as | New-BEBackupDefinition -FileSystemSelection $fsjob -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly | 
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-2016*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-2016*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition
                
    WriteLogEntry("Finished creating jobs for P-2016FILESVR  ~2Min then next server")
}


function CreateSQLJobs
{
    WriteLogEntry("Creating backup jobs for P-SQL2014")

    $sqljob = New-BESqlDatabaseSelection -InstanceName "SQL2014"
    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "P-SQL2014.hrosl.local"
	$name = $as.Name
    
    $as | New-BEBackupDefinition -SqlDatabaseSelection $sqljob -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly |
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-sql*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-sql*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition

                
    WriteLogEntry("Finished creating jobs for P-SQL2014. ~2Min then next server")
}


function CreateESXJobs
{
    WriteLogEntry("Creating backup jobs for P-VMAgent")

    $esxjob = New-BEVMWareSelection "ha-datacenter\P-VMAGENT"
    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "10.67.83.248"
	$name = $as.Name
    
    $as | New-BEBackupDefinition -VMWareSelection $esxjob -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly |
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-vmagent*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-vmagent*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition

                
    WriteLogEntry("Finished creating jobs for P-VMAgent. ~2Min then next server")
}


function CreateExchangeJobs
{
    WriteLogEntry("Creating backup jobs for P-XCHG2013a")

    $xchgjob = New-BEExchangeDatabaseSelection -DatabaseName "Mailbox Database 0573191591"
    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "P-XCHG2013a.hrosl.local"
	$name = $as.Name
    
    $as | New-BEBackupDefinition -ExchangeDatabaseSelection $xchgjob -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly |
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-xchg*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-xchg*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition

                
    WriteLogEntry("Finished creating jobs for P-XCHG2013a. ~2Min then next server")
}


function CreateHyperVJobs
{
    WriteLogEntry("Creating backup jobs for P-HVAGENT")

    $hvjob = New-BEHyperVSelection P-HVAGENT
    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "ENSLHV2012R2.HROSL.LOCAL"
    $name = $as.Name
    
    $as | New-BEBackupDefinition -HyperVSelection $hvjob -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly |
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-hvagent*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-hvagent*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition

                
    WriteLogEntry("Finished creating jobs for P-HVAGENT. ~2Min then next server")
}


function CreateSPSJobs
{
    WriteLogEntry("Creating backup jobs for P-SPS2013")

    $sched1 = New-BESchedule -Daily -Every 1 -StartingAt "6:00am"
    $sched2 = New-BESchedule –HourlyWithTimeWindow –StartingAt 9:00AM –EndingAt 1:00AM –Every 4

    $as = Get-BEAgentServer "P-SPS2013.HROSL.LOCAL"
    $name = $as.Name
    
    $as | New-BEBackupDefinition -SharePointAllResourcesSelection Include -Name ($name) -BackupJobDefault BackupToDeduplicationDevice –WithInitialFullBackupOnly |
        Set-BEInitialFullBackupTask -DiskStorageKeepForHours 24 -Schedule $sched1 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-sps*")) |
        Add-BEIncrementalBackupTask -DiskStorageKeepForHours 8 -Schedule $sched2 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("p-mbes-sps*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterBackup "*full*" -DiskStorageKeepForHours 24 -Storage (Get-BEDeduplicationDiskStorageDevice -Name ("P-CASO*")) |
        Add-BEDuplicateStageBackupTask -ImmediatelyAfterDuplicate "*Duplicate*" -Storage (Get-BETapeDriveDevice -Name ("Tape*")) |
        Save-BEBackupDefinition
      
               
    WriteLogEntry("Finished creating jobs for P-SPS2013. ~2Min then restart all machine services")
}


function RestartServicesCASandMBES
{
    WriteLogEntry("Restarting Services on all machines.  ~20Min")

    #restart services
    $sessions = New-PSSession (Get-BEBackupExecServer *P* | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {Import-Module "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI\BEMCLI"} -Session $sessions
    Invoke-Command {Stop-BEService} -Session $sessions -ThrottleLimit 4
    Invoke-Command {Start-BEService} -Session $sessions -ThrottleLimit 1
    Remove-PSSession -Session $sessions


    WriteLogEntry("Finished Restarting Services on CAS and all MBES.  Now on to Gen files on Agents")

}


function ScheduleGenerateFilesOnFileServer
{
    WriteLogEntry("Scheduling generate files on P-FILESVR")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    $sessions = New-PSSession ( Get-BEAgentServer "P-FILESVR*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN GenerateFiles /SC HOURLY /MO 4 /ST 08:00 /TR C:\GenerateFiles\GenerateFiles.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling generate files on P-FILESVR")
}


function ScheduleGenerateFilesOnVMAgent
{
    WriteLogEntry("Scheduling generate files on P-VMAGENT")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    #The syntax to schedule a command on Windows 2003 is slightly different...it doesn't accept a XML switch.
    $sessions = New-PSSession ( Get-BEAgentServer "P-VMAGENT*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN GenerateFiles /SC HOURLY /MO 4 /ST 08:00 /TR C:\GenerateFiles\GenerateFiles.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling generate files on P-VMAGENT")
}


function ScheduleGenerateFilesOnSQL
{
    WriteLogEntry("Scheduling generate files on P-SQL2014")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    #The syntax to schedule a command on Windows 2003 is slightly different...it doesn't accept a XML switch.
    $sessions = New-PSSession ( Get-BEAgentServer "P-SQL2014*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN InsertRows /SC HOURLY /MO 4 /ST 08:00 /TR C:\insertrows.cmd"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling generate files on P-SQL2014")
}


function ScheduleGenerateFilesOnExchange
{
    WriteLogEntry("Scheduling generate files on P-XCHG2013a")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    #The syntax to schedule a command on Windows 2003 is slightly different...it doesn't accept a XML switch.
    $sessions = New-PSSession ( Get-BEAgentServer "P-XCHG2013a*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN GrowMailbox /SC HOURLY /MO 4 /ST 08:00 /TR C:\ExchScripts\Scripts\Mailgen\growmailbox.cmd"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling generate files on P-XCHG2013a")
}


function ScheduleGenerateFilesOnHVAgent
{
    WriteLogEntry("Scheduling generate files on P-HVAGENT")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    $sessions = New-PSSession ( Get-BEAgentServer "P-HVAGENT*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN GenerateFiles /SC HOURLY /MO 4 /ST 08:00 /TR C:\GenerateFiles\GenerateFiles.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling generate files on P-HVAGENT")
}


function ScheduleCreateFilesOnSPS
{
    WriteLogEntry("Scheduling script to create files on P-SPS2013")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    $sessions = New-PSSession ( Get-BEAgentServer "P-SPS2013*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN GenerateFiles /SC once /ST 20:00 /TR C:\sptools\makewebapps.cmd"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling script to create files on P-SPS2013")

}


function ScheduleGenerateFilesOnSPS
{
    WriteLogEntry("Scheduling script to generate files on P-SPS2013")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    $sessions = New-PSSession ( Get-BEAgentServer "P-SPS2013*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN MODFiles /SC HOURLY /MO 4 /ST 23:30 /TR C:\sptools\modwebapps.cmd"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling script to generate files on P-SPS2013")

}


function ScheduleEnableDebuggingMBES
{
    WriteLogEntry("Scheduling script to enable debugging on all MBES")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    $sessions = New-PSSession ( Get-BEAgentServer *MBES* | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN EnableDebugging /SC once /ST 20:00 /TR C:\enabledebugging.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling script to enable debugging on all MBES")

}


function ScheduleEnableDebuggingCAS
{
    WriteLogEntry("Scheduling script to enable debugging on CAS")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    $sessions = New-PSSession ( Get-BEAgentServer -local | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN EnableDebugging /SC once /ST 20:30 /TR c:\enabledebugging.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling script to enable debugging on CAS")

}


function FinalRestartServicesCASandMBES
{
    WriteLogEntry("Restarting Services on CAS and all MBES")

    #restart services
    $sessions = New-PSSession (Get-BEBackupExecServer *P* | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {Import-Module "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI\BEMCLI"} -Session $sessions
    Invoke-Command {Stop-BEService} -Session $sessions -ThrottleLimit 4
    Invoke-Command {Start-BEService} -Session $sessions -ThrottleLimit 1
    Remove-PSSession -Session $sessions


    WriteLogEntry("Finished Restarting Services on CAS and all MBES")

}


function ScheduleSQLDeadlockScript
{
    WriteLogEntry("Scheduling SQL Deadlock Script on P-CASO")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    #The syntax to schedule a command on Windows 2003 is slightly different...it doesn't accept a XML switch.
    $sessions = New-PSSession ( Get-BEAgentServer "P-CASO*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU hrosl\scaleadmin /RP Engit123! /TN Deadlocks /SC HOURLY /MO 12 /ST 23:15 /TR c:\SQLDeadlock\SQLDeadlock.cmd"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling SQL Deadlock Script on P-CASO")
}


function ScheduleSetupGatherMemoryStats
{
    WriteLogEntry("Scheduling SetupGatherMemoryStats Script on P-CASO")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    #The syntax to schedule a command on Windows 2003 is slightly different...it doesn't accept a XML switch.
    $sessions = New-PSSession ( Get-BEAgentServer "P-CASO*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU administrator /RP Engit123! /TN SetupGatherMem /SC ONCE /ST 21:30 /TR c:\BE16-1142.1326Rmemleak\SetupGatherMemoryStats.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling SetupGatherMemoryStats Script on P-CASO")
}


function ScheduleSetupNotification
{
    WriteLogEntry("Scheduling SetupNotification Script on P-CASO")

    #Schedule the utility to create/delete files on the remote boxes.  We want to sleep for 1 minute after its scheduled, 
    #to help stagger when the tasks are scheduled among all the servers.
    #The syntax to schedule a command on Windows 2003 is slightly different...it doesn't accept a XML switch.
    $sessions = New-PSSession ( Get-BEAgentServer "P-CASO*" | Select-Object -ExpandProperty Name | Sort-Object )
    Invoke-Command {$arguments = "/CREATE /RU administrator /RP Engit123! /TN SetupNotify /SC ONCE /ST 21:35 /TR c:\BE16-1142.1326Rmemleak\SetupNotification.bat"} -Session $sessions
    Invoke-Command {Start-Process -FilePath "schtasks.exe" -ArgumentList $arguments; Sleep 60} -Session $sessions -ThrottleLimit 10
    Remove-PSSession -Session $sessions
    
    WriteLogEntry("Finished scheduling SetupNotification Script on P-CASO")
}


###########################################
# This is the main function in the script #
###########################################

#################################################################################################################
#This is the place where everything is executed, none of the above functions happen until they are called here.
#For example, The Function InstallBEonCAS is created in the code above, but the function is not called until below
#So it does not do anything until it gets down here.
#
# You can choose to use sleeps for a continous run or you can use Pauses for a more manual setup. 
# You can change the '300' seconds to any amount you want.
# This call will sleep for 5 minutes (300 seconds) before running the next function below.
#################################################################################################################

InstallBEonCAS
#sleep -Seconds 1200
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)
ipmo "C:\Program Files\Veritas\Backup Exec\Modules\BEMCLI"

InstallBEonMBES
#sleep -Seconds 1500 
Write-Host "Press any key to continue...   Go and check each MMS and make sure BE gets installed before continueing with script"
[void][System.Console]::ReadKey($true)

PushInstallRemoteAgents
#sleep -Seconds 800 
Write-Host "Press any key to continue...   Go and check each Agent Server and make sure BEAgent gets installed before continueing with script"
Write-Host "go and establish trust with all agent & MMS machines from UI"
[void][System.Console]::ReadKey($true)

CopyModulesToAgents
#sleep -Seconds 60
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

AddEsxHost
#sleep -Seconds 60
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

CreateDedupeDevices
#sleep -Seconds 240
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

ConfigureSharingForDedup
#sleep -Seconds 240
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

CreateFileServerJobs
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

Create2016FileServerJobs
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

CreateSQLJobs
sleep -Seconds 120
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

CreateESXJobs
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

CreateExchangeJobs
sleep -Seconds 120
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

CreateHyperVJobs
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

CreateSPSJobs
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

RestartServicesCASandMBES
#sleep -Seconds 240
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

ScheduleGenerateFilesOnFileServer
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleGenerateFilesOnVMAgent
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleGenerateFilesOnSQL
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleGenerateFilesOnExchange
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleGenerateFilesOnHVAgent
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleCreateFilesOnSPS
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleGenerateFilesOnSPS
sleep -Seconds 60
#Write-Host "Press any key to continue..."
#[void][System.Console]::ReadKey($true)

ScheduleEnableDebuggingMBES
#sleep -Seconds 60
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

ScheduleEnableDebuggingCAS
#sleep -Seconds 60
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

FinalRestartServicesCASandMBES
#sleep -Seconds 240
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

ScheduleSQLDeadlockScript
#sleep -Seconds 60
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

ScheduleSetupGatherMemoryStats
#sleep -Seconds 60
Write-Host "Press any key to continue..."
[void][System.Console]::ReadKey($true)

ScheduleSetupNotification
#sleep -Seconds 10