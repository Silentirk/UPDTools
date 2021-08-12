#This script migrates local profiles on server to user profile disks. With little modification can be used to migrate roaming profiles to user profile disks.
#Tested on Windows Server 2012R2 Remote desktopservices host
#Before using this script environment for user profile disks should be prepared including share with VHDX template
#Reset permissions on subfolders and files credit goes to dom-colangelo.

$updPath = "\\server.contoso.com\updshare" #Path to UPD share with existing VHDX template

$fixsourceserverprofiles = $true  #If plan to use UPD with the same RDSH
$i = 100000001 #base vhdx disk signature

$templateUpd = "$updPath\UVHD-template.vhdx" #UPD template file

#Here replace *S-1-5-21-xxxxxxxxxx-* with appropriate partial SID for your domain:
$profiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -like "*S-1-5-21-xxxxxxxxxx-*" -and $_.Name -notlike "*-OLD" } | ForEach-Object { Get-ItemProperty $_.pspath } | Select-Object profileImagePath, sid

foreach ($profile in $profiles) {
  $name = $profile.profileImagePath
  $sid = (New-Object System.Security.Principal.SecurityIdentifier($profile.sid, 0)).Value

  if ($sid) {
    $userUpd = "$updPath\UVHD-$sid.vhdx"
    #Check if UPD already exists
    if (test-path $userUpd) {
      Write-Error "Already exists UPD for $name - $sid"
    }
    else {
      #UPD does not exist, copy template to new file
      Copy-Item -Path $templateUpd -Destination $userUpd
      Write-Information "Created UPD for $name - $sid"
    }
    #Mount UPD for copying data
    $disk = Mount-DiskImage -ImagePath $userUpd
    Write-Information "Mounted vhd for $name"
    #Get drive letter
    $Drive = Get-Partition (Get-DiskImage -ImagePath $userUpd).Number | Get-Volume
    $drivePath = $Drive.DriveLetter + ":\"

    #Copy files from old profile path to new UPD path
    robocopy "$($profile.profileImagePath)" $drivePath /copy:datso /r:0 /mt:64 /xj /xd "Application Data*" "Code Cache" /s /z /np /nfl /njs /njh > $null
    Write-Information "Copied $($profile.profileImagePath) to $drivePath"
        
    #Fix permissions on profile root folder
    $sidX = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $acl = (Get-Item $drivePath).GetAccessControl('Access')
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidX)
    $permission1 = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.SetAccessRule($permission1)
    $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $permission2 = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.SetAccessRule($permission2)
    $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $permission3 = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.SetAccessRule($permission3)
    Set-Acl -Path $drivePath -AclObject $acl

    #Reset permissions on subfolders & files
    Try {
      #Start the job that will reset permissions for each file, don't even start if there are no direct sub-files
      $SubFiles = Get-ChildItem $drivePath -File
      If ($SubFiles) {
        $Job = Start-Job -ScriptBlock { $args[0] | ForEach-Object { icacls $_.FullName /Reset /C } } -ArgumentList $SubFiles
      }
  
      #Now go through each $Path's direct folder (if there's any) and start a process to reset the permissions, for each folder.
      $Processes = @()
      $SubFolders = Get-ChildItem $drivePath -Directory
      If ($SubFolders) {
        Foreach ($SubFolder in $SubFolders) {
          #Start a process rather than a job, icacls should take way less memory than Powershell+icacls
          $Processes += Start-Process icacls -WindowStyle Hidden -ArgumentList """$($SubFolder.FullName)"" /Reset /T /C" -PassThru
        }
      }
 
      #Now that all processes/jobs have been started, let's wait for them (first check if there was any subfile/subfolder)
      #Wait for $Job
      If ($SubFiles) {
        Wait-Job $Job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $Job
      }
      #Wait for all the processes to end, if there's any still active
      If ($SubFolders) {
        Wait-Process -Id $Processes.Id -ErrorAction SilentlyContinue
      }
  
      Write-Host "The script has completed resetting permissions under $($drivePath)."
    }
    Catch {
      $ErrorMessage = $_.Exception.Message
      Throw "There was an error during setting the permissions: $($ErrorMessage)"
    }

    #Set unique disk signature for upd vhdx
    $part = Get-Partition (Get-DiskImage -ImagePath $userUpd).Number
    $disk = $part | Get-Disk
    Set-Disk -UniqueId $disk.UniqueId -Signature $i
    $i++

    #Dismount vhdx
    Dismount-DiskImage -ImagePath $userUpd
    Write-Information "Dismounted VHD for $name"

    #Set user permission on vhdx file
    $acl = (get-item $userUpd).GetAccessControl('Access')
    $permission = New-Object System.Security.AccessControl.FileSystemAccessRule($sidX, 'FullControl', 'None', 'None', 'Allow')
    $acl.SetAccessRule($permission)
    Set-Acl -Path $userUpd -AclObject $acl

    #Rename registry entries and folders on source RDSH
    if ($fixsourceserverprofiles) {
      Rename-Item -Path $profile.profileImagePath -Newname ($profile.profileImagePath + "-OLD")
      Write-Information "Renamed $($profile.profileImagePath) folder"
      Rename-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -NewName ($sid + "-OLD")
      Write-Information "Renamed ProfileList\$sid Registry Key"
    }

  }
}
