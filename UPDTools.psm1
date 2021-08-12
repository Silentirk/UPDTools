Import-Module ActiveDirectory

<#
.Synopsis
   Simple search for AD Users.
.DESCRIPTION
   Looks for AD Users using fields Name, DisplayName, TelephoneNumber, Mobile, Title, Department, SamAccountName, Mail. Strings with spaces, for example, "Egeanin Tamarath" should be included into qoutes. You can specify multiple values separated by commas.
.EXAMPLE
   Search-ADUser 3442, 3452
.EXAMPLE
   Search-ADUser "Egeanin Tamarath"
.EXAMPLE
   Search-ADUser egeanin@contoso.com
#>
function Search-ADUser {
   [CmdletBinding()]
   [Alias("sad")]
   Param
   (
      # String for search
      [Parameter(Mandatory = $true,
         ValueFromPipelineByPropertyName = $true,
         Position = 0)]
      [String[]]$Strings,
      # Search in all domain. By default it is limited to specific organizational unit specified in code below, it could be useful for very large domains.
      [switch]$AllDomain
   )

   Begin {
   }
   Process {
      foreach ($string in $strings) {
         if (!$AllDomain) {
            $scope = 'OU=Seanchan,OU=Branches,DC=contoso,DC=com'
         }
         else {
            $scope = 'DC=contoso,DC=com'
         }
         $obj = Get-ADUser -SearchBase $scope -Filter "name -like '*$String*' -or displayname -like '*$String*' -or telephonenumber -like '*$String*' -or mobile -like '*$String*' -or title -like '*$String*' -or department -like '*$String*' -or samaccountname -like '*$String*' -or mail -like '*$String*'" -Properties CanonicalName, DistinguishedName, DisplayName, enabled, SamAccountName, mail, company, Department, title, OfficePhone, LastLogonDate, Description, City, Office, MobilePhone, whencreated, manager, employeeID, employeeNumber, info
         return $obj
      }
   }
   End {
   }
}

<#
.Synopsis
   Sets new size for UPD for specific user.
.DESCRIPTION
   You can specify user as first parameter ($Identity), or you can pipeline some user (or collection of users) from Get-ADUser, Search-ADUser, Get-ADGroupMember comandlets. You cannot specify size lower than current size. Command must be run with administrator privileges. User must not be logged on with this profile.
.EXAMPLE
   Increase UPD sizes for all managers:   
   Search-ADUser "manager" | Set-UPD -NewSize 20GB
.EXAMPLE
   Increase UPD size for IvanovII:
   Set-UPD IvanovII -NewSize 10GB
#>
function Set-UPD {
   [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
   Param
   (
      # AD User
      [Parameter(Mandatory = $true,
         ValueFromPipeLine = $true,
         ValueFromPipelineByPropertyName = $true,
         Position = 0)]
      [Microsoft.ActiveDirectory.Management.ADUser]$Identity,
      # New size in bytes
      [Parameter(Mandatory = $true, Position = 1)]
      [Uint64]$NewSize,
      [Switch]$Force
   )

   Begin {
      if ($Force) {
         $ConfirmPreference = 'None'
      }
      #Specify share with user profile disk VHDX files here
      $updPath = "\\updserver.contoso.com\UPD"
   }
   Process {
      $aduser = Get-ADUser -Identity $Identity -Properties DistinguishedName, DisplayName, SID, SamAccountName, UserPrincipalName
      if ($aduser) {
         $upd = "$updPath\UVHD-" + $aduser.SID + ".vhdx"
         if (Test-Path $upd) {
            try {
               get-DiskImage -ImagePath $upd -ErrorAction Stop
            }
            catch {
               Write-Error "Cannot access VHDX file. Error:`n$_"
               return
            }
            $updimage = Get-DiskImage -ImagePath $upd
            [PSCustomObject]@{'DistinguishedName' = $aduser.DistinguishedName
               'DisplayName'                      = $aduser.DisplayName
               'SamAccountName'                   = $aduser.SamAccountName
               'UserPrincipalName'                = $aduser.UserPrincipalName
               'UPDPath'                          = $updimage.ImagePath
               'UPDVHDXFileSize_GB'               = $updimage.FileSize / 1GB
               'UPDMaximumSize_GB'                = $updimage.Size / 1GB
               'UPDNewMaximumSize_GB'             = $NewSize / 1GB
            }
            if ($updimage.Size -lt $NewSize) {
               $message = "Change UPD maximum size to $NewSize ?"
               if ($PSCmdlet.ShouldProcess($message, $upd, "Change maximum size to $NewSize")) {
                  $newsizemb = $NewSize / 1MB

                  #Powershell comandlets like Resize-VHD require Hyper-V Role installed. It seems the only way to extend VHDX on machine without Hyper-V role is to use diskpart:
                  "select vdisk file=""$upd""`nexpand vdisk maximum=$newsizemb" | Out-File updtool_temp.txt -Encoding ascii -Force
                  start-process "diskpart.exe" -Wait -NoNewWindow -ArgumentList "/s updtool_temp.txt"
                  Remove-Item updtool_temp.txt -Force 
                  #Still Resize-VHD may work faster, so if you have Hyper-V role installed on your machine you can replace code above with:
                  #Resize-VHD -Path $upd -SizeBytes $NewSize

                  Mount-DiskImage -ImagePath $upd -NoDriveLetter
                  $part = Get-Partition (Get-DiskImage -ImagePath $upd).Number
                  Set-Disk -Number $part.DiskNumber -IsOffline $false
                  Set-Disk -Number $part.DiskNumber -IsReadOnly $false
                  Resize-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -Size (Get-PartitionSupportedSize -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber).SizeMax
                  set-disk -Number $part.DiskNumber -IsOffline $true
                  Dismount-DiskImage -ImagePath $upd
               }
            }
            else { Write-Error "Current UPD Maximum size $($updimage.size) bytes is more or equal than new size $NewSize bytes" }
         }
         else { Write-Error "UPD $upd for user $Identity with SID $($aduser.SID) does not exist." }
      }
      else { Write-Error "Active Directory user $Identity not found" }
   }
   End {
   }
}

<#
.Synopsis
   Gets current sizes for UPD for specific user.
.DESCRIPTION
   You can specify AD user as first parameter ($Identity), or you can pipeline some user (or collection of users) from Get-ADUser, Get-ADGroupMember and similar comandlets (or Search-ADUser comandlet from this module). Command must be run with administrator privileges.  User must not be logged on with this profile.
.EXAMPLE
   Get UPD sizes for all managers:   
   Search-ADUser "manager" | Get-UPD
.EXAMPLE
   Get UPD size for IvanovII:
   Get-UPD IvanovII
#>
function Get-UPD {
   [CmdletBinding()]
   Param
   (
      # AD User
      [Parameter(Mandatory = $true,
         ValueFromPipeLine = $true,
         ValueFromPipelineByPropertyName = $true,
         Position = 0)]
      [Microsoft.ActiveDirectory.Management.ADUser]$Identity
   )

   Begin {
      #Specify share with user profile disk VHDX files here
      $updPath = "\\updserver.contoso.com\UPD"
   
   }
   Process {
      $aduser = Get-ADUser -Identity $Identity -Properties DistinguishedName, DisplayName, SID, SamAccountName, UserPrincipalName
      if ($aduser) {

         $upd = "$updPath\UVHD-" + $aduser.SID + ".vhdx"
         if (Test-Path $upd) {
            $DiskImageBusy = $false
            try {
               Mount-DiskImage -ImagePath $upd -NoDriveLetter -ErrorAction Stop
            }
            catch {
               Write-Warning "Cannot access VHDX file. Probably user is logged on RD farm, or you do not have permissions on file. Error:`n$_"
               $DiskImageBusy = $true
            }
            finally {
               if (!$DiskImageBusy) {
                  $part = Get-Partition (Get-DiskImage -ImagePath $upd).Number
                  Set-Disk -Number $part.DiskNumber -IsOffline $false
                  $remainingsize = (Get-Volume -Partition $part).SizeRemaining
                  Set-Disk -Number $part.DiskNumber -IsOffline $true
                  Dismount-DiskImage -ImagePath $upd
                  $UPDVHDXSize = (Get-DiskImage -ImagePath $upd).Size
               }
               [PSCustomObject]@{'DistinguishedName' = $aduser.DistinguishedName
                  'DisplayName'                      = $aduser.DisplayName
                  'SamAccountName'                   = $aduser.SamAccountName
                  'UserPrincipalName'                = $aduser.UserPrincipalName
                  'UPDPath'                          = $upd
                  'UPDVHDXFileSize_GB'               = (Get-Item $upd).Length / 1GB
                  'UPDMaximumSize_GB'                = if ($DiskImageBusy) { "Cannot get maximum size: file is being used by another process" } else { $UPDVHDXSize / 1GB }
                  'UPDFreeSpace_GB'                  = if ($DiskImageBusy) { "Cannot get remaining profile size: file is being used by another process" } else { $remainingsize / 1GB }
               }
            }
         }
         else { Write-Error "UPD $upd for user $Identity with SID $($aduser.SID) does not exist." }
      }
      else { Write-Error "Active Directory user $Identity not found" }
   }
   End {
   }
}
