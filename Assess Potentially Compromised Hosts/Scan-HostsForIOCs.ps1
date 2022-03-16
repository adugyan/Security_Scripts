# This line primarily exists for testing purposes.  Because we run it several times in an ISE or whatever, this cleans up lingering variables from last time.

Remove-Variable -Name Run*

# If you want to disable any of the searches (which are enclosed in If statements below) you can comment them out here so that we don't set the variable that fires them.

$RunReg_Search = $TRUE
$RunFS_Search = $TRUE
$RunNet_Search = $TRUE
$RunDNS_Search = $TRUE
$RunEvent_Search = $TRUE
$RunUser_Search = $TRUE
$RunTask_Search = $TRUE


$Net = "172.16.12" # The subnet the script will be running its checks against
$Range = 7..13 # The range of devices on the subnet we are scanning. 

$Targets = New-Object System.Collections.ArrayList
 
foreach ($Target in $Range) {
        $IP = "$Net.$Target"
        if (Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $IP)
        {
            echo "$IP is active"
            $Targets.Add($IP) | Out-Null
        }
    }
  
Write-Host "`n"

$Creds = Get-Credential -Credential "Administrator"
 
# Adjust file paths for your list of IOCs as necessary  Output Folder will be created if it does not exist.

$OutFolder = ".\Output"

$FilePath = ".\files.txt"
$NetPath = ".\ips.txt"
$DomainPath = ".\domains.txt"
$TaskPath = ".\tasks.txt"
$UserPath = ".\users.txt"
$RegPath = ".\reg.txt"
  
$OldTrusted = Get-Item WSMan:\localhost\Client\TrustedHosts

foreach($Target in $Targets) {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $Target -Force
    New-Item -Path $OutFolder -Name $Target -ItemType "directory" -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Finding IOCs for $Target `n" 
    if ($RunReg_Search) {
        $RegistryIOCs = Get-Content $RegPath
        Write-Host "Searching for Registry IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock {
            ForEach ($Entry in $USING:RegistryIOCs) {
                Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $Entry -ErrorAction SilentlyContinue # | Findstr "$Entry"
                Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $Entry -ErrorAction SilentlyContinue # | Findstr "$Entry"
                }
            } | Out-File -FilePath "$OutFolder\$Target\RegistryIOCs.txt"
        }
 
    if ($RunFS_Search) {
        $FileIOCs = Get-Content $FilePath | Split-Path -Leaf
        Write-Host "Finding FileSystem IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock {
            Get-ChildItem -Path C:\* -Recurse -Force -Include $USING:FileIOCs -ErrorAction SilentlyContinue | Format-Table FullName, Length, LastWriteTime, Mode
        } | Out-File -FilePath "$OutFolder\$Target\FileIOCs.txt"
    }
  
    if ($RunNet_Search) {
        $NetIOCs = Get-Content $NetPath
        Write-Host "Finding Network IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock {
            $Netstat = netstat -ano
            foreach ($IP in $USING:NetIOCs) {
                $Netstat | findstr $IP
            }     
        } | Out-File -FilePath "$OutFolder\$Target\NetworkIOCs.txt"   
    }
  
    if ($RunDNS_Search) {
        $DomainIOCs = Get-Content $DomainPath
        Write-Host "Finding Domain IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock { 
            foreach ($IP in $USING:DomainIOCs) {
                Get-DNSClientCache | findstr $IP
            } 
        } | Out-File -FilePath "$OutFolder\$Target\DomainIOCs.txt"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock { 
            Get-Content "C:\Windows\System32\Drivers\etc\hosts"
        } | Out-File -FilePath "$OutFolder\$Target\hosts.txt"
    }
   
    if ($RunEvent_Search) {
        Write-Host "Finding Event IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock { 
            #Get-WinEvent -FilterHashtable @{LogName="Security"; id=4728} | Select-Object -ExpandProperty Message
            Get-WinEvent -FilterHashtable @{LogName="Security"; id=4732} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message
        } | Out-File -FilePath "$OutFolder\$Target\EventIOCs.txt"
    }
  
    if ($RunUser_Search) {
        $UserIOCs = Get-Content $UserPath
        Write-Host "Finding User IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock { 
            $LocalUsers = Get-LocalUser
            foreach ($User in $USING:UserIOCs) {
                $LocalUsers | findstr $User
            }
            wmic useraccount
        } | Out-File -FilePath "$OutFolder\$Target\UserIOCs.txt"
    }
  
    if ($RunTask_Search) {
        $TaskIOCs = Get-Content $TaskPath
        Write-Host "Finding Task IOCs for $Target"
        Invoke-Command -ComputerName $Target -Credential $Creds -ScriptBlock { 
        $ScheduledTasks = Get-ScheduledTask 
        foreach ($Task in $USING:TaskIOCs) {
            $ScheduledTasks | findstr $Task
			}
		} | Out-File -FilePath "$OutFolder\$Target\TaskIOCs.txt"
    }

    Write-Host " "
}

$Cleanup = Get-ChildItem -Recurse ".\Output"

ForEach ($File in $Cleanup) {
	If (-Not $File.Length) {
		Remove-Item $File.FullName
		}
	If ($File.Name -eq "hosts.txt" -and ($File.Length -eq 824 -OR $File.Length -eq 1650)) {
		Remove-Item $File.FullName
		}
	}

Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$OldTrusted" -Force
