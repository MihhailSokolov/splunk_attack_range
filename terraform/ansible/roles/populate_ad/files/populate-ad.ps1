$domain = "attackrange.local"
$numberOfUsers = 20

$domainController = $(Get-ADDomainController -server $domain).HostName
$rootPath = $(($domain.ToLower().Split(".") | % { "DC=" + $_}) -Join ',')

Write-Host "Creating OUs..."
New-ADOrganizationalUnit -Name "Groups" -Path "$rootPath"
New-ADOrganizationalUnit -Name "Employees" -Path "$rootPath"
New-ADOrganizationalUnit -Name "Finance" -Path "OU=Employees,$rootPath"
New-ADOrganizationalUnit -Name "IT" -Path "OU=Employees,$rootPath"
New-ADOrganizationalUnit -Name "Other" -Path "OU=Employees,$rootPath"
New-ADOrganizationalUnit -Name "Systems" -Path "$rootPath"
New-ADOrganizationalUnit -Name "Clients" -Path "OU=Systems,$rootPath"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Systems,$rootPath"
Start-Sleep -Seconds 5

Write-Host "Creating Users and Groups..."
New-ADGroup -Name "ServerAdmins" -SamAccountName ServerAdmins -GroupCategory Security -GroupScope Global -DisplayName "ServerAdmins" -Path "OU=Groups,$rootPath" -ManagedBy (Get-ADUser Administrator)
New-ADGroup -Name "ITSupport" -SamAccountName ITSupport -GroupCategory Security -GroupScope Global -DisplayName "ITSupport" -Path "OU=Groups,$rootPath" -ManagedBy (Get-ADUser Administrator)
Start-Sleep -Seconds 5

$searchBase = "OU=Employees,$rootPath"
$OUs = Get-ADOrganizationalUnit -Server $domainController -SearchBase $searchBase -SearchScope OneLevel -Filter * | Select-Object -expand DistinguishedName

1..$numberOfUsers | ForEach-Object {
    $response = Invoke-RestMethod -Uri "https://randomuser.me/api?inc=name,email"
    $firstName = $response.results.name.first
    $lastName = $response.results.name.last
    $email = $response.results.email.replace("@example.com", "@$domain")
    $parts = $email.Replace("@$domain", "").Split(".")
    $userId = $parts[0] + $parts[1].Substring(0, 1)
    $userExists = $false
    try {
        Get-ADUser -Server $domainController "$userId"
        $userExists = $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
        $userExists = $false
    }
    if ($userExists) {
        $randomNum = Get-Random -Minimum -1 -Maximum 10
        $userId += "$randomNum"
        try {
            Get-ADUser -Server $domainController "$userId"
            $userExists = $true
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
            $userExists = $false
        }
        if ($userExists) {
            $userId = $userId.Replace("$randomNum", "$(Get-Random -Minimum -10 -Maximum 100)")
        }
    }
    
    $symbols = 33, 35, 37, 42, 43, 45, 46, 47, 61, 63, 64
    $password = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
    $password += -join ((48..59) | Get-Random -Count 2 | % {[char]$_})
    $password += -join ($symbols | Get-Random -Count 2 | % {[char]$_})

    $OU = $OUs | Get-Random -Count 1
    try {
        New-ADUser -Server $domainController -Name "$userId" -GivenName "$firstName" -Surname "$lastName" -SamAccountName "$userId" -DisplayName "$userId" -UserPrincipalName "$userId@$domain" -Path "$OU" -AccountPassword (ConvertTo-SecureString -AsPlainText "$password" -Force) -EmailAddress "$email" -Enabled $true
    } catch [Microsoft.ActiveDirectory.Management.ADPasswordException] {
        $password = -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
        $password += -join ((48..59) | Get-Random -Count 2 | % {[char]$_})
        $password += -join ($symbols | Get-Random -Count 2 | % {[char]$_})
        New-ADUser -Server $domainController -Name "$userId" -GivenName "$firstName" -Surname "$lastName" -SamAccountName "$userId" -DisplayName "$userId" -UserPrincipalName "$userId@$domain" -Path "$OU" -AccountPassword (ConvertTo-SecureString -AsPlainText "$password" -Force) -EmailAddress "$email" -Enabled $true
    }
    Write-Host "Created user $userId with password $password in $OU"
    Start-Sleep -Seconds 5
}


Write-Host "Assigning Users to Groups"
$serverAdminsGroup = Get-ADGroup ServerAdmins
$itSupportGroup = Get-ADGroup ITSupport

$ITUsers = Get-ADUser -Filter "*" -SearchBase "OU=IT,OU=Employees,$rootPath"
For ($i=0; $i -lt ($ITUsers.Length * 2 / 3); $i++) {
    if ((Get-Random -Minimum 0 -Maximum 2) -gt 0) {
        Add-ADGroupMember -Identity $itSupportGroup -Members $ITUsers[$i]
    } else {
        Add-ADGroupMember -Identity $serverAdminsGroup -Members $ITUsers[$i]
    }
}

$users = Get-ADUser -Filter "*"

Write-Host "Creating Computers..."
$existingComputers = Get-ADComputer -Filter "*" -SearchBase "CN=Computers,$rootPath"
ForEach ($computer in $existingComputers) {
    Move-ADObject -Identity $computer -TargetPath "OU=Servers,OU=Systems,$rootPath"
}

For ($i=1; $i -le $users.Length; $i++) {
    $computerName = "CLIENT-WIN-$($i + 1)"
    New-ADComputer -Name $computerName -SamAccountName $computerName -Path "OU=Clients,OU=Systems,$rootPath" -ManagedBy $itSupportGroup
}

For ($i=1; $i -le ($users.Length / 5); $i++) {
    $computerName = "SERVER-WIN-$i"
    New-ADComputer -Name $computerName -SamAccountName $computerName -Path "OU=Servers,OU=Systems,$rootPath" -ManagedBy $serverAdminsGroup
}

Start-Sleep -Seconds 10

Write-Host "Adding privilege escalation path..."

$path = "AD:\$($itSupportGroup.DistinguishedName)"
$acl = Get-Acl $path
$accessrule = New-Object System.DirectoryServices.ActiceDirectoryAccessRule($serverAdminsGroup.sid, "GenericWrite", "Allow")
$acl.AddAccessRule($accessrule)
Set-Acl -AclObject $acl -Path $path

ForEach ($user in $users) {
    $path = "AD:\$($user.DistinguishedName)"
    $acl = Get-Acl $path
    $accessrule = New-Object System.DirectoryServices.ActiceDirectoryAccessRule($itSupportGroup, "ExtendedRight", "Allow")
    $acl.AddAccessRule($accessrule)
    Set-Acl -AclObject $acl -Path $path
}
ForEach ($user in $(Get-ADGroupMember "Domain Admins")) {
    $path = "AD:\$($user.DistinguishedName)"
    $acl = Get-Acl $path
    $accessrule = New-Object System.DirectoryServices.ActiceDirectoryAccessRule($itSupportGroup, "ExtendedRight", "Allow")
    $acl.AddAccessRule($accessrule)
    Set-Acl -AclObject $acl -Path $path
}

Write-Host "Finished - login with one of the users from ServerAdmins group on the server to be compromised"