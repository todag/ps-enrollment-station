function Validate-Pin()
{
    <#
    .SYNOPSIS
        Validates a PIN code
    .PARAMETER Pin1
        The PUK to validate
    .PARAMETER Pin2
        The PUK to validate
    #>
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Pin1,
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Pin2
     )
     if(-not ($Pin1.ToString() -eq $Pin2.ToString())) {
        return $false
     } elseif($Pin1.Contains(" ")) {
        return $false
     } elseif(($Pin1.Length -lt 6) -or $Pin1.Length -gt 8) {
        return $false
     }
     return $true
}

function Validate-Puk()
{
    <#
    .SYNOPSIS
        Validates a PUK code
    .PARAMETER Puk1
        The PUK to validate
    .PARAMETER Puk2
        The PUK to validate
    #>
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Puk1,
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Puk2
     )
     if(-not ($Puk1.ToString() -eq $Puk2.ToString())) {
        return $false
     } elseif($Puk1.Contains(" ")) {
        return $false
     } elseif(($Puk1.Length -lt 6) -or $Puk1.Length -gt 8) {
        return $false
     }
     return $true
}


function Hide-Secrets() {
    <#
    .SYNOPSIS
        Hide secrets from String, ie PIN, PUK and management keys
    .PARAMETER String
        The string to hide secrets from
    #>
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$String
     )

    if(($script:hideSecrets -eq $true) -and (-not [string]::IsNullOrEmpty($String))) {
        $replacePattern = "(?i)(?<=-p |--pin |--puk |-m |--management-key |-n |--new-puk |--new-pin ).+?([^\s]+)"
        $hidden = $String -replace $replacePattern, "*"
        return ,$hidden
    } else {
        return ,$String
    }
}

function Get-ADUsers() {
    <#
    .SYNOPSIS
        Returns user(s) from Active Directory
    .PARAMETER SearchString
        The search string to filter on
    #>
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$SearchString
    )

    if([string]::IsNullOrEmpty($SearchString)) {
        $SearchString = "*"
    }
    Write-Log -LogString "Searching for users with searchstring $SearchString" -Severity Debug
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = ("(&(objectCategory=User)(samAccountName=" + $SearchString + "))")
    $searcher.PropertiesToLoad.Add("displayName") | Out-Null
    $searcher.PropertiesToLoad.Add("userPrincipalName") | Out-Null
    $entries = $searcher.FindAll()

    $users = New-Object Collections.Generic.List[Object]
    foreach($entry in $entries) {
        $users.Add([PSCustomObject]@{
            DisplayName    = $entry.GetDirectoryEntry().displayName.ToString()
            samAccountName = $entry.GetDirectoryEntry().samAccountName.ToString()
            upn            = $entry.GetDirectoryEntry().userPrincipalName.ToString()
            dn             = $entry.GetDirectoryEntry().distinguishedName.ToString()
        }) | Out-Null
    }
    #$entries.Close() --<
    return ,$users
}