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
        throw "PINs not matching!"
     } elseif($Pin1.Contains(" ")) {
        throw "PIN contains whitespace!"
     } elseif(($Pin1.Length -lt 6) -or $Pin1.Length -gt 8) {
        throw "PIN length less than 4 or more than 8"
     }
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
        throw "PUKs not matching!"
     } elseif($Puk1.Contains(" ")) {
        throw "PUK contains whitespace!"
     } elseif(($Puk1.Length -lt 6) -or $Puk1.Length -gt 8) {
        throw "PUK length less than 4 or more than 8"
     }
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


function Set-ResultText() {
    <#
    .SYNOPSIS
        Sets the result text in the Main Window
    .PARAMETER Success
        Whether to mark the result text as successful (green)
    .PARAMETER Failed
        Whether to mark the result text as failure (red)
    #>
    param(
        [Parameter(ParameterSetName = "Success")]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Success,
        [Parameter(ParameterSetName = "Failed")]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Failed
    )

    if($Success) {
        $MainWindow.txtResult.Text = $Success
        $MainWindow.txtResult.Foreground  = "Green"
    } else {
        $MainWindow.txtResult.Text = $Failed
        $MainWindow.txtResult.Foreground  = "Red"
    }
}