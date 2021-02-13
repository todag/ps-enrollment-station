function Get-Readers() {
    <#
    .SYNOPSIS
        Returns a list of connected smart card readers
    #>
    $r = Execute -ExeFile $script:ykman -desc "Getting readers" -arguments "list --readers"
    $readers = New-Object Collections.Generic.List[String]
    foreach($line in $r.stdout.Split([Environment]::NewLine)) {
        if(-Not [string]::IsNullOrWhiteSpace($line)) {
            $readers.Add($line.Trim()) | Out-Null
        }
    }
    return ,$readers
}

function Get-SmartCards() {
    <#
    .SYNOPSIS
        Returns a list of connected smart cards
    #>
    $cards = New-Object Collections.Generic.List[PSCustomObject]
    foreach($reader in (Get-Readers)) {

        $readerInfo = Execute -ExeFile $script:ykman -desc "Reading card in reader $reader" -arguments ('--reader "' + $reader + '" info') -NoThrow

        if ($readerInfo.ExitCode -eq 0) {

            $pivInfo = Execute -ExeFile $script:ykman -desc "Reading PIV info from reader $reader" -arguments ('--reader "' + $reader + '" piv info')

            # Get slot info
            $slot9a = ([regex]::Match($pivInfo.stdout, 'Slot 9a:\s+Algorithm:\s+(.*)\s+Subject DN:\s+(.*)\s+Issuer DN:\s+(.*)\s+Serial:\s+(.*)\s+Fingerprint:\s+(.*)\s+Not before:\s+(.*)\s+Not after:\s+(.*)'))
            $slot9c = ([regex]::Match($pivInfo.stdout, 'Slot 9c:\s+Algorithm:\s+(.*)\s+Subject DN:\s+(.*)\s+Issuer DN:\s+(.*)\s+Serial:\s+(.*)\s+Fingerprint:\s+(.*)\s+Not before:\s+(.*)\s+Not after:\s+(.*)'))

            Write-Host "ReaderInfo: $($readerInfo.stdout)"
            $cards.Add([PSCustomObject]@{
                Reader          = $reader
                DeviceType      = ([regex]::Match($readerInfo.stdout, 'Device type:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                SerialNumber    = ([regex]::Match($readerInfo.stdout, 'Serial number:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                FirmwareVersion = ([regex]::Match($readerInfo.stdout, 'Firmware version:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                Modes           = ([regex]::Match($readerInfo.stdout, 'Enabled USB interfaces:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                App_OTP         = ([regex]::Match($readerInfo.stdout, 'OTP\s+(.*[^\s])').Groups[1].Value -replace "`n", "" -replace "`r", "")
                App_FIDOU2F     = ([regex]::Match($readerInfo.stdout, 'FIDO U2F\s+(.*[^\s])').Groups[1].Value -replace "`n", "" -replace "`r", "")
                App_OpenPGP     = ([regex]::Match($readerInfo.stdout, 'OpenPGP\s+(.*[^\s])').Groups[1].Value -replace "`n", "" -replace "`r", "")
                App_PIV         = ([regex]::Match($readerInfo.stdout, 'PIV\s+(.*[^\s])').Groups[1].Value -replace "`n", "" -replace "`r", "")
                App_OATH        = ([regex]::Match($readerInfo.stdout, 'OATH\s+(.*[^\s])').Groups[1].Value -replace "`n", "" -replace "`r", "")
                App_FIDO2       = ([regex]::Match($readerInfo.stdout, 'FIDO2\s+(.*[^\s])').Groups[1].Value -replace "`n", "" -replace "`r", "")
                PINRetries      = ([regex]::Match($pivInfo.stdout, 'PIN tries remaining:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                PIV_Version     = ([regex]::Match($pivInfo.stdout, 'PIV version:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                CardOk          = $true
                DisplayName     = ([regex]::Match($readerInfo.stdout, 'Device type:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "") + " - " + ([regex]::Match($readerInfo.stdout, 'Serial number:\s(.*)').Groups[1].Value -replace "`n", "" -replace "`r", "")
                slot9a          = [PSCustomObject]@{
                    InUse       = $slot9a.Success
                    Algorithm   = $slot9a.Groups[1].Value.Trim()
                    SubjectDN   = $slot9a.Groups[2].Value.Trim()
                    IssuerDN    = $slot9a.Groups[3].Value.Trim()
                    Serial      = $slot9a.Groups[4].Value.Trim()
                    Fingerprint = $slot9a.Groups[5].Value.Trim()
                    Not_before  = $slot9a.Groups[6].Value.Trim()
                    Not_after   = $slot9a.Groups[7].Value.Trim()

                }
                slot9c          = [PSCustomObject]@{
                    InUse       = $slot9c.Success
                    Algorithm   = $slot9c.Groups[1].Value.Trim()
                    SubjectDN   = $slot9c.Groups[2].Value.Trim()
                    IssuerDN    = $slot9c.Groups[3].Value.Trim()
                    Serial      = $slot9c.Groups[4].Value.Trim()
                    Fingerprint = $slot9c.Groups[5].Value.Trim()
                    Not_before  = $slot9c.Groups[6].Value.Trim()
                    Not_after   = $slot9c.Groups[7].Value.Trim()
                }
            })

        }
        else {
            $cards.Add([PSCustomObject]@{
                Reader          = $reader
                DeviceType      = $reader
                CardOk          = $false
            })
        }
    }
    return ,$cards
}

function Generate-Key() {
    <#
    .SYNOPSIS
        Generates a key on the smart card
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER Pin
        The smart cards PIN code
    .PARAMETER mgmtKey
        The smart cards management key (optional)
    .PARAMETER KeyAlgo
        The algorithm to use for key generation
    .PARAMETER TouchPolicy
        The keys touch policy
    .PARAMETER PinPolicy
        The keys pin policy
    #>
    param(
       [Parameter(Mandatory=$true)]  [PSCustomObject]$Card,
       [Parameter(Mandatory=$true)]  [string]$Pin,
       [Parameter(Mandatory=$false)] [string]$mgmtKey = "010203040506070801020304050607080102030405060708",
       [Parameter(Mandatory=$false)] [string]$KeyAlgo = "RSA2048",
       [Parameter(Mandatory=$false)] [string]$TouchPolicy = "CACHED",
       [Parameter(Mandatory=$false)] [string]$PinPolicy = "ALWAYS",
       [Parameter(Mandatory=$true)]  [string]$Slot
    )
    Execute -ExeFile $script:ykman -desc "Generating $KeyAlgo key in slot $Slot" -arguments "--device $($Card.SerialNumber) piv generate-key -P $Pin -m $mgmtKey -a $KeyAlgo --pin-policy $PinPolicy --touch-policy $TouchPolicy $slot $($script:workDir)\pubkey.pem"
}

function Generate-Csr() {
    <#
    .SYNOPSIS
        Generates a signed csr with the key in the slow
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER Pin
        The smart cards PIN code
    .PARAMETER Subject
        The csr's subject string
    .PARAMETER Slot
        Which keyslot to use to sign the csr
    .PARAMETER PubKeyPath
        Path to the public key (optional)
    #>
    param(
        [Parameter(Mandatory=$true)] [PSCustomObject]$Card,
        [Parameter(Mandatory=$true)] [string]$PIN,
        [Parameter(Mandatory=$true)] [string]$Subject,
        [Parameter(Mandatory=$true)] [string]$Slot,
        [Parameter(Mandatory=$false)] [string]$PubKeyPath = "$($script:workDir)\pubkey.pem"

    )
    Execute -ExeFile $script:ykman -desc "Generating CSR from slot $Slot" -arguments "--device $($Card.SerialNumber) piv generate-csr -P $pin -s $subject $slot $($script:workDir)\pubkey.pem $($script:workDir)\pubkey.csr"
}

function Reset-Piv() {
    <#
    .SYNOPSIS
        Resets the PIV function on the card
    .PARAMETER Card
        The smart card object to perform the operation on
    #>
    param([Parameter(Mandatory=$true)] [PSCustomObject]$Card)
    Execute -ExeFile $script:ykman -desc "Resetting PIV" -arguments "--device $($Card.SerialNumber) piv reset -f"
}

function Set-Mode() {
    <#
    .SYNOPSIS
        Sets the USB modes of the card
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER Mode
        The modes to set
    #>
    param(
        [Parameter(Mandatory=$true)]  [PSCustomObject]$Card,
        [Parameter(Mandatory=$true)]  [string]$Mode
    )
     Execute -ExeFile $script:ykman -desc "Setting mode to $Mode" -arguments "--device $($Card.SerialNumber) mode $Mode -f"
}

function Set-Pin() {
    <#
    .SYNOPSIS
        Sets a new PIN on the card
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER CurrentPin
        The smart cards current PIN code
    .PARAMETER NewPin
        The new PIN to set
    #>
    param(
        [Parameter(Mandatory=$true)][PSCustomObject]$Card,
        [Parameter(Mandatory=$true)][string]$CurrentPin,
        [Parameter(Mandatory=$true)][string]$NewPin
    )
    Execute -ExeFile $script:ykman -desc "Setting PIN code" -arguments "--device $($Card.SerialNumber) piv change-pin -P $CurrentPin -n $NewPin"
}
function Set-Puk() {
    <#
    .SYNOPSIS
        Sets a new PUK on the card
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER CurrentPuk
        The smart cards current PUK code
    .PARAMETER NewPuk
        The new PUK to set
    #>
    param(
        [Parameter(Mandatory=$true)][PSCustomObject]$Card,
        [Parameter(Mandatory=$true)][string]$CurrentPuk,
        [Parameter(Mandatory=$true)][string]$NewPuk
    )
    Execute -ExeFile $script:ykman -desc "Setting PUK code" -arguments "--device $($Card.SerialNumber) piv change-puk -p $CurrentPuk -n $NewPuk"
}

function Unblock-Pin() {
    <#
    .SYNOPSIS
        Unblocks a blocked PIN
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER CurrentPuk
        The smart cards current PUK code
    .PARAMETER NewPin
        The new pin to set
    #>
    param(
        [Parameter(Mandatory=$true)][PSCustomObject]$Card,
        [Parameter(Mandatory=$true)][string]$CurrentPuk,
        [Parameter(Mandatory=$true)][string]$NewPin
    )
    Execute -ExeFile $script:ykman -desc "Unblocking PIN" -arguments "--device $($Card.SerialNumber) piv unblock-pin -p $CurrentPuk -n $NewPin"
}


function Protect-ManagementKey() {
    <#
    .SYNOPSIS
        Protects the management key with the PIN
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER Pin
        The cards current PIN
    .PARAMETER ManagementKey
        The cards current management key
    #>
    param(
        [Parameter(Mandatory=$true)][PSCustomObject]$Card,
        [Parameter(Mandatory=$true)][string]$Pin,
        [Parameter(Mandatory=$false)][string]$ManagementKey = "010203040506070801020304050607080102030405060708"
    )
    Execute -ExeFile $script:ykman -desc "Protecting management key" -arguments "--device $($Card.SerialNumber) piv change-management-key --protect -P $Pin --management-key $ManagementKey --force"
}

function Reset-Chuid() {
    <#
    .SYNOPSIS
        Resets the cards CHUID
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER Pin
        The cards current PIN
    .PARAMETER MgmtKey
        The cards current management key
    #>
    param(
       [Parameter(Mandatory=$true)]  [PSCustomObject]$Card,
       [Parameter(Mandatory=$true)]  [string]$Pin,
       [Parameter(Mandatory=$false)] [string]$MgmtKey = "010203040506070801020304050607080102030405060708"
    )
    Execute -ExeFile $script:ykman -desc "Resetting CHUID" -arguments "--device $($Card.SerialNumber) piv set-chuid -P $pin -m $mgmtKey"
}

function Import-Certificate() {
    <#
    .SYNOPSIS
        Imports a certificate to the specified slot
    .PARAMETER Card
        The smart card object to perform the operation on
    .PARAMETER Pin
        The cards current PIN
    .PARAMETER MgmtKey
        The cards current management key
    .PARAMETER Slot
        The target slot
    .PARAMETER CertFile
        The certfile to import (optional)
    #>
    param(
       [Parameter(Mandatory=$true)]  [PSCustomObject]$Card,
       [Parameter(Mandatory=$true)]  [string]$Pin,
       [Parameter(Mandatory=$false)] [string]$mgmtKey = "010203040506070801020304050607080102030405060708",
       [Parameter(Mandatory=$true)]  [string]$Slot,
       [Parameter(Mandatory=$false)]  [string]$CertFile = "$($script:workDir)\cert.crt"
    )
    Execute -ExeFile $script:ykman -desc "Importing certificate to slot $Slot" -arguments "--device $($Card.SerialNumber) piv import-certificate -P $pin -m $mgmtKey -v $slot $CertFile"
}