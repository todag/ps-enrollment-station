Set-StrictMode -Version 2.0
$appVersion = "0.2 - 2020-02-16"
$appAbout = @"
Enrollment Station v $($appVersion)

Copyright (C) 2021 github.com/todag

Icons from:
http://modernuiicons.com/
https://materialdesignicons.com/
"@

Write-Host ("::Loading enrollment-station v" + $appVersion)
$ErrorActionPreference = "Stop"

#
# ---------------------- Script scope variables ----------------------
#
$script:ykman = "C:\Program Files\Yubico\YubiKey Manager\ykman.exe"
$script:workDir = "$($env:APPDATA)\ps-enrollment-station"
$script:hideSecrets = $true
$script:ShowDebugOutput = $true
$script:ca = (New-Object -ComObject CertificateAuthority.Config).GetConfig(0)

#
# Load Required assemblies
#
Write-Host ("::Loading assemblies... ") -NoNewline
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
        '

Write-Host ("Done!") -ForegroundColor Green
if(!(Test-Path $script:workDir)) {
    New-Item -ItemType Directory -Force -Path $script:workDir | Out-Null
}

#region Functions

function Get-Readers() {
    <#
    .SYNOPSIS
        Returns a list of connected smart card readers
    #>
    $r = Execute -ExeFile $script:ykman -desc "Getting readers" -arguments "list --readers" -NoThrow
    if(-not $r.ExitCode -eq 0) {
        Write-Log -LogString "Error getting readers!" -Severity Critical
        return ,$null
    }
    $readers = New-Object Collections.Generic.List[String]
    foreach($line in $r.stdout.Split([Environment]::NewLine)) {
        if(-Not [string]::IsNullOrWhiteSpace($line)) {
            $readers.Add($line.Trim()) | Out-Null
        }
    }
    Write-Log -LogString "Found $($readers.Count) reader(s)" -Severity Notice
    return ,$readers
}
function Get-SmartCards() {
    <#
    .SYNOPSIS
        Returns a list of connected smart cards
    #>
    $cards = New-Object Collections.Generic.List[PSCustomObject]
    foreach($reader in (Get-Readers)) {

        if(-not ($reader -match "yubico|yubikey")) {
            Write-Log -LogString "Skipping incompatible reader $reader" -Severity Debug
            $cards.Add([PSCustomObject]@{
                Reader          = $reader
                DeviceType      = $reader
                CardOk          = $false
            })
            continue
        }

        $readerInfo = Execute -ExeFile $script:ykman -desc "Reading card in reader $reader" -arguments ('--reader "' + $reader + '" info') -NoThrow

        if ($readerInfo.ExitCode -eq 0) {

            $pivInfo = Execute -ExeFile $script:ykman -desc "Reading PIV info from reader $reader" -arguments ('--reader "' + $reader + '" piv info')

            # Get slot info
            $slot9a = ([regex]::Match($pivInfo.stdout, 'Slot 9a:\s+Algorithm:\s+(.*)\s+Subject DN:\s+(.*)\s+Issuer DN:\s+(.*)\s+Serial:\s+(.*)\s+Fingerprint:\s+(.*)\s+Not before:\s+(.*)\s+Not after:\s+(.*)'))
            $slot9c = ([regex]::Match($pivInfo.stdout, 'Slot 9c:\s+Algorithm:\s+(.*)\s+Subject DN:\s+(.*)\s+Issuer DN:\s+(.*)\s+Serial:\s+(.*)\s+Fingerprint:\s+(.*)\s+Not before:\s+(.*)\s+Not after:\s+(.*)'))

            Write-Log -LogString "Reader piv info:`n $($readerInfo.stdout)" -Severity Debug
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
    .PARAMETER Slot
        The Slot to generate the key in
    .PARAMETER OutputFile
        The file to save the public key to
    #>
    param(
       [Parameter(Mandatory=$true)]  [PSCustomObject]$Card,
       [Parameter(Mandatory=$true)]  [string]$Pin,
       [Parameter(Mandatory=$false)] [string]$mgmtKey = "010203040506070801020304050607080102030405060708",
       [Parameter(Mandatory=$false)] [string]$KeyAlgo = "RSA2048",
       [Parameter(Mandatory=$false)] [string]$TouchPolicy = "CACHED",
       [Parameter(Mandatory=$false)] [string]$PinPolicy = "ALWAYS",
       [Parameter(Mandatory=$true)]  [string]$Slot,
       [Parameter(Mandatory=$true)]  [string]$OutputFile
    )
    Execute -ExeFile $script:ykman -desc "Generating $KeyAlgo key in slot $Slot" -arguments "--device $($Card.SerialNumber) piv generate-key -P $Pin -m $mgmtKey -a $KeyAlgo --pin-policy $PinPolicy --touch-policy $TouchPolicy $slot $OutputFile"
}

function Generate-Csr() {
    <#
    .SYNOPSIS
        Generates a signed csr with the key in the slot
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
    .PARAMETER OutputFile
        File to save the CSR to
    #>
    param(
        [Parameter(Mandatory=$true)] [PSCustomObject]$Card,
        [Parameter(Mandatory=$true)] [string]$PIN,
        [Parameter(Mandatory=$true)] [string]$Subject,
        [Parameter(Mandatory=$true)] [string]$Slot,
        [Parameter(Mandatory=$true)] [string]$PubKeyFile,
        [Parameter(Mandatory=$true)] [string]$OutputFile

    )
    Execute -ExeFile $script:ykman -desc "Generating CSR from slot $Slot" -arguments "--device $($Card.SerialNumber) piv generate-csr -P $pin -s $subject $slot $PubKeyFile $OutputFile"
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
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Card,

        [Parameter(Mandatory=$true)]
        [string]$Pin,

        [Parameter(Mandatory=$false)]
        [string]$mgmtKey = "010203040506070801020304050607080102030405060708",

        [Parameter(Mandatory=$true)]
        [string]$Slot,

        [Parameter(Mandatory=$true, ParameterSetName="A")]
        [string]$CertFile = "$($script:workDir)\cert.crt",

        [Parameter(Mandatory=$true, ParameterSetName="B")]
        [string]$CertBase64
    )

    if($CertBase64) {
        Set-Content "$($script:workDir)\$($Card.SerialNumber).$Slot.crt" -Value $CertBase64
        $CertFile = "$($script:workDir)\$($Card.SerialNumber).$Slot.crt"
    }
    Execute -ExeFile $script:ykman -desc "Importing certificate to slot $Slot" -arguments "--device $($Card.SerialNumber) piv import-certificate -P $pin -m $mgmtKey -v $slot $CertFile"
}
function Request-Certificate()
{
    <#
    .SYNOPSIS
        Requests a certificate from the CA
    .PARAMETER CertTemplate
        The custom CertTemplate object to use for the request
    .PARAMETER CsrFile
        The CSR file to use for the request
    .PARAMETER OutputFile
        The file to save the certificate to
    .PARAMETER Id
        Id of pending request
    .PARAMETER ConfigString
        The CA config string ie hostname\ca-name
    #>
    param(
        [Parameter(Mandatory=$true,  ParameterSetName="A")]
        [PSCustomObject]$CertTemplate,

        [Parameter(Mandatory=$true, ParameterSetName="A")]
        [string]$CsrFile,

        [Parameter(Mandatory=$false, ParameterSetName="A")]
        [Parameter(Mandatory=$false, ParameterSetName="B")]
        [string]$OutputFile,

        [Parameter(Mandatory=$false, ParameterSetName="B")]
        [string]$Id,

        [Parameter(Mandatory=$false, ParameterSetName="A")]
        [Parameter(Mandatory=$false, ParameterSetName="B")]
        [string]$ConfigString = $script:ca
    )

    $r = [PSCustomObject]@{
        Base64 = $null
        ReturnCode = $null
        Pending_Id = $null
        Id = $null
    }

    # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nn-certcli-icertrequest
    # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
    # CR_IN_ENCODEANY = 0xff

    $CertRequest = New-Object -ComObject CertificateAuthority.Request
    if(-not $Id) {
        Write-Log -LogString "Requesting certificate. Template $($CertTemplate.Name) Csr: $CsrFile" -Severity Debug
        $csrData = Get-Content $CsrFile
        $requestStatus = $CertRequest.Submit(0xff,$csrData,"CertificateTemplate:$($CertTemplate.Name)", $ConfigString)
        $r.ReturnCode = $requestStatus
        Write-Log -LogString "Request status: $requestStatus" -Severity Debug
        if($requestStatus -eq 3) {
            $r.Base64 = $CertRequest.GetCertificate(0)
            if($OutputFile) {
                Set-Content $OutputFile -Value $r.Base64
            }
        } elseif($requestStatus -eq 5) {
            $r.Id = $CertRequest.GetRequestId()
        }
    } else {
        $requestStatus = $CertRequest.RetrievePending($Id, $ConfigString)
        Write-Log -LogString "Request status: $requestStatus" -Severity Debug
        $r.ReturnCode = $requestStatus
        if($requestStatus -eq 3) {
            $r.Base64 = $CertRequest.GetCertificate(0)
            if($OutputFile) {
                Set-Content $OutputFile -Value $r.Base64
            }
        }
    }

    if($r.ReturnCode -eq 0) { Write-Log -LogString ":: ReturnCode 0 foreign certificate" -Severity Notice }
    if($r.ReturnCode -eq 2) { Write-Log -Logstring ":: ReturnCode 2 request denied " -Severity Notice }
    if($r.ReturnCode -eq 3) { Write-Log -LogString ":: ReturnCode 3 certificate issued" -Severity Notice }
    if($r.ReturnCode -eq 5) { Write-Log -LogString ":: ReturnCode 5 request pending" -Severity Notice }
    if($r.ReturnCode -eq 6) { Write-Log -LogString ":: ReturnCode 6 certificate revoked" -Severity Notice }

    return ,$r
}

function Get-SigningCertificates() {
    <#
    .SYNOPSIS
        Returns a list of available signing certificates
    #>
    $certs = New-Object Collections.Generic.List[PSCustomObject]
    foreach($cert in @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.37" -and $_.EnhancedKeyUsages["1.3.6.1.4.1.311.20.2.1"]}})) {
        $certs.Add([PSCustomObject]@{
            Thumbprint   = $cert.Thumbprint
            SerialNumber = $cert.SerialNumber
            Subject      = $cert.Subject
            NotAfter     = $cert.NotAfter
            NotBefore    = $cert.NotBefore
            Description  = ($cert.Subject).Substring(0,($cert.Subject).IndexOf(',')) + " " + ($cert.NotBefore)
            })
    }
    Write-Log -LogString "Found $($certs.Count) signing certificates..." -Severity Debug
    return ,$certs
}

function Sign-CertificateRequest() {
    <#
    .SYNOPSIS
        Wraps the CSR in a signed CMC CSR
    .PARAMETER SigningCertificateThumbprint
        Thumbprint of the signing certificate
    .PARAMETER Subject
        Subject of the request (ie. ad\username)
        !! Seems to only work in the ad\username format
    .PARAMETER CertTemplate
        Custom certificate template object used for the inner request
    .PARAMETER CsrFile
        The csr file to sign
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SigningCertificateThumbprint,

        [Parameter(Mandatory=$true)]
        [string]$Subject,

        [Parameter(Mandatory=$true)]
        [PSCustomObject]$CertTemplate,

        [Parameter(Mandatory=$true, ParameterSetName="A")]
        [string]$CsrInputFile,

        [Parameter(Mandatory=$true, ParameterSetName="B")]
        [string]$CsrInputBase64,

        [Parameter(Mandatory=$true, ParameterSetName="A")]
        [string]$CsrOutputFile

    )
    if($CertTemplate.RequiredSignatures -lt 1) {
        Write-Log -LogString "Template does not need Enrollment Agent signing" -Severity Notice
        return
    }

    Write-Log -LogString "Signing $CsrInputFile for subject $subject. Signing cert thumbprint: $SigningCertificateThumbprint" -Severity Debug
    if($CsrInputFile) {
        $csrInput = Get-Content -LiteralPath $CsrInputFile
    } else {
        $csrInput = $CsrInputBase64
    }
    Write-Log -LogString "CSR Input: `n$csrInput" -Severity Debug
    $csrData = [string]::Empty
    foreach($line in ($csrInput -split "`r`n")) {
        if((-not $line.StartsWith("-----")) -and ($line.Length -gt 0)) {
            $csrData = $csrData + $line + [Environment]::NewLine
        }
    }
    Write-Log -LogString "CSR data:`n$csrData" -Severity Debug
    $pkcs10request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    $pkcs10request.InitializeDecode($csrData)
    $cmcRequest = New-Object -ComObject X509Enrollment.CX509CertificateRequestCmc
    $cmcRequest.InitializeFromInnerRequestTemplateName($pkcs10request, $($certTemplate.Name));
    $cmcRequest.RequesterName = $Subject
    $signerCertificate = New-Object -ComObject X509Enrollment.CSignerCertificate
    #$signerCertificate.UIContextMessage = ""
    $signerCertificate.Initialize(0,0,0xc,$SigningCertificateThumbprint)
    $cmcRequest.SignerCertificate = $signerCertificate
    #$cmcRequest.UIContextMessage = ""
    $cmcRequest.Silent = $true
    Write-Log -LogString "Please provide the PIN for the signing certificate!" -Severity Notice
    $cmcRequest.Encode()
    #$strRequest = $cmcRequest.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    Write-Log -LogString "CMC data:`n$($cmcRequest.RawData())" -Severity Debug
    Set-Content -Value $cmcRequest.RawData() -LiteralPath $CsrOutputFile
    Write-Log -LogString "Signed CSR saved to $CsrOutputFile"
}

function Get-CertificateTemplates() {
    <#
    .SYNOPSIS
        Returns a list of all certificate templates
    #>
    $ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
    $ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
    $templates = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($t in @($ADSI.Children)) {
        $template = [PSCustomObject]@{
            DisplayName        = $t.DisplayName.ToString()
            Name               = $t.Name.ToString()
            RequiredSignatures = $t."msPKI-RA-Signature".ToString() -as [Int]
        }
        $templates.Add($template) | Out-Null
    }

    Write-Log -LogString "Fetched $($templates.Count) templates" -Severity Debug
    return ,$templates
}
function Execute() {
    <#
    .SYNOPSIS
        Runs an executable or command and logs the output
    .PARAMETER Desc
        Description of the execution, is presented in the ProgressBar
    .PARAMETER ExeFile
        The file or command to execute
    .PARAMETER Arguments
        The arguments for the executable
    .PARAMETER NoThrow
        Don't throw exception if the execution return code is > 0
    #>
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $Desc,
        [Parameter(Mandatory = $true)]
        [string] $ExeFile,
        [Parameter(Mandatory = $true)]
        [string] $Arguments,
        [Parameter(Mandatory = $false)]
        [switch] $NoThrow
    )

    Write-Log -LogString "Executing: $([System.IO.Path]::GetFileName($exeFile)) $arguments" -Severity Notice

    $MainWindow.ProgressBar.IsIndeterminate = $true
    $MainWindow.txtStatus.Text = $desc

    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.Status = ""
    $runSpace = [runspacefactory]::CreateRunspace()
    $runSpace.ApartmentState = "STA"
    $runSpace.ThreadOptions = "ReuseThread"
    $runSpace.Open()
    $runSpace.SessionStateProxy.SetVariable("syncHash", $syncHash)
    $runSpace.SessionStateProxy.SetVariable("arguments", $arguments)
    $runSpace.SessionStateProxy.SetVariable("exeFile", $exeFile)

    $powershell = [powershell]::Create().AddScript({
        Try {
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = $exeFile
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = $arguments
                $pinfo.CreateNoWindow = $true
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $syncHash.result = [pscustomobject]@{
                    stdout   = $p.StandardOutput.ReadToEnd()
                    stderr   = $p.StandardError.ReadToEnd()
                    ExitCode = $p.ExitCode
                }
                $p.WaitForExit()
                #
                # Hide secrets from output
                #
                $syncHash.result.stdout = Hide-Secrets -String $syncHash.result.stdout
                $syncHash.result.stderr = Hide-Secrets -String $syncHash.result.stderr
                $arguments = Hide-Secrets -String $arguments
            }
            Catch {
                Write-Host "CATCH!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            }
        })

    $powershell.Runspace = $runSpace
    $object = $powershell.BeginInvoke()

    while (!$object.IsCompleted) {
        Start-Sleep -Milliseconds 10
        [System.Windows.Forms.Application]::DoEvents()
    }

    $MainWindow.ProgressBar.IsIndeterminate = $false
    $MainWindow.txtStatus.Text = ""

    Write-Log -LogString "Return code: ---$($syncHash.result.ExitCode)---" -Severity Debug

    if (-Not ([string]::IsNullOrEmpty($syncHash.result.stdout))) {
        Write-Log -LogString "Stdout: $($syncHash.result.stdout.Trim())" -Severity Debug
    }
    if (-Not ([string]::IsNullOrEmpty($syncHash.result.stderr))) {
        Write-Log -LogString "Stderr: $($syncHash.result.stderr.Trim())" -Severity Critical
    }

    if($syncHash.result.ExitCode -ne 0) {
        Write-Log -LogString "Executing $exeFile with arguments: $arguments failed with message: $($syncHash.result.stderr) `n $($syncHash.result.stdout)" -Severity Critical
        if(-not $NoThrow) {
            throw "Executing $exeFile with arguments: $arguments failed with message: $($syncHash.result.stderr) `n $($syncHash.result.stdout)"
        }
    }

    return ,$syncHash.result
}
function Show-CardOperationsWindow(){
    param(
        [Parameter(Mandatory=$true)] [PSCustomObject]$Card,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("ChangePIN", "ChangePUK", "UnblockPIN", "ResetPIV")]
        [string]$Operation
    )

    #
    # Setup Window
    #
    $Win = @{}
    $Win.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_CardOperationsWindow))
    $xaml_CardOperationsWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $Win.$($_.Name) = $Win.Window.FindName($_.Name)
    }

    Write-Host $Operation

    if($Operation -eq "ChangePIN") {
        $Win.grdChangePin.Visibility = "Visible"
    } elseif ($Operation -eq "ChangePUK") {
        $Win.grdChangePuk.Visibility = "Visible"
    } elseif ($Operation -eq "UnblockPIN")
    {
        $Win.grdUnblockPin.Visibility = "Visible"
    } elseif ($Operation -eq "ResetPIV") {
        $Win.grdResetPiv.Visibility = "Visible"
    }

    $Win.btnChangePin.Add_Click({
        try{
            Validate-Pin -Pin1 $Win.pwdChangePinPin1.Password -Pin2 $Win.pwdChangePinPin2.Password
            $Win.Window.Close()
            Set-Pin -Card $Card -CurrentPin $Win.pwdChangePinPin.Password -NewPin $Win.pwdChangePinPin1.Password
            [System.Windows.MessageBox]::Show("PIN Changed on $($Card.DeviceType)", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PIN Change failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnChangePuk.Add_Click({
        try{
            Validate-Puk -Puk1 $Win.pwdChangePukPuk1.Password -Puk2 $Win.pwdChangePukPuk2.Password
            $Win.Window.Close()
            Set-Puk -Card $Card -CurrentPuk $Win.pwdChangePukPuk.Password -NewPuk $Win.pwdChangePukPuk1.Password
            [System.Windows.MessageBox]::Show("PUK Changed on $($Card.DeviceType)", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PUK Change failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnUnblockPin.Add_Click({
        try{
            Validate-Pin -Pin1 $Win.pwdUnblockPinPin1.Password -Pin2 $Win.pwdUnblockPinPin1.Password
            $Win.Window.Close()
            Unblock-Pin -Card $Card -CurrentPuk $Win.pwdUnblockPinPuk.Password -NewPin $Win.pwdUnblockPinPin1.Password
            [System.Windows.MessageBox]::Show("PIN Unblocked and changed on $($Card.DeviceType)", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PIN Unblock failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnResetPiv.Add_Click({
        if(([System.Windows.Forms.MessageBox]::Show("This will reset the PIV application, continue?`n`nWarning! All keys will be lost!","Warning",1,48)) -ne 'Ok') {
            return
        }

        try{
            $Win.Window.Close()
            Reset-Piv -Card $Card
            [System.Windows.MessageBox]::Show("PIV on $($Card.DeviceType) reset successfully", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PIV reset failed on card $(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })




    $Win.Window.ShowDialog()

}
function Show-EnrollWindow(){
    param(
        [Parameter(Mandatory=$true)]  [PSCustomObject]$Card
    )

    #
    # Setup Window
    #
    $Win = @{}
    $Win.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_EnrollWindow))
    $xaml_EnrollWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $Win.$($_.Name) = $Win.Window.FindName($_.Name)
    }

    $Win.cmbTemplates.ItemsSource = Get-CertificateTemplates
    $Win.cmbSigningCerts.ItemsSource = Get-SigningCertificates
    $Win.txtSubject.Text = "/CN=$($env:Username)/"

    $Win.btnShowFindUsersWindow.Add_Click({
        $selectedUser = (Show-FindUsersWindow)
        if(-not [string]::IsNullOrEmpty($selectedUser)) {
            $Win.txtSubject.Text = $selectedUser
        }
    })

    $Win.btnCancel.add_Click({
        $Win.Window.Close()
    })




    $Win.btnEnroll.Add_Click({
        # Get options from UI
        if($Win.cmbiNewCard.IsSelected -or $Win.chkReset.IsChecked) {
            if(([System.Windows.Forms.MessageBox]::Show("This will reset the PIV application and all existing keys will be lost!, continue?","Warning",1,48)) -ne 'Ok') {
                return
            }

            $resetPiv = $true
            $CurrentPin = "123456"
            $CurrentPuk = "12345678"
            if(-not (Validate-Pin -Pin1 $Win.pwdNewPin1.Password -Pin2 $Win.pwdNewPin2.Password)) {
                [System.Windows.MessageBox]::Show("PIN validation failed!", "Information", 'Ok', 'Information') | Out-Null
                return
            }
            $NewPin = $Win.pwdNewPin1.Password
            $NewPuk = $Win.pwdNewPin1.Password
        } else {
            $resetPiv = $false
            $CurrentPin = $Win.pwdCurrentPin.Password
        }

        if($Win.cmbiAdvRequest.IsSelected) {
            $Slot = $Win.cmbSlot.SelectedItem.Tag
            $KeyAlgo = $Win.cmbKeyAlgo.SelectedItem.Tag
            $PinPolicy = $Win.cmbKeyPinPolicy.SelectedItem.Tag
        } else {
            $Slot = "9a"
            $KeyAlgo = "RSA2048"
            $PinPolicy = "DEFAULT"
        }

        $TouchPolicy = $Win.cmbKeyTouchPolicy.SelectedItem.Tag

        $Subject = $Win.txtSubject.Text

        if($win.cmbTemplates.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("No Template selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        } else {
            $CertTemplate = $Win.cmbTemplates.SelectedItem
        }

        if((($win.cmbTemplates.SelectedItem).RequiredSignatures -gt 0) -and $win.cmbSigningCerts.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("Selected Template requires signing but not signing cert selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        } else {
            $SigningCert = $Win.cmbSigningCerts.SelectedItem
        }

        $SetCCIDOnlyMode = $Win.chkSetCCIDOnlyMode.IsChecked

        $opts = "Reset piv: $ResetPiv`nSlot: $Slot`nKey Algorithm: $KeyAlgo`nPIN Policy: $PinPolicy`nTouchPolicy: $TouchPolicy`nCertificate Template: $CertTemplate`nSigning Certificate: $SigningCert`nSubject: $Subject`nSet CCID only mode: $SetCCIDOnlyMode"
        Write-Log -Logstring "Attempting enroll will the following options:`n$opts" -Severity Debug

        try {
            $Win.Window.Close()
            if($resetPiv) {
                reset-piv -Card $Card
                Set-Pin -Card $Card -CurrentPin $CurrentPin -NewPin $NewPin
                Set-Puk -Card $Card -CurrentPuk $CurrentPuk -NewPuk $NewPuk
                $Pin = $NewPin
            } else {
                $Pin = $CurrentPin
            }

            $parms = @{
                Card = $Card
                Pin = $Pin
                TouchPolicy = $TouchPolicy
                PinPolicy = $PinPolicy
                Slot = $Slot
                OutputFile = "$($script:workDir)\$($Card.SerialNumber).$Slot.pubkey.pem"
            }
            Generate-Key @parms

            $parms = @{
                Card = $Card
                Pin = $Pin
                Subject = $Subject
                Slot = $Slot
                PubKeyFile = "$($script:workDir)\$($Card.SerialNumber).$Slot.pubkey.pem"
                OutputFile = "$($script:workDir)\$($Card.SerialNumber).$Slot.csr"
            }
            Generate-Csr @parms

            if(($CertTemplate).RequiredSignatures -gt 0) {
                $parms = @{
                    SigningCertificateThumbprint = ($SigningCert).Thumbprint
                    Subject = $Subject
                    CertTemplate = $CertTemplate
                    CsrInputFile = "$($script:workDir)\$($Card.SerialNumber).$Slot.csr"
                    CsrOutputFile = "$($script:workDir)\$($Card.SerialNumber).$Slot.signed.csr"
                }
                Sign-CertificateRequest  @parms
                $request = Request-Certificate -CertTemplate $CertTemplate -CsrFile "$($script:workDir)\$($Card.SerialNumber).$Slot.signed.csr" -OutputFile "$($script:workDir)\$($Card.SerialNumber).$Slot.crt"
            }
            else {
                $request = Request-Certificate -CertTemplate $CertTemplate -CsrFile "$($script:workDir)\$($Card.SerialNumber).$Slot.csr" -OutputFile "$($script:workDir)\$($Card.SerialNumber).$Slot.crt"
            }

            if($request.ReturnCode -eq 5) {
                [System.Windows.MessageBox]::Show("Certificate request is pending CA Manager approval.`nRequest id: $($request.Id)", "Information", 'Ok', 'Information') | Out-Null
                return
            } elseif($request.ReturnCode -eq 3) {
                Import-Certificate -Card $Card -Pin $Pin -Slot $Slot -CertBase64 $request.Base64
            } else {
                throw "Unexpected return code [$($request.ReturnCode)] while requesting certificate."
            }

            Reset-Chuid -Card $Card -Pin $Pin
            if($SetCCIDOnlyMode) {
                Set-Mode -Card $Card -Mode "CCID"
            }
            [System.Windows.MessageBox]::Show("Certificate enrolled successfully!`n`n$opts", "Information", 'Ok', 'Information') | Out-Null
            [System.Windows.MessageBox]::Show("The Card Holder Unique Identifier (CHUID) has been reset.`n`nYou should remove and reinsert the key before enrolling other certificates or doing any signing operations.", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            #[System.Windows.MessageBox]::Show("$($_ | Out-String)", "Error", 'Ok', 'Error') | Out-Null
            [System.Windows.MessageBox]::Show("Enrollment failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.Window.ShowDialog()
}
function Show-FindUsersWindow() {
    #
    # Setup Window
    #
    $FindUsersWindow = @{}
    $FindUsersWindow.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_FindUsersWindow))
    $xaml_FindUsersWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $FindUsersWindow.$($_.Name) = $FindUsersWindow.Window.FindName($_.Name)
    }

    $FindUsersWindow.SearchButton.add_Click({
        try {
            $users = (Get-AdUsers -SearchString $FindUsersWindow.SearchTextBox.Text)
            $FindUsersWindow.DataGrid.ItemsSource = $users
            $FindUsersWindow.CountTextBlock.Text = "Search matched $($users.Count) users"
        } catch {
            [System.Windows.MessageBox]::Show("$($_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $FindUsersWindow.OkButton.add_Click({
        $FindUsersWindow.Window.Close()
    })

    $FindUsersWindow.CancelButton.add_Click({
        $FindUsersWindow.Window.Close()
    })

    $FindUsersWindow.Window.ShowDialog() | Out-Null

    if($FindUsersWindow.OkButton.IsChecked)
    {
        return "$((Get-WmiObject Win32_NTDOMAIN).DomainName)\$(($FindUsersWindow.DataGrid.SelectedItem).samAccountName)".Trim()
    }
}
function Show-MainWindow(){
    # Setup Window
    #
    $MainWindow = @{}
    $MainWindow.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_MainWindow))
    $xaml_MainWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $MainWindow.$($_.Name) = $MainWindow.Window.FindName($_.Name)
    }

    #
    # Hide console window
    #
    $MainWindow.Window.add_Loaded({
        $consolePtr = [Console.Window]::GetConsoleWindow()
        [Console.Window]::ShowWindow($consolePtr, 0)
    })

    #
    # Show/Hide console button clicked
    #
    $MainWindow.btnShowConsole.add_Click({
        $consolePtr = [Console.Window]::GetConsoleWindow()
        if($MainWindow.btnShowConsole.IsChecked)
        {
            [Console.Window]::ShowWindow($consolePtr, 1)
            Write-Log -LogString "Showing console... *** Warning! *** Closing console window will terminate the script. Use togglebutton to hide it again." -Severity Warning
        }
        else
        {
            Write-Log -LogString "Hiding console..." -Severity Debug
            [Console.Window]::ShowWindow($consolePtr, 0)
        }
    })

    #
    # Appinfo button clicked
    #
    $MainWindow.btnShowAppInfo.add_Click({
        [System.Windows.MessageBox]::Show($appAbout, "Information", 'Ok', 'Information') | Out-Null
    })

    function Check-ValidCardIsSelected{
        if(($MainWindow.lstReaders.SelectedIndex -eq -1) -or (-not $MainWindow.lstReaders.SelectedItem.CardOk)) {
            [System.Windows.MessageBox]::Show("You must select a compatible card.", "Information", 'Ok', 'Information') | Out-Null
            return $false
        } else {
            return $true
        }
    }

    $MainWindow.Window.add_ContentRendered( {
        $MainWindow.lstReaders.ItemsSource = Get-SmartCards
        $MainWindow.txtCA.Text = $script:ca
    })

    $MainWindow.ReloadCardsButton.Add_Click({
        $MainWindow.lstReaders.ItemsSource = Get-SmartCards
    })

    $MainWindow.btnShowEnrollWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-EnrollWindow -Card $MainWindow.lstReaders.SelectedItem
        }
    })

    $MainWindow.btnShowRequestToFileWindow.Add_Click({
        Show-RequestToFileWindow -Card $MainWindow.lstReaders.SelectedItem
    })

    $MainWindow.btnShowRequestPendingWindow.Add_Click({
        Show-RequestPendingWindow -Card $MainWindow.lstReaders.SelectedItem
    })

    $MainWindow.btnChangePin.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "ChangePIN"
        }
    })

    $MainWindow.btnChangePuk.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "ChangePUK"
        }
    })

    $MainWindow.btnUnblockPin.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "UnblockPIN"
        }
    })

    $MainWindow.btnResetPiv.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "ResetPIV"
        }
    })

    $MainWindow.Window.ShowDialog()

}
function Show-RequestPendingWindow(){
    param(
        [Parameter(Mandatory=$false)]  [PSCustomObject]$Card
    )

    #
    # Setup Window
    #
    $Win = @{}
    $Win.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_RequestPendingWindow))
    $xaml_RequestPendingWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $Win.$($_.Name) = $Win.Window.FindName($_.Name)
    }


    if((($Card) -and (-not $Card.CardOk)) -or (-not $Card)) {
        $Win.chkSaveToFile.IsChecked = $true
        $Win.chkSaveToFile.IsEnabled = $false
    }


    $Win.btnCancel.add_Click({
        $Win.Window.Close()
    })

    $Win.btnEnroll.Add_Click({
        try{
            $Id = $Win.txtId.Text
            $Slot = $Win.cmbSlot.SelectedItem.Tag
            $Pin = $Win.pwdPin.Password
            $SaveToFile = $Win.chkSaveToFile.IsChecked

            if($SaveToFile) {
                $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
                $SaveFileDialog.Filter = "Certificate files (*.crt)|*.cer|All files (*.*)|*.*"
                $SaveFileDialog.ShowDialog()

                if($SaveFileDialog.FileName -eq "") {
                    return
                }
            }
            $Win.Window.Close()

            $request = Request-Certificate -Id $Id
            if($request.ReturnCode -eq 5) {
                [System.Windows.MessageBox]::Show("Certificate request is still pending CA Manager approval.`nRequest id: $($Id)", "Information", 'Ok', 'Information') | Out-Null
                return
            } elseif(($request.ReturnCode -eq 3) -and (-not $SaveToFile)) {
                # Save request to card slot
                Import-Certificate -Card $Card -Pin $Pin -Slot $Slot -CertBase64 $request.Base64
                Reset-Chuid -Card $Card -Pin $Pin
                [System.Windows.MessageBox]::Show("Certificate enrolled successfully!", "Information", 'Ok', 'Information') | Out-Null
                [System.Windows.MessageBox]::Show("The Card Holder Unique Identifier (CHUID) has been reset.`n`nYou should remove and reinsert the key before enrolling other certificates or doing any signing operations.", "Information", 'Ok', 'Information') | Out-Null
            } elseif (($request.ReturnCode -eq 3) -and ($SaveToFile)){
                # Save request to file
                Set-Content $SaveFileDialog.FileName -Value $request.Base64
                Write-Log -LogString "Request $Id retrieved and saved to $($SaveFileDialog.FileName)" -Severity Notice
                [System.Windows.MessageBox]::Show("Certificate saved successfully!", "Information", 'Ok', 'Information') | Out-Null
            } else {
                throw "Unexpected return code [$($request.ReturnCode)] while requesting certificate."
            }
        } catch {
            [System.Windows.MessageBox]::Show("Request failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })
    $Win.Window.ShowDialog()
}
function Show-RequestToFileWindow(){
    #
    # Setup Window
    #
    $Win = @{}
    $Win.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_RequestToFileWindow))
    $xaml_RequestToFileWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $Win.$($_.Name) = $Win.Window.FindName($_.Name)
    }

    $Win.cmbTemplates.ItemsSource = Get-CertificateTemplates
    $Win.cmbSigningCerts.ItemsSource = Get-SigningCertificates
    $Win.txtSubject.Text = "/CN=$($env:Username)/"

    $Win.btnShowFindUsersWindow.Add_Click({
        $selectedUser = (Show-FindUsersWindow)
        if(-not [string]::IsNullOrEmpty($selectedUser)) {
            $Win.txtSubject.Text = $selectedUser
        }
    })

    $Win.btnCancel.add_Click({
        $Win.Window.Close()
    })

    $Win.btnSelectCsrFile.add_Click({
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
        $OpenFileDialog.Filter = "Certificate files (*.csr,*.req)|*.csr;*.req|All files (*.*)|*.*"
        $OpenFileDialog.ShowDialog()
        if($OpenFileDialog.FileName -ne "") {
            $Win.txtCsrFilePath.Text = $OpenFileDialog.FileName
        }
    })

    $Win.btnEnroll.Add_Click({
        $Subject = $Win.txtSubject.Text
        if($win.cmbTemplates.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("No Template selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        } else {
            $CertTemplate = $Win.cmbTemplates.SelectedItem
        }

        if((($win.cmbTemplates.SelectedItem).RequiredSignatures -gt 0) -and $win.cmbSigningCerts.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("Selected Template requires signing but not signing cert selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        } else {
            $SigningCert = $Win.cmbSigningCerts.SelectedItem
        }

        if(-not $Win.txtCsrFilePath.Text) {
            [System.Windows.MessageBox]::Show("No CSR File selected!", "Information", 'Ok', 'Information') | Out-Null
            return
        }
        $CsrFile = $Win.txtCsrFilePath.Text


        $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $SaveFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
        $SaveFileDialog.Filter = "Certificate files (*.crt)|*.cer|All files (*.*)|*.*"
        $SaveFileDialog.ShowDialog()
        if($SaveFileDialog.FileName -eq "") {
            return
        }
        $Win.Window.Close()

        try{
            if(($CertTemplate).RequiredSignatures -gt 0) {
                $parms = @{
                    SigningCertificateThumbprint = ($SigningCert).Thumbprint
                    Subject = $Subject
                    CertTemplate = $CertTemplate
                    CsrInputFile = $CsrFile
                    CsrOutputFile = "$($script:workDir)\tmp.signed.csr"
                }
                Sign-CertificateRequest  @parms
                $request = Request-Certificate -CertTemplate $CertTemplate -CsrFile "$($script:workDir)\tmp.signed.csr"
            }
            else {
                $request = Request-Certificate -CertTemplate $CertTemplate -CsrFile $CsrFile
            }

            if($request.ReturnCode -eq 5) {
                [System.Windows.MessageBox]::Show("Certificate request is pending CA Manager approval.`nRequest id: $($request.Id)", "Information", 'Ok', 'Information') | Out-Null
                return
            } elseif($request.ReturnCode -eq 3) {
                Set-Content $SaveFileDialog.FileName -Value $request.Base64
                Write-Log -LogString "Certificate retrieved and saved to $($SaveFileDialog.FileName)" -Severity Notice
                [System.Windows.MessageBox]::Show("Certificate saved successfully!", "Information", 'Ok', 'Information') | Out-Null
            } else {
                throw "Unexpected return code [$($request.ReturnCode)] while requesting certificate."
            }
        } catch {
            [System.Windows.MessageBox]::Show("Request failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.Window.ShowDialog()
}
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
Function Write-Log
{
    <#
    .SYNOPSIS
        Writes log to console
    .PARAMETER LogString
        The string to log/output
    .PARAMETER Severity
        Severity of the message
    #>
    param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$LogString,
    [Parameter(Mandatory = $false)]
    [ValidateSet("Critical", "Warning", "Notice", "Debug")]
    [string]$Severity = "Notice"
    )

    $LogString = Hide-Secrets -String $LogString

    [int]$intSeverity = 0

    if($Severity -eq "Critical") { $intSeverity = 2; $color = "Red" }
    if($Severity -eq "Warning") { $intSeverity = 4; $color = "Magenta" }
    if($Severity -eq "Notice") { $intSeverity = 5; $color = "Cyan" }
    if($Severity -eq "Debug") { $intSeverity = 7; $color = "Yellow" }

    if(($Severity -eq "Debug") -and (-not $script:ShowDebugOutput))
    {
        return
    }

    $TimeStamp = ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))

    if($LogString.Contains([Environment]::NewLine)) {
        $LogString = ($TimeStamp + " [" + $Severity + "] [" + $((Get-PSCallStack)[1].Command) + "] `n" + $LogString)
    } else {
        $LogString = ($TimeStamp + " [" + $Severity + "] [" + $((Get-PSCallStack)[1].Command) + "] " + $LogString)
    }




    Write-Host $LogString -Foreground $color

}
#endregion

#region XAML
[xml]$xaml_FindUsersWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="FindUsersWindow"
    Title="" Height="500" Width="725">

    <Window.Resources>
        <BooleanToVisibilityConverter x:Key="VisCon"/>

        <Style TargetType="{x:Type TextBlock}">
            <Setter Property="FontSize" Value="12"/>
        </Style>
        <Style TargetType="{x:Type TextBox}">
            <Setter Property="FontSize" Value="12"/>
        </Style>
        <Style TargetType="{x:Type Button}">
            <Setter Property="FontSize" Value="12"/>
        </Style>
        <Style TargetType="{x:Type ListBox}">
            <Setter Property="FontSize" Value="12"/>
        </Style>
        <Style TargetType="{x:Type ComboBox}">
            <Setter Property="FontSize" Value="12"/>
        </Style>
        <Style TargetType="{x:Type CheckBox}">
            <Setter Property="FontSize" Value="12"/>
        </Style>

    </Window.Resources>
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="10,0,10,0">
            <TextBlock Text="User: " VerticalAlignment="Center"/>
            <TextBox Name="SearchTextBox" Width="100"/>
            <Button Content="Search" Height="25" Name="SearchButton" Margin="5,0,0,0"/>
        </StackPanel>

        <!--<ScrollViewer Grid.Row="4">-->
            <DataGrid ScrollViewer.CanContentScroll="True"  ScrollViewer.HorizontalScrollBarVisibility="Auto" Grid.Row="4" IsReadOnly="True" ColumnWidth="*" HorizontalAlignment="Stretch" Name="DataGrid" AutoGenerateColumns="True" SelectionMode="Single" Margin="10,10,10,0"/>
        <!--</ScrollViewer>-->
        <TextBlock Name="CountTextBlock" Grid.Column="0" Grid.ColumnSpan="4" Grid.Row="5" Margin="0,0,10,2" HorizontalAlignment="Right"/>
        <StackPanel Grid.Column="0" HorizontalAlignment="Center" Grid.Row="6" Orientation="Horizontal">
            <ToggleButton Content="Ok" Width="60" Height="25" Name="OkButton" Margin="10"/>
            <Button Content="Cancel" Width="60" Height="25" Name="CancelButton" Margin="10"/>
        </StackPanel>

    </Grid>
</Window>

"@
[xml]$xaml_RequestToFileWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="RequestToFileWindow"
    SizeToContent="WidthAndHeight"
    Title="" MinHeight="325" MinWidth="425">

    <Window.Resources>
        <BooleanToVisibilityConverter x:Key="VisCon"/>

        <SolidColorBrush x:Key="iconColor">#336699</SolidColorBrush>
        <!-- Material Design Icons -->
        <Geometry x:Key="searchIcon">M15.5,12C18,12 20,14 20,16.5C20,17.38 19.75,18.21 19.31,18.9L22.39,22L21,23.39L17.88,20.32C17.19,20.75 16.37,21 15.5,21C13,21 11,19 11,16.5C11,14 13,12 15.5,12M15.5,14A2.5,2.5 0 0,0 13,16.5A2.5,2.5 0 0,0 15.5,19A2.5,2.5 0 0,0 18,16.5A2.5,2.5 0 0,0 15.5,14M10,4A4,4 0 0,1 14,8C14,8.91 13.69,9.75 13.18,10.43C12.32,10.75 11.55,11.26 10.91,11.9L10,12A4,4 0 0,1 6,8A4,4 0 0,1 10,4M2,20V18C2,15.88 5.31,14.14 9.5,14C9.18,14.78 9,15.62 9,16.5C9,17.79 9.38,19 10,20H2Z</Geometry>
        <Geometry x:Key="uploadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M16 17H14V13H11L15 9L19 13H16Z</Geometry>
        <Geometry x:Key="downloadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M14 9H16V13H19L15 17L11 13H14Z</Geometry>
        <Geometry x:Key="selectFileIcon">M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H13C12.59,21.75 12.2,21.44 11.86,21.1C9.22,18.67 9.05,14.56 11.5,11.92C13.69,9.5 17.33,9.13 20,11V8L14,2M13,9V3.5L18.5,9H13M20.31,18.9C21.64,16.79 21,14 18.91,12.68C16.8,11.35 14,12 12.69,14.08C11.35,16.19 12,18.97 14.09,20.3C15.55,21.23 17.41,21.23 18.88,20.32L22,23.39L23.39,22L20.31,18.9M16.5,19A2.5,2.5 0 0,1 14,16.5A2.5,2.5 0 0,1 16.5,14A2.5,2.5 0 0,1 19,16.5A2.5,2.5 0 0,1 16.5,19Z</Geometry>

        <!-- ModernUI Icons Icons -->
        <Geometry x:Key="consoleIcon">F1 M 17,20L 59,20L 59,56L 17,56L 17,20 Z M 20,26L 20,53L 56,53L 56,26L 20,26 Z M 23.75,31L 28.5,31L 33.25,37.5L 28.5,44L 23.75,44L 28.5,37.5L 23.75,31 Z </Geometry>
        <Geometry x:Key="backIcon">F1 M 57,42L 57,34L 32.25,34L 42.25,24L 31.75,24L 17.75,38L 31.75,52L 42.25,52L 32.25,42L 57,42 Z </Geometry>
        <Geometry x:Key="reloadIcon">F1 M 38,20.5833C 42.9908,20.5833 47.4912,22.6825 50.6667,26.046L 50.6667,17.4167L 55.4166,22.1667L 55.4167,34.8333L 42.75,34.8333L 38,30.0833L 46.8512,30.0833C 44.6768,27.6539 41.517,26.125 38,26.125C 31.9785,26.125 27.0037,30.6068 26.2296,36.4167L 20.6543,36.4167C 21.4543,27.5397 28.9148,20.5833 38,20.5833 Z M 38,49.875C 44.0215,49.875 48.9963,45.3932 49.7703,39.5833L 55.3457,39.5833C 54.5457,48.4603 47.0852,55.4167 38,55.4167C 33.0092,55.4167 28.5088,53.3175 25.3333,49.954L 25.3333,58.5833L 20.5833,53.8333L 20.5833,41.1667L 33.25,41.1667L 38,45.9167L 29.1487,45.9167C 31.3231,48.3461 34.483,49.875 38,49.875 Z </Geometry>
        <Geometry x:Key="cardIcon">F1 M 23.75,22.1667L 52.25,22.1667C 55.7478,22.1667 58.5833,25.0022 58.5833,28.5L 58.5833,47.5C 58.5833,50.9978 55.7478,53.8333 52.25,53.8333L 23.75,53.8333C 20.2522,53.8333 17.4167,50.9978 17.4167,47.5L 17.4167,28.5C 17.4167,25.0022 20.2522,22.1667 23.75,22.1667 Z M 57,42.75L 19,42.75L 19,45.9167C 19,47.0702 19.3084,48.1518 19.8473,49.0833L 56.1527,49.0833C 56.6916,48.1518 57,47.0702 57,45.9167L 57,42.75 Z M 20.5833,25.3333L 20.5833,31.6667L 26.9167,31.6667L 26.9167,25.3333L 20.5833,25.3333 Z </Geometry>
        <Geometry x:Key="infoIcon">F1 M 31.6666,30.0834L 42.7499,30.0834L 42.7499,33.2501L 42.7499,52.2501L 45.9165,52.2501L 45.9165,57.0001L 31.6666,57.0001L 31.6666,52.2501L 34.8332,52.2501L 34.8332,34.8335L 31.6666,34.8335L 31.6666,30.0834 Z M 38.7917,19C 40.9778,19 42.75,20.7722 42.75,22.9583C 42.75,25.1445 40.9778,26.9167 38.7917,26.9167C 36.6055,26.9167 34.8333,25.1445 34.8333,22.9583C 34.8333,20.7722 36.6055,19 38.7917,19 Z </Geometry>

        <Style TargetType="{x:Type TextBlock}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type PasswordBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
            <Setter Property="Width" Value="90"/>
        </Style>
        <Style TargetType="{x:Type TextBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type Button}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type ComboBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type CheckBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
    </Window.Resources>

    <Grid Name="EnrollGrid" Grid.Row="1" Width="380" Visibility="{Binding ElementName=ShowEnrollGridButton,Path=IsChecked, Converter={StaticResource VisCon}}" Margin="10,10,10,0">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="120"/>
            <ColumnDefinition Width="10"/>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Request certificate to file" FontSize="16"/>
        <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

        <TextBlock Grid.Column="0" Grid.Row="3" Text="Certificate Template"/>
        <ComboBox Grid.Column="2" Grid.Row="3" Name="cmbTemplates" DisplayMemberPath="DisplayName"/>

        <TextBlock Grid.Column="0" Grid.Row="5" Text="Signing certificate" FontSize="12" Name="EnrollSigningCertTextBlock">
            <TextBlock.Style>
                <Style TargetType="TextBlock">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding ElementName=cmbTemplates, Path=SelectedItem.RequiredSignatures, FallbackValue=0}" Value="0">
                            <Setter Property="Visibility" Value="Collapsed"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </TextBlock.Style>
        </TextBlock>
        <ComboBox Grid.Column="2" Grid.Row="5" Name="cmbSigningCerts" DisplayMemberPath="Description" Visibility="{Binding ElementName=EnrollSigningCertTextBlock, Path=Visibility}"/>

        <TextBlock Grid.Column="0" Grid.Row="6" Text="Subject" Visibility="{Binding ElementName=EnrollSigningCertTextBlock, Path=Visibility}"/>
        <Grid Grid.Column="2" Grid.Row="6" Visibility="{Binding ElementName=EnrollSigningCertTextBlock, Path=Visibility}">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Grid.Column="0" Name="txtSubject" IsReadOnly="True" HorizontalAlignment="Stretch"/>
            <Button Grid.Column="1" Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" Name="btnShowFindUsersWindow" ToolTip="Find user" Background="Transparent" Margin="2,2,0,2">
                <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource searchIcon}"/>
            </Button>
        </Grid>

        <TextBlock Grid.Column="0" Grid.Row="7" Text="CSR File" Name="txtSelectCsrFile"/>
        <Grid Grid.Column="2" Grid.Row="7">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Grid.Column="0" Name="txtCsrFilePath" IsReadOnly="True" HorizontalAlignment="Stretch"/>
            <Button Grid.Column="1" Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" Name="btnSelectCsrFile" ToolTip="Select CSR file" Background="Transparent" Margin="2,2,0,2">
                <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource selectFileIcon}"/>
            </Button>
        </Grid>

        <StackPanel Orientation="Horizontal" Grid.Column="2" HorizontalAlignment="Right" Grid.Row="16" Margin="0,10,0,0">
            <Button Name="btnEnroll" Content="Enroll" Width="90"/>
            <Button Name="btnCancel" Content="Cancel" Width="90" Margin="6,2,0,2"/>
        </StackPanel>
    </Grid>
</Window>

"@
[xml]$xaml_RequestPendingWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="RequestPendingWindow"
    Title="" Height="225" Width="425">

    <Window.Resources>
        <BooleanToVisibilityConverter x:Key="VisCon"/>

        <SolidColorBrush x:Key="iconColor">#336699</SolidColorBrush>
        <!-- Material Design Icons -->
        <Geometry x:Key="searchIcon">M15.5,12C18,12 20,14 20,16.5C20,17.38 19.75,18.21 19.31,18.9L22.39,22L21,23.39L17.88,20.32C17.19,20.75 16.37,21 15.5,21C13,21 11,19 11,16.5C11,14 13,12 15.5,12M15.5,14A2.5,2.5 0 0,0 13,16.5A2.5,2.5 0 0,0 15.5,19A2.5,2.5 0 0,0 18,16.5A2.5,2.5 0 0,0 15.5,14M10,4A4,4 0 0,1 14,8C14,8.91 13.69,9.75 13.18,10.43C12.32,10.75 11.55,11.26 10.91,11.9L10,12A4,4 0 0,1 6,8A4,4 0 0,1 10,4M2,20V18C2,15.88 5.31,14.14 9.5,14C9.18,14.78 9,15.62 9,16.5C9,17.79 9.38,19 10,20H2Z</Geometry>
        <Geometry x:Key="uploadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M16 17H14V13H11L15 9L19 13H16Z</Geometry>
        <Geometry x:Key="downloadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M14 9H16V13H19L15 17L11 13H14Z</Geometry>

        <!-- ModernUI Icons Icons -->
        <Geometry x:Key="consoleIcon">F1 M 17,20L 59,20L 59,56L 17,56L 17,20 Z M 20,26L 20,53L 56,53L 56,26L 20,26 Z M 23.75,31L 28.5,31L 33.25,37.5L 28.5,44L 23.75,44L 28.5,37.5L 23.75,31 Z </Geometry>
        <Geometry x:Key="backIcon">F1 M 57,42L 57,34L 32.25,34L 42.25,24L 31.75,24L 17.75,38L 31.75,52L 42.25,52L 32.25,42L 57,42 Z </Geometry>
        <Geometry x:Key="reloadIcon">F1 M 38,20.5833C 42.9908,20.5833 47.4912,22.6825 50.6667,26.046L 50.6667,17.4167L 55.4166,22.1667L 55.4167,34.8333L 42.75,34.8333L 38,30.0833L 46.8512,30.0833C 44.6768,27.6539 41.517,26.125 38,26.125C 31.9785,26.125 27.0037,30.6068 26.2296,36.4167L 20.6543,36.4167C 21.4543,27.5397 28.9148,20.5833 38,20.5833 Z M 38,49.875C 44.0215,49.875 48.9963,45.3932 49.7703,39.5833L 55.3457,39.5833C 54.5457,48.4603 47.0852,55.4167 38,55.4167C 33.0092,55.4167 28.5088,53.3175 25.3333,49.954L 25.3333,58.5833L 20.5833,53.8333L 20.5833,41.1667L 33.25,41.1667L 38,45.9167L 29.1487,45.9167C 31.3231,48.3461 34.483,49.875 38,49.875 Z </Geometry>
        <Geometry x:Key="cardIcon">F1 M 23.75,22.1667L 52.25,22.1667C 55.7478,22.1667 58.5833,25.0022 58.5833,28.5L 58.5833,47.5C 58.5833,50.9978 55.7478,53.8333 52.25,53.8333L 23.75,53.8333C 20.2522,53.8333 17.4167,50.9978 17.4167,47.5L 17.4167,28.5C 17.4167,25.0022 20.2522,22.1667 23.75,22.1667 Z M 57,42.75L 19,42.75L 19,45.9167C 19,47.0702 19.3084,48.1518 19.8473,49.0833L 56.1527,49.0833C 56.6916,48.1518 57,47.0702 57,45.9167L 57,42.75 Z M 20.5833,25.3333L 20.5833,31.6667L 26.9167,31.6667L 26.9167,25.3333L 20.5833,25.3333 Z </Geometry>
        <Geometry x:Key="infoIcon">F1 M 31.6666,30.0834L 42.7499,30.0834L 42.7499,33.2501L 42.7499,52.2501L 45.9165,52.2501L 45.9165,57.0001L 31.6666,57.0001L 31.6666,52.2501L 34.8332,52.2501L 34.8332,34.8335L 31.6666,34.8335L 31.6666,30.0834 Z M 38.7917,19C 40.9778,19 42.75,20.7722 42.75,22.9583C 42.75,25.1445 40.9778,26.9167 38.7917,26.9167C 36.6055,26.9167 34.8333,25.1445 34.8333,22.9583C 34.8333,20.7722 36.6055,19 38.7917,19 Z </Geometry>

        <Style TargetType="{x:Type TextBlock}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type PasswordBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
            <Setter Property="Width" Value="90"/>
        </Style>
        <Style TargetType="{x:Type TextBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type Button}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type ComboBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type CheckBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>

    </Window.Resources>

    <Grid Name="RetrieveGrid" Grid.Row="1" Width="380" Visibility="{Binding ElementName=ShowRetrieveGridButton,Path=IsChecked, Converter={StaticResource VisCon}}" Margin="10,10,10,0">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="120"/>
            <ColumnDefinition Width="10"/>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="20"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Retrieve approved certificate" FontSize="16"/>
        <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

        <TextBlock Grid.Column="0" Grid.Row="4" Text="Request Id"/>
        <TextBox Grid.Column="2" Grid.Row="4" Name="txtId" HorizontalAlignment="Stretch"/>

        <TextBlock Grid.Column="0" Grid.Row="5" Text="Save to file"/>
        <CheckBox Grid.Column="2" Grid.Row="5" Name="chkSaveToFile" VerticalAlignment="Center"/>

        <TextBlock Grid.Column="0" Grid.Row="6" Text="Target Slot" Name="txtSlot">
            <TextBlock.Style>
                    <Style TargetType="TextBlock">
                        <Style.Triggers>
                            <DataTrigger Binding="{Binding ElementName=chkSaveToFile, Path=IsChecked, FallbackValue=False}" Value="True">
                                <Setter Property="Visibility" Value="Collapsed"/>
                            </DataTrigger>
                        </Style.Triggers>
                    </Style>
                </TextBlock.Style>
        </TextBlock>
        <ComboBox Grid.Column="2" Grid.Row="6" HorizontalAlignment="Stretch" Name="cmbSlot" SelectedIndex="0" Visibility="{Binding ElementName=txtSlot, Path=Visibility}">
            <ComboBoxItem Content="Slot 9a: PIV Authentication" Tag="9a"/>
            <ComboBoxItem Content="Slot 9c: Digital Signature" Tag="9c"/>
            <ComboBoxItem Content="Slot 9d: Key Management" Tag="9d"/>
            <ComboBoxItem Content="Slot 9e: Card Authentication" Tag="9e"/>
            <ComboBoxItem Content="Slot f9: Attestation" Tag="f9"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="7" Text="Current PIN" Visibility="{Binding ElementName=txtSlot, Path=Visibility}"/>
        <PasswordBox Grid.Column="2" Grid.Row="7" Name="pwdPin" HorizontalAlignment="Left" Visibility="{Binding ElementName=txtSlot, Path=Visibility}"/>

        <StackPanel Grid.Column="2" Grid.Row="8" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button Name="btnEnroll" Content="Retrieve" Width="90"/>
            <Button Name="btnCancel" Content="Cancel" Width="90" Margin="6,2,0,2"/>
        </StackPanel>


    </Grid>


</Window>

"@
[xml]$xaml_CardOperationsWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="RequestPendingWindow"
    Title="" Height="225" Width="425">

    <Window.Resources>
        <BooleanToVisibilityConverter x:Key="VisCon"/>

        <SolidColorBrush x:Key="iconColor">#336699</SolidColorBrush>
        <!-- Material Design Icons -->
        <Geometry x:Key="searchIcon">M15.5,12C18,12 20,14 20,16.5C20,17.38 19.75,18.21 19.31,18.9L22.39,22L21,23.39L17.88,20.32C17.19,20.75 16.37,21 15.5,21C13,21 11,19 11,16.5C11,14 13,12 15.5,12M15.5,14A2.5,2.5 0 0,0 13,16.5A2.5,2.5 0 0,0 15.5,19A2.5,2.5 0 0,0 18,16.5A2.5,2.5 0 0,0 15.5,14M10,4A4,4 0 0,1 14,8C14,8.91 13.69,9.75 13.18,10.43C12.32,10.75 11.55,11.26 10.91,11.9L10,12A4,4 0 0,1 6,8A4,4 0 0,1 10,4M2,20V18C2,15.88 5.31,14.14 9.5,14C9.18,14.78 9,15.62 9,16.5C9,17.79 9.38,19 10,20H2Z</Geometry>
        <Geometry x:Key="uploadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M16 17H14V13H11L15 9L19 13H16Z</Geometry>
        <Geometry x:Key="downloadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M14 9H16V13H19L15 17L11 13H14Z</Geometry>

        <!-- ModernUI Icons Icons -->
        <Geometry x:Key="consoleIcon">F1 M 17,20L 59,20L 59,56L 17,56L 17,20 Z M 20,26L 20,53L 56,53L 56,26L 20,26 Z M 23.75,31L 28.5,31L 33.25,37.5L 28.5,44L 23.75,44L 28.5,37.5L 23.75,31 Z </Geometry>
        <Geometry x:Key="backIcon">F1 M 57,42L 57,34L 32.25,34L 42.25,24L 31.75,24L 17.75,38L 31.75,52L 42.25,52L 32.25,42L 57,42 Z </Geometry>
        <Geometry x:Key="reloadIcon">F1 M 38,20.5833C 42.9908,20.5833 47.4912,22.6825 50.6667,26.046L 50.6667,17.4167L 55.4166,22.1667L 55.4167,34.8333L 42.75,34.8333L 38,30.0833L 46.8512,30.0833C 44.6768,27.6539 41.517,26.125 38,26.125C 31.9785,26.125 27.0037,30.6068 26.2296,36.4167L 20.6543,36.4167C 21.4543,27.5397 28.9148,20.5833 38,20.5833 Z M 38,49.875C 44.0215,49.875 48.9963,45.3932 49.7703,39.5833L 55.3457,39.5833C 54.5457,48.4603 47.0852,55.4167 38,55.4167C 33.0092,55.4167 28.5088,53.3175 25.3333,49.954L 25.3333,58.5833L 20.5833,53.8333L 20.5833,41.1667L 33.25,41.1667L 38,45.9167L 29.1487,45.9167C 31.3231,48.3461 34.483,49.875 38,49.875 Z </Geometry>
        <Geometry x:Key="cardIcon">F1 M 23.75,22.1667L 52.25,22.1667C 55.7478,22.1667 58.5833,25.0022 58.5833,28.5L 58.5833,47.5C 58.5833,50.9978 55.7478,53.8333 52.25,53.8333L 23.75,53.8333C 20.2522,53.8333 17.4167,50.9978 17.4167,47.5L 17.4167,28.5C 17.4167,25.0022 20.2522,22.1667 23.75,22.1667 Z M 57,42.75L 19,42.75L 19,45.9167C 19,47.0702 19.3084,48.1518 19.8473,49.0833L 56.1527,49.0833C 56.6916,48.1518 57,47.0702 57,45.9167L 57,42.75 Z M 20.5833,25.3333L 20.5833,31.6667L 26.9167,31.6667L 26.9167,25.3333L 20.5833,25.3333 Z </Geometry>
        <Geometry x:Key="infoIcon">F1 M 31.6666,30.0834L 42.7499,30.0834L 42.7499,33.2501L 42.7499,52.2501L 45.9165,52.2501L 45.9165,57.0001L 31.6666,57.0001L 31.6666,52.2501L 34.8332,52.2501L 34.8332,34.8335L 31.6666,34.8335L 31.6666,30.0834 Z M 38.7917,19C 40.9778,19 42.75,20.7722 42.75,22.9583C 42.75,25.1445 40.9778,26.9167 38.7917,26.9167C 36.6055,26.9167 34.8333,25.1445 34.8333,22.9583C 34.8333,20.7722 36.6055,19 38.7917,19 Z </Geometry>

        <Style TargetType="{x:Type TextBlock}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type PasswordBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
            <Setter Property="Width" Value="90"/>
        </Style>
        <Style TargetType="{x:Type TextBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type Button}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type ComboBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type CheckBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>

    </Window.Resources>

    <Grid>
        <Grid Grid.Row="1" Name="grdChangePin" Visibility="Collapsed" Width="380" Margin="10,10,10,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="120"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="8"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Change PIN" FontSize="16"/>
            <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

            <TextBlock Grid.Column="0" Grid.Row="2" Text="Current PIN"/>
            <PasswordBox Grid.Column="2" Grid.Row="2" Name="pwdChangePinPin" HorizontalAlignment="Left"/>

            <TextBlock Grid.Column="0" Grid.Row="3" Text="New PIN"/>
            <PasswordBox Grid.Column="2" Grid.Row="3" Name="pwdChangePinPin1" HorizontalAlignment="Left"/>

            <TextBlock Grid.Column="0" Grid.Row="4" Text="New PIN (Again)"/>
            <PasswordBox Grid.Column="2" Grid.Row="4" Name="pwdChangePinPin2" HorizontalAlignment="Left"/>

            <Button Grid.Column="2" Grid.Row="5" Name="btnChangePin" Content="Ok" Width="90" HorizontalAlignment="Right"/>
        </Grid>

        <Grid Grid.Row="1" Name="grdChangePuk" Visibility="Collapsed" Width="380" Margin="10,10,10,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="120"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="8"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Change PUK" FontSize="16"/>
            <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

            <TextBlock Grid.Column="0" Grid.Row="2" Text="Current PUK"/>
            <PasswordBox Grid.Column="2" Grid.Row="2" Name="pwdChangePukPuk" HorizontalAlignment="Left"/>

            <TextBlock Grid.Column="0" Grid.Row="3" Text="New PUK"/>
            <PasswordBox Grid.Column="2" Grid.Row="3" Name="pwdChangePukPuk1" HorizontalAlignment="Left"/>

            <TextBlock Grid.Column="0" Grid.Row="4" Text="New PUK (Again)"/>
            <PasswordBox Grid.Column="2" Grid.Row="4" Name="pwdChangePukPuk2" HorizontalAlignment="Left"/>

            <Button Grid.Column="2" Grid.Row="5" Name="btnChangePuk" Content="Ok" Width="90" HorizontalAlignment="Right"/>
        </Grid>

        <Grid Grid.Row="1" Name="grdUnblockPin" Visibility="Collapsed" Width="380" Margin="10,10,10,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="120"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="8"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Unblock PIN" FontSize="16"/>
            <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

            <TextBlock Grid.Column="0" Grid.Row="2" Text="Current PUK"/>
            <PasswordBox Grid.Column="2" Grid.Row="2" Name="pwdUnblockPinPuk" HorizontalAlignment="Left"/>

            <TextBlock Grid.Column="0" Grid.Row="3" Text="New PIN"/>
            <PasswordBox Grid.Column="2" Grid.Row="3" Name="pwdUnblockPinPin1" HorizontalAlignment="Left"/>

            <TextBlock Grid.Column="0" Grid.Row="4" Text="New PIN (Again)"/>
            <PasswordBox Grid.Column="2" Grid.Row="4" Name="pwdUnblockPinPin2" HorizontalAlignment="Left"/>

            <Button Grid.Column="2" Grid.Row="5" Name="btnUnblockPin" Content="Ok" Width="90" HorizontalAlignment="Right"/>
        </Grid>

         <Grid Grid.Row="1" Name="grdResetPiv" Visibility="Collapsed" Width="380" Margin="10,10,10,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="120"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="8"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Reset PIV" FontSize="16"/>
            <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

            <Button Grid.Column="2" Grid.Row="5" Name="btnResetPiv" Content="Ok" Width="90" HorizontalAlignment="Right"/>
        </Grid>

    </Grid>


</Window>

"@
[xml]$xaml_MainWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window"
    Title="" Height="600" Width="900" >

 <Window.Resources>
        <BooleanToVisibilityConverter x:Key="VisCon"/>

        <SolidColorBrush x:Key="iconColor">#336699</SolidColorBrush>
        <!-- Material Design Icons -->
        <Geometry x:Key="searchIcon">M15.5,12C18,12 20,14 20,16.5C20,17.38 19.75,18.21 19.31,18.9L22.39,22L21,23.39L17.88,20.32C17.19,20.75 16.37,21 15.5,21C13,21 11,19 11,16.5C11,14 13,12 15.5,12M15.5,14A2.5,2.5 0 0,0 13,16.5A2.5,2.5 0 0,0 15.5,19A2.5,2.5 0 0,0 18,16.5A2.5,2.5 0 0,0 15.5,14M10,4A4,4 0 0,1 14,8C14,8.91 13.69,9.75 13.18,10.43C12.32,10.75 11.55,11.26 10.91,11.9L10,12A4,4 0 0,1 6,8A4,4 0 0,1 10,4M2,20V18C2,15.88 5.31,14.14 9.5,14C9.18,14.78 9,15.62 9,16.5C9,17.79 9.38,19 10,20H2Z</Geometry>
        <Geometry x:Key="uploadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M16 17H14V13H11L15 9L19 13H16Z</Geometry>
        <Geometry x:Key="downloadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M14 9H16V13H19L15 17L11 13H14Z</Geometry>
        <Geometry x:Key="certificateIcon">M13 21L15 20L17 21V14H13M17 9V7L15 8L13 7V9L11 10L13 11V13L15 12L17 13V11L19 10M20 3H4A2 2 0 0 0 2 5V15A2 2 0 0 0 4 17H11V15H4V5H20V15H19V17H20A2 2 0 0 0 22 15V5A2 2 0 0 0 20 3M11 8H5V6H11M9 11H5V9H9M11 14H5V12H11Z</Geometry>
        <Geometry x:Key="requestIcon">M20 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H13.09A5.47 5.47 0 0 1 13 19A6 6 0 0 1 19 13A5.88 5.88 0 0 1 22 13.81V6A2 2 0 0 0 20 4M20 11H4V8H20M20 15V18H23V20H20V23H18V20H15V18H18V15Z</Geometry>
        <Geometry x:Key="requestIcon2">M21,18H24V20H21V23H19V20H16V18H19V15H21V18M19,8V6H3V8H19M19,12H3V18H14V20H3C1.89,20 1,19.1 1,18V6C1,4.89 1.89,4 3,4H19A2,2 0 0,1 21,6V13H19V12Z</Geometry>

        <Geometry x:Key="retrieveIcon">M20 4H4C2.9 4 2 4.89 2 6V18C2 19.11 2.9 20 4 20H11.68C11.57 19.5 11.5 19 11.5 18.5C11.5 14.91 14.41 12 18 12C19.5 12 20.9 12.53 22 13.4V6C22 4.89 21.11 4 20 4M20 11H4V8H20V11M20.83 15.67L22 14.5V18.5H18L19.77 16.73C19.32 16.28 18.69 16 18 16C16.62 16 15.5 17.12 15.5 18.5S16.62 21 18 21C18.82 21 19.54 20.61 20 20H21.71C21.12 21.47 19.68 22.5 18 22.5C15.79 22.5 14 20.71 14 18.5S15.79 14.5 18 14.5C19.11 14.5 20.11 14.95 20.83 15.67Z</Geometry>
        <Geometry x:Key="retrieveIcon2">M20 4H4C2.89 4 2 4.89 2 6V18C2 19.11 2.9 20 4 20H11.68C11.57 19.5 11.5 19 11.5 18.5C11.5 18.33 11.5 18.17 11.53 18H4V12H20V12.32C20.74 12.56 21.41 12.93 22 13.4V6C22 4.89 21.1 4 20 4M20 8H4V6H20V8M20.83 15.67L22 14.5V18.5H18L19.77 16.73C19.32 16.28 18.69 16 18 16C16.62 16 15.5 17.12 15.5 18.5S16.62 21 18 21C18.82 21 19.54 20.61 20 20H21.71C21.12 21.47 19.68 22.5 18 22.5C15.79 22.5 14 20.71 14 18.5S15.79 14.5 18 14.5C19.11 14.5 20.11 14.95 20.83 15.67Z</Geometry>

        <Geometry x:Key="requestToFileIcon">M11 16A1 1 0 1 1 10 15A1 1 0 0 1 11 16M20 8V20A2 2 0 0 1 18 22H6A2 2 0 0 1 4 20V4A2 2 0 0 1 6 2H14M17 15H12.83A3 3 0 1 0 12.83 17H14V19H16V17H17M18.5 9L13 3.5V9Z</Geometry>
        <Geometry x:Key="requestToFileIcon2">M14 2H6A2 2 0 0 0 4 4V20A2 2 0 0 0 6 22H18A2 2 0 0 0 20 20V8L14 2M18 20H6V4H13V9H18M12.83 15A3 3 0 1 0 12.83 17H14V19H16V17H17V15M10 17A1 1 0 1 1 11 16A1 1 0 0 1 10 17Z</Geometry>


        <!-- ModernUI Icons Icons -->
        <Geometry x:Key="consoleIcon">F1 M 17,20L 59,20L 59,56L 17,56L 17,20 Z M 20,26L 20,53L 56,53L 56,26L 20,26 Z M 23.75,31L 28.5,31L 33.25,37.5L 28.5,44L 23.75,44L 28.5,37.5L 23.75,31 Z </Geometry>
        <Geometry x:Key="backIcon">F1 M 57,42L 57,34L 32.25,34L 42.25,24L 31.75,24L 17.75,38L 31.75,52L 42.25,52L 32.25,42L 57,42 Z </Geometry>
        <Geometry x:Key="reloadIcon">F1 M 38,20.5833C 42.9908,20.5833 47.4912,22.6825 50.6667,26.046L 50.6667,17.4167L 55.4166,22.1667L 55.4167,34.8333L 42.75,34.8333L 38,30.0833L 46.8512,30.0833C 44.6768,27.6539 41.517,26.125 38,26.125C 31.9785,26.125 27.0037,30.6068 26.2296,36.4167L 20.6543,36.4167C 21.4543,27.5397 28.9148,20.5833 38,20.5833 Z M 38,49.875C 44.0215,49.875 48.9963,45.3932 49.7703,39.5833L 55.3457,39.5833C 54.5457,48.4603 47.0852,55.4167 38,55.4167C 33.0092,55.4167 28.5088,53.3175 25.3333,49.954L 25.3333,58.5833L 20.5833,53.8333L 20.5833,41.1667L 33.25,41.1667L 38,45.9167L 29.1487,45.9167C 31.3231,48.3461 34.483,49.875 38,49.875 Z </Geometry>
        <Geometry x:Key="cardIcon">F1 M 23.75,22.1667L 52.25,22.1667C 55.7478,22.1667 58.5833,25.0022 58.5833,28.5L 58.5833,47.5C 58.5833,50.9978 55.7478,53.8333 52.25,53.8333L 23.75,53.8333C 20.2522,53.8333 17.4167,50.9978 17.4167,47.5L 17.4167,28.5C 17.4167,25.0022 20.2522,22.1667 23.75,22.1667 Z M 57,42.75L 19,42.75L 19,45.9167C 19,47.0702 19.3084,48.1518 19.8473,49.0833L 56.1527,49.0833C 56.6916,48.1518 57,47.0702 57,45.9167L 57,42.75 Z M 20.5833,25.3333L 20.5833,31.6667L 26.9167,31.6667L 26.9167,25.3333L 20.5833,25.3333 Z </Geometry>
        <Geometry x:Key="infoIcon">F1 M 31.6666,30.0834L 42.7499,30.0834L 42.7499,33.2501L 42.7499,52.2501L 45.9165,52.2501L 45.9165,57.0001L 31.6666,57.0001L 31.6666,52.2501L 34.8332,52.2501L 34.8332,34.8335L 31.6666,34.8335L 31.6666,30.0834 Z M 38.7917,19C 40.9778,19 42.75,20.7722 42.75,22.9583C 42.75,25.1445 40.9778,26.9167 38.7917,26.9167C 36.6055,26.9167 34.8333,25.1445 34.8333,22.9583C 34.8333,20.7722 36.6055,19 38.7917,19 Z </Geometry>

        <Style TargetType="{x:Type TextBlock}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type PasswordBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
            <Setter Property="Width" Value="90"/>
        </Style>
        <Style TargetType="{x:Type TextBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type Button}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type ComboBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type CheckBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>

    </Window.Resources>
    <Grid>
        <Grid.Style>
            <Style TargetType="Grid">
                <Style.Triggers>
                    <DataTrigger Binding="{Binding ElementName=ProgressBar, Path=IsIndeterminate}" Value="True">
                        <Setter Property="IsEnabled" Value="False"/>
                    </DataTrigger>
                    <DataTrigger Binding="{Binding ElementName=ProgressBar, Path=IsIndeterminate}" Value="False">
                        <Setter Property="IsEnabled" Value="True"/>
                    </DataTrigger>
                </Style.Triggers>
            </Style>
        </Grid.Style>
    <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="250"/>
    </Grid.ColumnDefinitions>
    <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="3*"/>
        <RowDefinition Height="7*"/>
        <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

        <TextBlock Text="Enrollment Station" Margin="10,0,0,0" Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="2" FontSize="18"/>

        <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="2,0,2,2">
            <Button Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" ToolTip="App Info" Name="btnShowAppInfo" Background="Transparent" Margin="2,0,2,0">
                <Path Margin="2" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource infoIcon}"/>
            </Button>

            <ToggleButton Grid.Row="0" Grid.Column="1" Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" ToolTip="Show/Hide console" IsChecked="False" Name="btnShowConsole" Background="Transparent" Margin="2,0,2,0">
                <Path Margin="2" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource consoleIcon}"/>
            </ToggleButton>
        </StackPanel>

        <GroupBox Grid.Column="0" Grid.Row="1" Margin="10">
            <GroupBox.Header>
                <TextBlock Text="Tokens/Cards" FontWeight="Bold"/>
            </GroupBox.Header>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <ListView Name="lstReaders" Grid.Column="0">
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="Reader">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="Auto"/>
                                                    <ColumnDefinition Width="Auto"/>
                                                </Grid.ColumnDefinitions>
                                                <Border Grid.Column="0" Grid.RowSpan="2" Margin="0,0,2,0" VerticalAlignment="Center" Height="25" Width="25" Background="Transparent" HorizontalAlignment="Center">
                                                    <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource cardIcon}"/>
                                                </Border>
                                                <TextBlock Grid.Column="1" FontSize="12" VerticalAlignment="Center" TextAlignment="Center" Text="{Binding Reader}"/>
                                            </Grid>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                                <GridViewColumn Header="Card">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock FontSize="12">
                                                <TextBlock.Style>
                                                    <Style TargetType="TextBlock">
                                                        <Style.Triggers>
                                                            <DataTrigger Binding="{Binding CardOk, FallbackValue=False}" Value="False">
                                                                <Setter Property="Foreground" Value="Red"/>
                                                                <Setter Property="Text" Value="-- Incompatible --"/>
                                                            </DataTrigger>
                                                            <DataTrigger Binding="{Binding CardOk, FallbackValue=False}" Value="True">
                                                                <Setter Property="Text" Value="{Binding DeviceType}"/>
                                                            </DataTrigger>
                                                        </Style.Triggers>
                                                    </Style>
                                                </TextBlock.Style>
                                            </TextBlock>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                                <GridViewColumn Header="Serial">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding SerialNumber}" VerticalAlignment="Center"/>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                                <GridViewColumn Header="9a">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <Border Grid.Column="0" VerticalAlignment="Center" Height="20" Width="20" Background="Transparent" HorizontalAlignment="Center">
                                                <Path Margin="1" Stretch="Uniform" Data="{StaticResource certificateIcon}" ToolTip="Slot 9a: PIV Authentication">
                                                    <Path.Style>
                                                        <Style TargetType="Path">
                                                            <Style.Triggers>
                                                                <DataTrigger Binding="{Binding slot9a.InUse, FallbackValue=False}" Value="False">
                                                                    <Setter Property="Fill" Value="LightGray"/>
                                                                </DataTrigger>
                                                                <DataTrigger Binding="{Binding slot9a.InUse, FallbackValue=False}" Value="True">
                                                                    <Setter Property="Fill" Value="{StaticResource iconColor}"/>
                                                                </DataTrigger>
                                                            </Style.Triggers>
                                                        </Style>
                                                    </Path.Style>
                                                </Path>
                                            </Border>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                                <GridViewColumn Header="9c">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <Border Grid.Column="0" VerticalAlignment="Center" Height="20" Width="20" Background="Transparent" HorizontalAlignment="Center">
                                                <Path Margin="1" Stretch="Uniform" Data="{StaticResource certificateIcon}" ToolTip="Slot 9c: Digital Signature">
                                                    <Path.Style>
                                                        <Style TargetType="Path">
                                                            <Style.Triggers>
                                                                <DataTrigger Binding="{Binding slot9c.InUse, FallbackValue=False}" Value="False">
                                                                    <Setter Property="Fill" Value="LightGray"/>
                                                                </DataTrigger>
                                                                <DataTrigger Binding="{Binding slot9c.InUse, FallbackValue=False}" Value="True">
                                                                    <Setter Property="Fill" Value="{StaticResource iconColor}"/>
                                                                </DataTrigger>
                                                            </Style.Triggers>
                                                        </Style>
                                                    </Path.Style>
                                                </Path>
                                            </Border>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                            </GridView>
                        </ListView.View>
                    </ListView>
                    <Button Grid.Column="1" Grid.Row="0" Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" Name="ReloadCardsButton" ToolTip="Reload cards" Background="Transparent" Margin="3,0,0,0">
                        <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource reloadIcon}"/>
                    </Button>
                </Grid>
            </GroupBox>


        <GroupBox Grid.Column="0" Grid.Row="2" Margin="10" Visibility="{Binding ElementName=lstReaders,Path=SelectedItem.CardOk, FallbackValue=Collapsed, Converter={StaticResource VisCon}}">
        <GroupBox.Header>
            <TextBlock Text="Selected Card" FontWeight="Bold"/>
        </GroupBox.Header>

            <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" CanContentScroll="True">
                <StackPanel>
                    <GroupBox>
                        <GroupBox.Header>
                            <StackPanel Orientation="Horizontal">
                                <Border Grid.Column="0" Grid.RowSpan="2" Margin="0,0,2,0" VerticalAlignment="Center" Height="25" Width="25" Background="Transparent" HorizontalAlignment="Center">
                                    <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource cardIcon}"/>
                                </Border>
                                <TextBlock Text="Card info" Margin="2,0,0,0" VerticalAlignment="Center" FontWeight="Bold"/>
                            </StackPanel>
                        </GroupBox.Header>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="8"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="16"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="8"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Serial number"/>
                            <TextBox Grid.Row="0" Grid.Column="2" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.SerialNumber}"/>

                            <TextBlock Grid.Row="1" Grid.Column="0" Text="PIV Version"/>
                            <TextBox Grid.Row="1" Grid.Column="2" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.PIV_Version}"/>

                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Firmware Version"/>
                            <TextBox Grid.Row="2" Grid.Column="2" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.FirmwareVersion}"/>

                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Modes"/>
                            <TextBox Grid.Row="3" Grid.Column="2" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.Modes}"/>

                            <TextBlock Grid.Row="4" Grid.Column="0" Text="PIN Retries"/>
                            <TextBox Grid.Row="4" Grid.Column="2" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.PINRetries}"/>

                            <TextBlock Grid.Row="0" Grid.Column="4" Text="OTP"/>
                            <TextBox Grid.Row="0" Grid.Column="6" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_OTP}"/>

                            <TextBlock Grid.Row="1" Grid.Column="4" Text="FIDO U2F"/>
                            <TextBox Grid.Row="1" Grid.Column="6" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_FIDOU2F}"/>

                            <TextBlock Grid.Row="2" Grid.Column="4" Text="FIDO2"/>
                            <TextBox Grid.Row="2" Grid.Column="6" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_FIDO2}"/>

                            <TextBlock Grid.Row="3" Grid.Column="4" Text="Open PGP"/>
                            <TextBox Grid.Row="3" Grid.Column="6" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_OpenPGP}"/>

                            <TextBlock Grid.Row="4" Grid.Column="4" Text="PIV"/>
                            <TextBox Grid.Row="4" Grid.Column="6" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_PIV}"/>

                            <TextBlock Grid.Row="5" Grid.Column="4" Text="OATH"/>
                            <TextBox Grid.Row="5" Grid.Column="6" IsReadOnly="True" BorderThickness="0" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_OATH}"/>

                        </Grid>
                    </GroupBox>

                    <GroupBox>
                        <GroupBox.Header>
                            <StackPanel Orientation="Horizontal">
                                <Border Grid.Column="0" VerticalAlignment="Center" Height="25" Width="25" Background="Transparent" HorizontalAlignment="Center">
                                    <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource certificateIcon}"/>
                                </Border>
                                <TextBlock Text="Slot 9a: PIV Authentication" Margin="2,0,0,0" VerticalAlignment="Center" FontWeight="Bold"/>
                            </StackPanel>
                        </GroupBox.Header>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="8"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Algorithm"/>
                            <TextBox Grid.Row="0" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.Algorithm}"/>

                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Subject"/>
                            <TextBox Grid.Row="1" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.SubjectDN}"/>

                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Issuer"/>
                            <TextBox Grid.Row="2" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.IssuerDN}"/>

                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Not before"/>
                            <TextBox Grid.Row="3" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.Not_before}"/>

                            <TextBlock Grid.Row="4" Grid.Column="0" Text="Not after"/>
                            <TextBox Grid.Row="4" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.Not_after}"/>

                            <TextBlock Grid.Row="5" Grid.Column="0" Text="Fingerprint"/>
                            <TextBox Grid.Row="5" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.Fingerprint}"/>

                            <TextBlock Grid.Row="6" Grid.Column="0" Text="Serial"/>
                            <TextBox Grid.Row="6" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9a.Serial}"/>
                        </Grid>
                    </GroupBox>
                    <GroupBox>
                        <GroupBox.Header>
                            <StackPanel Orientation="Horizontal">
                                <Border Grid.Column="0" VerticalAlignment="Center" Height="25" Width="25" Background="Transparent" HorizontalAlignment="Center">
                                    <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource certificateIcon}"/>
                                </Border>
                                <TextBlock Text="Slot 9c: Digital Signature" Margin="2,0,0,0" VerticalAlignment="Center" FontWeight="Bold"/>
                            </StackPanel>
                        </GroupBox.Header>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="8"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Algorithm"/>
                            <TextBox Grid.Row="0" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.Algorithm}"/>

                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Subject"/>
                            <TextBox Grid.Row="1" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.SubjectDN}"/>

                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Issuer"/>
                            <TextBox Grid.Row="2" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.IssuerDN}"/>

                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Not before"/>
                            <TextBox Grid.Row="3" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.Not_before}"/>

                            <TextBlock Grid.Row="4" Grid.Column="0" Text="Not after"/>
                            <TextBox Grid.Row="4" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.Not_after}"/>

                            <TextBlock Grid.Row="5" Grid.Column="0" Text="Fingerprint"/>
                            <TextBox Grid.Row="5" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.Fingerprint}"/>

                            <TextBlock Grid.Row="6" Grid.Column="0" Text="Serial"/>
                            <TextBox Grid.Row="6" Grid.Column="2" IsReadOnly="True" BorderThickness="0" HorizontalAlignment="Left" Text="{Binding ElementName=lstReaders, Path=SelectedItem.slot9c.Serial}"/>
                        </Grid>
                    </GroupBox>
                </StackPanel>
            </ScrollViewer>
        </GroupBox>


        <GroupBox Grid.Row="1" Grid.RowSpan="2" Grid.Column="1" Margin="10">
        <GroupBox.Header>
            <TextBlock Text="Card Actions" FontWeight="Bold"/>
        </GroupBox.Header>
            <Grid>
                <StackPanel Orientation="Vertical">
                    <Button Name="btnShowEnrollWindow" Margin="4">
                        <StackPanel Orientation="Horizontal" Width="150">
                            <Path Height="16" Width="16" Margin="0,0,4,0" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource requestIcon}"/>
                            <TextBlock Text="Request to card"/>
                        </StackPanel>
                    </Button>
                    <Button Name="btnShowRequestToFileWindow" Margin="4">
                        <StackPanel Orientation="Horizontal" Width="150">
                            <Path Height="16" Width="16" Margin="0,0,4,0" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource requestToFileIcon}"/>
                            <TextBlock Text="Request to file"/>
                        </StackPanel>
                    </Button>
                    <Button Name="btnShowRequestPendingWindow" Margin="4">
                        <StackPanel Orientation="Horizontal" Width="150">
                            <Path Height="16" Width="16" Margin="0,0,4,0" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource retrieveIcon}"/>
                            <TextBlock Text="Retrieve Pending"/>
                        </StackPanel>
                    </Button>
                </StackPanel>

                <StackPanel Orientation="Vertical" VerticalAlignment="Bottom">
                    <StackPanel Orientation="Horizontal">
                        <Button Content="Change PIN" Width="100" Margin="4" Name="btnChangePin"/>
                        <Button Content="Change PUK" Width="100" Margin="4" Name="btnChangePuk"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal">
                        <Button Content="Reset PIV" Width="100" Margin="4" Name="btnResetPiv"/>
                        <Button Content="Unblock PIN" Width="100" Margin="4" Name="btnUnblockPin"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal">
                        <Button Content="Modes" Width="100" Margin="4" Name="btnModes"/>
                    </StackPanel>
                </StackPanel>
            </Grid>
        </GroupBox>

        <Grid Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="2" Margin="10,0,10,10">
            <TextBlock HorizontalAlignment="Center" Name="txtCA" Margin="10,2,10,0" TextAlignment="Center" VerticalAlignment="Center"/>
            <ProgressBar IsIndeterminate="True" Name="ProgressBar" Height="25" VerticalAlignment="Top" Visibility="{Binding ElementName=ProgressBar,Path=IsIndeterminate, Converter={StaticResource VisCon}}"/>
            <TextBlock HorizontalAlignment="Center" Name="txtStatus" Margin="10,2,10,0" TextAlignment="Center" VerticalAlignment="Center" Visibility="{Binding ElementName=ProgressBar,Path=IsIndeterminate, Converter={StaticResource VisCon}}"/>
        </Grid>
    </Grid>

</Window>

"@
[xml]$xaml_EnrollWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="EnrollWindow"
    SizeToContent="WidthAndHeight"
    Title="" MinHeight="325" MinWidth="425">

    <Window.Resources>
        <BooleanToVisibilityConverter x:Key="VisCon"/>

        <SolidColorBrush x:Key="iconColor">#336699</SolidColorBrush>
        <!-- Material Design Icons -->
        <Geometry x:Key="searchIcon">M15.5,12C18,12 20,14 20,16.5C20,17.38 19.75,18.21 19.31,18.9L22.39,22L21,23.39L17.88,20.32C17.19,20.75 16.37,21 15.5,21C13,21 11,19 11,16.5C11,14 13,12 15.5,12M15.5,14A2.5,2.5 0 0,0 13,16.5A2.5,2.5 0 0,0 15.5,19A2.5,2.5 0 0,0 18,16.5A2.5,2.5 0 0,0 15.5,14M10,4A4,4 0 0,1 14,8C14,8.91 13.69,9.75 13.18,10.43C12.32,10.75 11.55,11.26 10.91,11.9L10,12A4,4 0 0,1 6,8A4,4 0 0,1 10,4M2,20V18C2,15.88 5.31,14.14 9.5,14C9.18,14.78 9,15.62 9,16.5C9,17.79 9.38,19 10,20H2Z</Geometry>
        <Geometry x:Key="uploadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M16 17H14V13H11L15 9L19 13H16Z</Geometry>
        <Geometry x:Key="downloadIcon">M20 18H4V8H20M20 6H12L10 4H4A2 2 0 0 0 2 6V18A2 2 0 0 0 4 20H20A2 2 0 0 0 22 18V8A2 2 0 0 0 20 6M14 9H16V13H19L15 17L11 13H14Z</Geometry>

        <!-- ModernUI Icons Icons -->
        <Geometry x:Key="consoleIcon">F1 M 17,20L 59,20L 59,56L 17,56L 17,20 Z M 20,26L 20,53L 56,53L 56,26L 20,26 Z M 23.75,31L 28.5,31L 33.25,37.5L 28.5,44L 23.75,44L 28.5,37.5L 23.75,31 Z </Geometry>
        <Geometry x:Key="backIcon">F1 M 57,42L 57,34L 32.25,34L 42.25,24L 31.75,24L 17.75,38L 31.75,52L 42.25,52L 32.25,42L 57,42 Z </Geometry>
        <Geometry x:Key="reloadIcon">F1 M 38,20.5833C 42.9908,20.5833 47.4912,22.6825 50.6667,26.046L 50.6667,17.4167L 55.4166,22.1667L 55.4167,34.8333L 42.75,34.8333L 38,30.0833L 46.8512,30.0833C 44.6768,27.6539 41.517,26.125 38,26.125C 31.9785,26.125 27.0037,30.6068 26.2296,36.4167L 20.6543,36.4167C 21.4543,27.5397 28.9148,20.5833 38,20.5833 Z M 38,49.875C 44.0215,49.875 48.9963,45.3932 49.7703,39.5833L 55.3457,39.5833C 54.5457,48.4603 47.0852,55.4167 38,55.4167C 33.0092,55.4167 28.5088,53.3175 25.3333,49.954L 25.3333,58.5833L 20.5833,53.8333L 20.5833,41.1667L 33.25,41.1667L 38,45.9167L 29.1487,45.9167C 31.3231,48.3461 34.483,49.875 38,49.875 Z </Geometry>
        <Geometry x:Key="cardIcon">F1 M 23.75,22.1667L 52.25,22.1667C 55.7478,22.1667 58.5833,25.0022 58.5833,28.5L 58.5833,47.5C 58.5833,50.9978 55.7478,53.8333 52.25,53.8333L 23.75,53.8333C 20.2522,53.8333 17.4167,50.9978 17.4167,47.5L 17.4167,28.5C 17.4167,25.0022 20.2522,22.1667 23.75,22.1667 Z M 57,42.75L 19,42.75L 19,45.9167C 19,47.0702 19.3084,48.1518 19.8473,49.0833L 56.1527,49.0833C 56.6916,48.1518 57,47.0702 57,45.9167L 57,42.75 Z M 20.5833,25.3333L 20.5833,31.6667L 26.9167,31.6667L 26.9167,25.3333L 20.5833,25.3333 Z </Geometry>
        <Geometry x:Key="infoIcon">F1 M 31.6666,30.0834L 42.7499,30.0834L 42.7499,33.2501L 42.7499,52.2501L 45.9165,52.2501L 45.9165,57.0001L 31.6666,57.0001L 31.6666,52.2501L 34.8332,52.2501L 34.8332,34.8335L 31.6666,34.8335L 31.6666,30.0834 Z M 38.7917,19C 40.9778,19 42.75,20.7722 42.75,22.9583C 42.75,25.1445 40.9778,26.9167 38.7917,26.9167C 36.6055,26.9167 34.8333,25.1445 34.8333,22.9583C 34.8333,20.7722 36.6055,19 38.7917,19 Z </Geometry>

        <Style TargetType="{x:Type TextBlock}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type PasswordBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
            <Setter Property="Width" Value="90"/>
        </Style>
        <Style TargetType="{x:Type TextBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type Button}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type ComboBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
        <Style TargetType="{x:Type CheckBox}">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,2,0,2"/>
        </Style>
    </Window.Resources>

    <Grid Name="EnrollGrid" Grid.Row="1" Width="380" Visibility="{Binding ElementName=ShowEnrollGridButton,Path=IsChecked, Converter={StaticResource VisCon}}" Margin="10,10,10,0">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="120"/>
            <ColumnDefinition Width="10"/>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Request certificate" FontSize="16"/>
        <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

        <TextBlock Grid.Column="0" Grid.Row="2" Text="Enrollment template"/>
        <ComboBox Grid.Column="2" Grid.Row="2" SelectedIndex="0" Name="cmbRequestType">
            <ComboBoxItem Content="Wipe and request" Name="cmbiNewCard" Tag="newcard"/>
            <ComboBoxItem Content="Advanced request" Name="cmbiAdvRequest" Tag="advrequest"/>
        </ComboBox>
        <TextBlock Grid.Column="0" Grid.Row="3" Text="Certificate Template"/>
        <ComboBox Grid.Column="2" Grid.Row="3" Name="cmbTemplates" DisplayMemberPath="DisplayName"/>

        <TextBlock Grid.Column="0" Grid.Row="5" Text="Signing certificate" FontSize="12" Name="EnrollSigningCertTextBlock">
            <TextBlock.Style>
                <Style TargetType="TextBlock">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding ElementName=cmbTemplates, Path=SelectedItem.RequiredSignatures, FallbackValue=0}" Value="0">
                            <Setter Property="Visibility" Value="Collapsed"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </TextBlock.Style>
        </TextBlock>
        <ComboBox Grid.Column="2" Grid.Row="5" Name="cmbSigningCerts" DisplayMemberPath="Description" Visibility="{Binding ElementName=EnrollSigningCertTextBlock, Path=Visibility}"/>

        <TextBlock Grid.Column="0" Grid.Row="6" Text="Subject" Visibility="{Binding ElementName=EnrollSigningCertTextBlock, Path=Visibility}"/>
        <Grid Grid.Column="2" Grid.Row="6" Visibility="{Binding ElementName=EnrollSigningCertTextBlock, Path=Visibility}">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Grid.Column="0" Name="txtSubject" IsReadOnly="True" HorizontalAlignment="Stretch"/>
            <Button Grid.Column="1" Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" Name="btnShowFindUsersWindow" ToolTip="Find user" Background="Transparent" Margin="2,2,0,2">
                <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource searchIcon}"/>
            </Button>
        </Grid>

        <!-- Only Show if Advanced request -->
        <TextBlock Grid.Column="0" Grid.Row="7" Text="Reset PIV" Name="txtResetPiv" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>
        <CheckBox Grid.Column="2" Grid.Row="7" Name="chkReset" VerticalAlignment="Center" IsChecked="{Binding ElementName=cmbiNewCard, Path=IsSelected, Mode=OneWay}" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>

        <!-- Only Show if Advanced request -->
        <TextBlock Grid.Column="0" Grid.Row="8" Text="Set CCID only mode" Name="txtSetMode" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>
        <CheckBox Grid.Column="2" Grid.Row="8" Name="chkSetCCIDOnlyMode" VerticalAlignment="Center" IsChecked="{Binding ElementName=cmbiNewCard, Path=IsSelected, Mode=OneWay}" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>

        <!-- Only Show if Advanced request -->
        <TextBlock Grid.Column="0" Grid.Row="9" Text="Target Slot" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>
        <ComboBox Grid.Column="2" Grid.Row="9" HorizontalAlignment="Stretch" Name="cmbSlot" SelectedIndex="0" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}">
            <ComboBoxItem Content="Slot 9a: PIV Authentication" Tag="9a"/>
            <ComboBoxItem Content="Slot 9c: Digital Signature" Tag="9c"/>
            <ComboBoxItem Content="Slot 9d: Key Management" Tag="9d"/>
            <ComboBoxItem Content="Slot 9e: Card Authentication" Tag="9e"/>
            <ComboBoxItem Content="Slot f9: Attestation" Tag="f9"/>
        </ComboBox>

        <!-- Only Show if Advanced request -->
        <TextBlock Grid.Column="0" Grid.Row="10" Text="Key Algorithm" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>
        <ComboBox Grid.Column="2" Grid.Row="10"  HorizontalAlignment="Stretch" SelectedIndex="2" Name="cmbKeyAlgo" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}">
            <ComboBoxItem Content="TDES" Tag="TDES"/>
            <ComboBoxItem Content="RSA1024" Tag="RSA1024"/>
            <ComboBoxItem Content="RSA2048" Tag="RSA2048"/>
            <ComboBoxItem Content="ECCP256" Tag="ECCP256"/>
            <ComboBoxItem Content="ECCP384" Tag="ECCP384"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="11" Text="Key Touch Policy" Name="txtTouchPolicy"/>
        <ComboBox Grid.Column="2" Grid.Row="11"  HorizontalAlignment="Stretch" SelectedIndex="2" Name="cmbKeyTouchPolicy">
            <ComboBoxItem Content="ALWAYS" Tag="ALWAYS"/>
            <ComboBoxItem Content="NEVER" Tag="NEVER"/>
            <ComboBoxItem Content="CACHED" Tag="CACHED"/>
        </ComboBox>

        <!-- Only Show if Advanced request -->
        <TextBlock Grid.Column="0" Grid.Row="12" Text="Key PIN Policy" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}"/>
        <ComboBox Grid.Column="2" Grid.Row="12"  HorizontalAlignment="Stretch" SelectedIndex="0" Name="cmbKeyPinPolicy" Visibility="{Binding ElementName=cmbiAdvRequest,Path=IsSelected, Converter={StaticResource VisCon}}">
            <ComboBoxItem Content="DEFAULT" Tag="DEFAULT"/>
            <ComboBoxItem Content="NEVER" Tag="NEVER"/>
            <ComboBoxItem Content="ONCE" Tag="ONCE"/>
            <ComboBoxItem Content="ALWAYS" Tag="ALWAYS"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="13" Text="Current PIN" Name="txtCurrentPin">
            <TextBlock.Style>
                <Style TargetType="TextBlock">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding ElementName=chkReset, Path=IsChecked}" Value="True">
                            <Setter Property="Visibility" Value="Collapsed"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </TextBlock.Style>
        </TextBlock>
        <PasswordBox Grid.Column="2" Grid.Row="13" Name="pwdCurrentPin" HorizontalAlignment="Left" Visibility="{Binding ElementName=txtCurrentPin, Path=Visibility}"/>

        <TextBlock Grid.Column="0" Grid.Row="14" Text="New PIN" Visibility="{Binding ElementName=chkReset,Path=IsChecked, Converter={StaticResource VisCon}}"/>
        <PasswordBox Grid.Column="2" Grid.Row="14" Name="pwdNewPin1" HorizontalAlignment="Left" Visibility="{Binding ElementName=chkReset,Path=IsChecked, Converter={StaticResource VisCon}}"/>

        <TextBlock Grid.Column="0" Grid.Row="15" Text="New PIN (Again)" Visibility="{Binding ElementName=chkReset,Path=IsChecked, Converter={StaticResource VisCon}}"/>
        <PasswordBox Grid.Column="2" Grid.Row="15" Name="pwdNewPin2" HorizontalAlignment="Left" Visibility="{Binding ElementName=chkReset,Path=IsChecked, Converter={StaticResource VisCon}}"/>

        <StackPanel Orientation="Horizontal" Grid.Column="2" HorizontalAlignment="Right" Grid.Row="16" Margin="0,10,0,0">
            <Button Name="btnEnroll" Content="Enroll" Width="90"/>
            <Button Name="btnCancel" Content="Cancel" Width="90" Margin="6,2,0,2"/>
        </StackPanel>
    </Grid>
</Window>

"@
#endregion
Show-MainWindow




#######################################################################
#                                                                     #
# Merged by user: todag                                               #
# On computer:    HV-CL01                                             #
# Date:           2021-02-16 23:02:36                                 #
# No code signing certificate found!                                  #
#                                                                     #
#######################################################################
