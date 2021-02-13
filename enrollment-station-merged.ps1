Set-StrictMode -Version 2.0
$appVersion = "0.1 - 2020-02-13"
$appAbout = @"
Enrollment Station v $($appVersion)

Copyright (C) 2021 github.com/todag

Icons from:
http://modernuiicons.com/
https://materialdesignicons.com/
"@

Write-Host ("::Loading enrollment-station v" + $appVersion)

#
# ---------------------- Script scope variables ----------------------
#
$script:ykman = "C:\Program Files\Yubico\YubiKey Manager\ykman.exe"
$script:certreq = "C:\Windows\system32\certreq.exe"
$script:workDir = "$($env:APPDATA)\ps-enrollment-station"
$script:hideSecrets = $true
$script:ShowVerboseOutput = $true
$script:ShowDebugOutput = $true
$script:ca = "DC01.AD.LOCAL\AD-DC01-CA"

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
If(!(Test-Path $script:workDir)) {
    New-Item -ItemType Directory -Force -Path $script:workDir | Out-Null
}

#region Functions
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
function Request-Certificate() {
    <#
    .SYNOPSIS
        Requests a certificate from the CA
    .PARAMETER CertTemplate
        The custom CertTemplate object to use for the request
    .PARAMETER CsrFile
        The csr file to use in the request
    .PARAMETER CertFile
        The file to save the certificate to
    .PARAMETER Id
        Id of pending request
    #>
    param(
        [Parameter(Mandatory=$true,  ParameterSetName="A")]  [PSCustomObject]$CertTemplate,
        [Parameter(Mandatory=$false, ParameterSetName="A")] [string]$CsrFile = "$($script:workDir)\pubkey.csr",
        [Parameter(Mandatory=$false, ParameterSetName="A")] [string]$CertFile = "$($script:workDir)\cert.crt",
        [Parameter(Mandatory=$false, ParameterSetName="B")] [string]$Id
    )
    if($Id) {
        $result = Execute -ExeFile $script:certreq -desc "Retrieving certificate id $Id from CA" -arguments "-config $script:ca -retrieve -f $id $($script:workDir)\cert.crt"
    } else {
        $result = Execute -ExeFile $script:certreq -desc "Requesting certificate from CA" -arguments "-config $script:ca -submit -f -attrib CertificateTemplate:$($certTemplate.Name) $CsrFile $CertFile"
    }

    if(($result.ExitCode -eq 0) -and ($result.stdout -like "*Certificate request is pending: Taken Under Submission*")) {
        $requestId = [regex]::Match($result.stdout, 'RequestId:\s"(.*)"').Groups[1].Value

        $r = [PSCustomObject]@{
                pending = $true
                id = $requestId
            }

        if ([string]::IsNullOrEmpty($requestId)) {
            throw " Unable to extract request id!"
        } else {
            Write-Log -LogString "Request is pending with id: $requestId" -Severity Notice
            return ,$r
        }
    } else {
        $r = [PSCustomObject]@{
                pending = $false
            }
        return ,$r
    }
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
        Signs a request with an enrollment agent certificate
    .PARAMETER SigningCertificateThumbprint
        Thumbprint of the signing certificate
    .PARAMETER Subject
        Subject of the request (ie. ad\username)
    .PARAMETER CertTemplate
        Custom certificate template object used for the inner request
    .PARAMETER CsrFile
        The csr file to sign
    #>
    param(
        [Parameter(Mandatory=$true)]  [string]$SigningCertificateThumbprint,
        [Parameter(Mandatory=$true)]  [string]$Subject,
        [Parameter(Mandatory=$true)]  [PSCustomObject]$CertTemplate,
        [Parameter(Mandatory=$false)]  [string]$CsrFile = "$($script:workDir)\pubkey.csr"
    )
    if($CertTemplate.RequiredSignatures -lt 1) {
        Write-Log -LogString "Template does not need Enrollment Agent signing" -Severity Notice
        return
    }

    Write-Log -LogString "Signing $CsrFile for subject $subject. Signing cert thumbprint: $SigningCertificateThumbprint" -Severity Debug
    $csrData = [string]::Empty
    foreach($line in (Get-Content -LiteralPath $CsrFile)) {
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
    $signerCertificate.Initialize(0,0,0xc,$SigningCertificateThumbprint)
    $cmcRequest.SignerCertificate = $signerCertificate
    Write-Log -LogString "Please provide the PIN for the signing certificate!" -Severity Notice
    $cmcRequest.Encode()
    #$strRequest = $cmcRequest.RawData($EncodingType.XCN_CRYPT_STRING_BASE64)
    Write-Log -LogString "CMC data:`n$($cmcRequest.RawData())" -Severity Debug
    Set-Content -Value $cmcRequest.RawData() -LiteralPath $CsrFile
    Write-Log -LogString "Signed CSR saved to $CsrFile"
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
        Start-Sleep -Milliseconds 50
        [System.Windows.Forms.Application]::DoEvents()
    }

    $MainWindow.ProgressBar.IsIndeterminate = $false
    $MainWindow.txtStatus.Text = ""

    Write-Log -LogString "Return code: ---$($syncHash.result.ExitCode)---" -Severity Debug

    if (-Not ([string]::IsNullOrEmpty($syncHash.result.stdout))) {
        Write-Log -LogString "Stdout: $($syncHash.result.stdout)" -Severity Debug
    }
    if (-Not ([string]::IsNullOrEmpty($syncHash.result.stderr))) {
        Write-Log -LogString "Stderr: $($syncHash.result.stderr)" -Severity Critical
    }

    if($syncHash.result.ExitCode -ne 0) {
        Write-Log -LogString "Executing $exeFile with arguments: $arguments failed with message: $($syncHash.result.stderr) `n $($syncHash.result.stdout)" -Severity Critical
        if(-not $NoThrow) {
            throw "Executing $exeFile with arguments: $arguments failed with message: $($syncHash.result.stderr) `n $($syncHash.result.stdout)"
        }
    }

    return ,$syncHash.result
}
function Show-AdvReqWindow(){
    param(
        [Parameter(Mandatory=$false)]  [PSCustomObject]$Card
    )

    #
    # Setup Window
    #
    $Win = @{}
    $Win.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_AdvReqWindow))
    $xaml_AdvReqWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
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

    $Win.btnEnroll.add_Click({
        if(([System.Windows.Forms.MessageBox]::Show("Are you sure you want to continue?","Warning",1,48)) -ne 'Ok') {
            return
        }

        if($win.cmbTemplates.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("No Template selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        }

        if((($win.cmbTemplates.SelectedItem).RequiredSignatures -gt 0) -and $win.cmbSigningCerts.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("Selected Template requires signing but not signing cert selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        }


        try {
            if($Win.chkReset.IsChecked) {
                Validate-Pin -Pin1 $Win.pwdPin1.Password -Pin2 $Win.pwdPin2.Password
                $Win.Window.Close()
                Reset-Piv -Card $Card
                Set-Pin -Card $card -CurrentPin "123456" -NewPin $Win.pwdPin1.Password
                Set-Puk -Card $card -CurrentPuk "12345678" -NewPuk $Win.pwdPin1.Password
            } else {
                $Win.Window.Close()
            }

            if((-not $card.Modes -eq "CCID") -and ($Win.RequestNewSetCCIDOnlyMode.IsChecked -eq $true)) {
                Set-Mode -Card $Card -Mode "CCID"
            }

            $args = @{
                Card = $Card
                Pin = $Win.pwdPin1.Password
                KeyAlgo = $Win.cmbKeyAlgo.SelectedItem.Content
                TouchPolicy = $Win.cmbKeyTouchPolicy.SelectedItem.Content
                PinPolicy = $Win.cmbKeyPinPolicy.SelectedItem.Content
                Slot = $Win.cmbSlot.SelectedItem.Tag
            }
            Generate-Key @args

            Generate-Csr -card $Card -pin $Win.pwdPin1.Password -subject $Win.txtSubject.Text -slot $Win.cmbSlot.SelectedItem.Tag

            if(($Win.cmbTemplates.SelectedItem).RequiredSignatures -gt 0) {
                $args = @{
                    SigningCertificateThumbprint = ($Win.cmbSigningCerts.SelectedItem).Thumbprint
                    Subject = $Win.txtSubject.Text
                    CertTemplate = $Win.cmbTemplates.SelectedItem
                }
                Sign-CertificateRequest  @args
            }

            $r = Request-Certificate -CertTemplate $Win.cmbTemplates.SelectedItem
            if($r.pending) {
                [System.Windows.MessageBox]::Show("Certificate request is pending CA Manager approval.`nRequest id: $($r.id)", "Information", 'Ok', 'Information') | Out-Null
                Set-ResultText -Success "Enrollment pending approval, id: $($r.id)"
                return
            }

            Import-Certificate -Card $Card -Pin $Win.pwdPin1.Password -Slot $Win.cmbSlot.SelectedItem.Tag
            Reset-Chuid -Card $Card -Pin $Win.pwdPin1.Password

        } catch {
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
        }

    })

    $Win.Window.ShowDialog()

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
            Set-ResultText -Success "PIN Changed on $($Card.DeviceType)"
        } catch {
            Set-ResultText -Failed "PIN Change failed!"
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnChangePuk.Add_Click({
        try{
            Validate-Puk -Puk1 $Win.pwdChangePukPuk1.Password -Puk2 $Win.pwdChangePukPuk2.Password
            $Win.Window.Close()
            Set-Puk -Card $Card -CurrentPuk $Win.pwdChangePukPuk.Password -NewPuk $Win.pwdChangePukPuk1.Password
            Set-ResultText -Success "PUK Changed on $($Card.DeviceType)"
        } catch {
            Set-ResultText -Failed "PUK Change failed!"
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnUnblockPin.Add_Click({
        try{
            Validate-Pin -Pin1 $Win.pwdUnblockPinPin1.Password -Pin2 $Win.pwdUnblockPinPin1.Password
            $Win.Window.Close()
            Unblock-Pin -Card $Card -CurrentPuk $Win.pwdUnblockPinPuk.Password -NewPin $Win.pwdUnblockPinPin1.Password
            Set-ResultText -Success "PIN Unblocked and changed on $($Card.DeviceType)"
        } catch {
            Set-ResultText -Failed "PIN Unblock failed!"
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnResetPiv.Add_Click({
        if(([System.Windows.Forms.MessageBox]::Show("This will reset the PIV application, continue?","Warning",1,48)) -ne 'Ok') {
            return
        }

        try{
            $Win.Window.Close()
            Reset-Piv -Card $Card
            Set-ResultText -Success "PIV on $($Card.DeviceType) reset successfully"
        } catch {
            Set-ResultText -Failed "PIV reset failed on card $($Card.DeviceType)"
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
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

    $Win.btnEnroll.Add_Click({
        if(([System.Windows.Forms.MessageBox]::Show("This will reset the PIV application and all existing keys will be lost!, continue?","Warning",1,48)) -ne 'Ok') {
            return
        }

        if($win.cmbTemplates.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("No Template selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        }

        if((($win.cmbTemplates.SelectedItem).RequiredSignatures -gt 0) -and $win.cmbSigningCerts.SelectedIndex -lt 0) {
            [System.Windows.MessageBox]::Show("Selected Template requires signing but not signing cert selected!.", "Information", 'Ok', 'Information') | Out-Null
            return
        }

        try {
            Validate-Pin -Pin1 $Win.pwdPin1.Password -Pin2 $Win.pwdPin2.Password
            $Win.Window.Close()
            reset-piv -Card $card
            Set-Pin -Card $card -CurrentPin "123456" -NewPin $Win.pwdPin1.Password
            Set-Puk -Card $card -CurrentPuk "12345678" -NewPuk $Win.pwdPin1.Password
            Generate-Key -Card $card -PIN $Win.pwdPin1.Password -Slot "9a" -TouchPolicy $Win.cmbKeyTouchPolicy.SelectedItem.Content

            Generate-Csr -Card $card -PIN $Win.pwdPin1.Password -Subject $Win.txtSubject.Text -Slot "9a"

            if(($Win.cmbTemplates.SelectedItem).RequiredSignatures -gt 0) {
                Sign-CertificateRequest -SigningCertificateThumbprint ($Win.cmbSigningCerts.SelectedItem).Thumbprint -Subject $Win.txtSubject.Text -CertTemplate $Win.cmbTemplates.SelectedItem
            }

            $r = Request-Certificate -CertTemplate $Win.cmbTemplates.SelectedItem
            if($r.pending) {
                [System.Windows.MessageBox]::Show("Certificate request is pending CA Manager approval.`nRequest id: $($r.id)", "Information", 'Ok', 'Information') | Out-Null
                Set-ResultText -Success "Enrollment pending approval, id: $($r.id)"
                return
            }

            Import-Certificate -Card $card -pin $Win.pwdPin1.Password -slot "9a"
            Reset-Chuid -Card $card -pin $Win.pwdPin1.Password
            Set-Mode -Card $card -Mode "CCID"
            Set-ResultText -Success "Enrollment succeeded"

        } catch {
            #[System.Windows.MessageBox]::Show("$($_ | Out-String)", "Error", 'Ok', 'Error') | Out-Null
            Set-ResultText -Failed "Enrollment failed!"
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.Window.ShowDialog()
    Write-Host "Exited!"
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
        return "$((Get-WmiObject Win32_NTDOMAIN).DomainName)\$(($FindUsersWindow.DataGrid.SelectedItem).samAccountName)"
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
        $cards = Get-SmartCards
        $MainWindow.lstReaders.ItemsSource = $cards
    })

    $MainWindow.ReloadCardsButton.Add_Click({
        $MainWindow.lstReaders.ItemsSource = Get-SmartCards
    })

    $MainWindow.btnShowEnrollWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
           $result = Show-EnrollWindow -Card $MainWindow.lstReaders.SelectedItem
        }
    })

    $MainWindow.btnShowAdvReqWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-AdvReqWindow -Card $MainWindow.lstReaders.SelectedItem
        }
    })

    $MainWindow.btnShowRequestPendingWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-RequestPendingWindow -Card $MainWindow.lstReaders.SelectedItem
        }
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
        [Parameter(Mandatory=$true)]  [PSCustomObject]$Card
    )

    #
    # Setup Window
    #
    $Win = @{}
    $Win.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_RequestPendingWindow))
    $xaml_RequestPendingWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $Win.$($_.Name) = $Win.Window.FindName($_.Name)
    }

    $Win.btnEnroll.Add_Click({
        try{
            $r = Request-Certificate -Id $Win.txtId.Text
            Write-host "lll"
            $r
            if($r.pending) {
                [System.Windows.MessageBox]::Show("Certificate request is still pending CA Manager approval.`nRequest id: $($r.id)", "Information", 'Ok', 'Information') | Out-Null
                Set-ResultText -Success "Enrollment pending approval, id: $($r.id)"
            } else {
                Import-Certificate -Card $card -pin $Win.pwdPin.Password -slot ($Win.cmbSlot.SelectedItem).Tag
                Reset-Chuid -Card $card -pin $Win.pwdPin.Password
                Set-ResultText -Success "Enrollment succeeded"
            }
            $r
        } catch {
            Set-ResultText -Failed "Request failed!"
            [System.Windows.MessageBox]::Show((Hide-Secrets -String $_), "Error", 'Ok', 'Error') | Out-Null
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
    [ValidateSet("Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug")]
    [string]$Severity = "Informational"
    )

    $LogString = Hide-Secrets -String $LogString

    [int]$intSeverity = 0

    if($Severity -eq "Emergency") { $intSeverity = 0; $color = "Red" }
    if($Severity -eq "Alert") { $intSeverity = 1; $color = "Red" }
    if($Severity -eq "Critical") { $intSeverity = 2; $color = "Red" }
    if($Severity -eq "Error") { $intSeverity = 3; $color = "Red" }
    if($Severity -eq "Warning") { $intSeverity = 4; $color = "Magenta" }
    if($Severity -eq "Notice") { $intSeverity = 5; $color = "Cyan" }
    if($Severity -eq "Informational") { $intSeverity = 6; $color = "White" }
    if($Severity -eq "Debug") { $intSeverity = 7; $color = "Yellow" }

    if($intSeverity -le 5)
    {
        Write-Host $LogString -Foreground $color
    }
    elseif(($intSeverity -eq 6) -and ($script:ShowVerboseOutput))
    {
        Write-Host $LogString -Foreground $color
    }
    elseif(($intSeverity -eq 7) -and ($script:ShowDebugOutput))
    {
        Write-Host $LogString -Foreground $color
    }
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
[xml]$xaml_EnrollWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="EnrollWindow"
    Title="" Height="325" Width="425">

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
        </Grid.RowDefinitions>
        <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Enroll new card" FontSize="16"/>
        <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

        <TextBlock Grid.Column="0" Grid.Row="3" Text="Template"/>
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

        <TextBlock Grid.Column="0" Grid.Row="7" Text="Key Touch Policy"/>
        <ComboBox Grid.Column="2" Grid.Row="7"  HorizontalAlignment="Stretch" SelectedIndex="2" Name="cmbKeyTouchPolicy">
            <ComboBoxItem Content="ALWAYS"/>
            <ComboBoxItem Content="NEVER"/>
            <ComboBoxItem Content="CACHED"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="8" Text="New PIN"/>
        <PasswordBox Grid.Column="2" Grid.Row="8" Name="pwdPin1" HorizontalAlignment="Left"/>

        <TextBlock Grid.Column="0" Grid.Row="9" Text="New PIN (Again)"/>
        <PasswordBox Grid.Column="2" Grid.Row="9" Name="pwdPin2" HorizontalAlignment="Left"/>

        <ToggleButton Grid.Column="2" Grid.Row="10" Name="btnEnroll" Content="Enroll" Width="90" HorizontalAlignment="Right"/>
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

        <ScrollViewer Grid.Column="0" Grid.Row="2" Margin="10" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" CanContentScroll="True">
            <StackPanel>
                <GroupBox Visibility="{Binding ElementName=lstReaders,Path=SelectedItem.CardOk, FallbackValue=Collapsed, Converter={StaticResource VisCon}}">
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
                        <TextBlock Grid.Row="0" Grid.Column="2" Text="{Binding ElementName=lstReaders, Path=SelectedItem.SerialNumber}"/>

                        <TextBlock Grid.Row="1" Grid.Column="0" Text="PIV Version"/>
                        <TextBlock Grid.Row="1" Grid.Column="2" Text="{Binding ElementName=lstReaders, Path=SelectedItem.PIV_Version}"/>

                        <TextBlock Grid.Row="2" Grid.Column="0" Text="Firmware Version"/>
                        <TextBlock Grid.Row="2" Grid.Column="2" Text="{Binding ElementName=lstReaders, Path=SelectedItem.FirmwareVersion}"/>

                        <TextBlock Grid.Row="3" Grid.Column="0" Text="Modes"/>
                        <TextBlock Grid.Row="3" Grid.Column="2" Text="{Binding ElementName=lstReaders, Path=SelectedItem.Modes}"/>

                        <TextBlock Grid.Row="4" Grid.Column="0" Text="PIN Retries"/>
                        <TextBlock Grid.Row="4" Grid.Column="2" Text="{Binding ElementName=lstReaders, Path=SelectedItem.PINRetries}"/>

                        <TextBlock Grid.Row="0" Grid.Column="4" Text="OTP"/>
                        <TextBlock Grid.Row="0" Grid.Column="6" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_OTP}"/>

                        <TextBlock Grid.Row="1" Grid.Column="4" Text="FIDO U2F"/>
                        <TextBlock Grid.Row="1" Grid.Column="6" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_FIDOU2F}"/>

                        <TextBlock Grid.Row="2" Grid.Column="4" Text="FIDO2"/>
                        <TextBlock Grid.Row="2" Grid.Column="6" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_FIDO2}"/>

                        <TextBlock Grid.Row="3" Grid.Column="4" Text="Open PGP"/>
                        <TextBlock Grid.Row="3" Grid.Column="6" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_OpenPGP}"/>

                        <TextBlock Grid.Row="4" Grid.Column="4" Text="PIV"/>
                        <TextBlock Grid.Row="4" Grid.Column="6" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_PIV}"/>

                        <TextBlock Grid.Row="5" Grid.Column="4" Text="OATH"/>
                        <TextBlock Grid.Row="5" Grid.Column="6" Text="{Binding ElementName=lstReaders, Path=SelectedItem.App_OATH}"/>

                    </Grid>
                </GroupBox>

                <GroupBox Grid.Column="1" Visibility="{Binding ElementName=lstReaders,Path=SelectedItem.slot9a.InUse, FallbackValue=Collapsed, Converter={StaticResource VisCon}}">
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
                <GroupBox Grid.Column="2" Visibility="{Binding ElementName=lstReaders,Path=SelectedItem.slot9c.InUse, FallbackValue=Collapsed, Converter={StaticResource VisCon}}">
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

        <GroupBox Grid.Row="1" Grid.RowSpan="2" Grid.Column="1" Margin="10">
        <GroupBox.Header>
            <TextBlock Text="Card Actions" FontWeight="Bold"/>
        </GroupBox.Header>
            <Grid>
                <StackPanel Orientation="Vertical">
                    <Button Content="Enroll New Card" Name="btnShowEnrollWindow" Margin="4"/>
                    <Button Content="Retrieve Pending" Name="btnShowRequestPendingWindow" Margin="4"/>
                    <Button Content="Advanced Request" Name="btnShowAdvReqWindow" Margin="4"/>
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

                </StackPanel>
            </Grid>
        </GroupBox>

        <Grid Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="2" Margin="10,0,10,10">
            <TextBlock HorizontalAlignment="Center" Name="txtResult" Margin="10,2,10,0" TextAlignment="Center" VerticalAlignment="Center"/>
            <ProgressBar IsIndeterminate="True" Name="ProgressBar" Height="25" VerticalAlignment="Top" Visibility="{Binding ElementName=ProgressBar,Path=IsIndeterminate, Converter={StaticResource VisCon}}"/>
            <TextBlock HorizontalAlignment="Center" Name="txtStatus" Margin="10,2,10,0" TextAlignment="Center" VerticalAlignment="Center" Visibility="{Binding ElementName=ProgressBar,Path=IsIndeterminate, Converter={StaticResource VisCon}}"/>
        </Grid>
    </Grid>

</Window>

"@
[xml]$xaml_AdvReqWindow = @"

<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="AdvReqWindow"
    Title="" Height="425" Width="425">

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

    <Grid Name="AdvancedRequestGrid" Grid.Row="1" Width="380" Visibility="{Binding ElementName=ShowRequestGridButton,Path=IsChecked, Converter={StaticResource VisCon}}" Margin="10,10,10,0">
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
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="20"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="0" Text="Advanced request" FontSize="16"/>
        <Separator Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="1" VerticalAlignment="Top"/>

        <TextBlock Grid.Column="0" Grid.Row="2" Text="Reset PIV"/>
        <CheckBox Grid.Column="2" Grid.Row="2" Name="chkReset" VerticalAlignment="Center"/>

        <TextBlock Grid.Column="0" Grid.Row="3" Text="Template"/>
        <ComboBox Grid.Column="2" Grid.Row="3" Width="Auto" Name="cmbTemplates" DisplayMemberPath="DisplayName" HorizontalAlignment="Stretch"/>

        <TextBlock Grid.Column="0" Grid.Row="4" Text="Signing certificate" FontSize="12" Name="AdvReqSigningCertTextBlock">
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
        <ComboBox Grid.Column="2" Grid.Row="4" Name="cmbSigningCerts" DisplayMemberPath="Description" Visibility="{Binding ElementName=AdvReqSigningCertTextBlock, Path=Visibility}"/>

        <TextBlock Grid.Column="0" Grid.Row="5" Text="Subject" Visibility="{Binding ElementName=AdvReqSigningCertTextBlock, Path=Visibility}"/>
        <Grid Grid.Column="2" Grid.Row="5" Visibility="{Binding ElementName=AdvReqSigningCertTextBlock, Path=Visibility}">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox Grid.Column="0" Name="txtSubject" IsReadOnly="True" HorizontalAlignment="Stretch"/>

            <Button Grid.Column="1" Height="25" Width="25" HorizontalAlignment="Right" VerticalAlignment="Top" Name="btnShowFindUsersWindow" ToolTip="Find user" Background="Transparent" Margin="2,2,0,2">
                <Path Margin="1" Stretch="Uniform" Fill="{StaticResource iconColor}" Data="{StaticResource searchIcon}"/>
            </Button>
        </Grid>

        <TextBlock Grid.Column="0" Grid.Row="6" Text="Target Slot"/>
        <ComboBox Grid.Column="2" Grid.Row="6" HorizontalAlignment="Stretch" Name="cmbSlot" SelectedIndex="0">
            <ComboBoxItem Content="Slot 9a: PIV Authentication" Tag="9a"/>
            <ComboBoxItem Content="Slot 9c: Digital Signature" Tag="9c"/>
            <ComboBoxItem Content="Slot 9d: Key Management" Tag="9d"/>
            <ComboBoxItem Content="Slot 9e: Card Authentication" Tag="9e"/>
            <ComboBoxItem Content="Slot f9: Attestation" Tag="f9"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="7" Text="Key Touch Policy"/>
        <ComboBox Grid.Column="2" Grid.Row="7"  HorizontalAlignment="Stretch" SelectedIndex="2" Name="cmbKeyTouchPolicy">
            <ComboBoxItem Content="ALWAYS"/>
            <ComboBoxItem Content="NEVER"/>
            <ComboBoxItem Content="CACHED"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="8" Text="Key PIN Policy"/>
        <ComboBox Grid.Column="2" Grid.Row="8"  HorizontalAlignment="Stretch" SelectedIndex="0" Name="cmbKeyPinPolicy">
            <ComboBoxItem Content="DEFAULT"/>
            <ComboBoxItem Content="NEVER"/>
            <ComboBoxItem Content="ONCE"/>
            <ComboBoxItem Content="ALWAYS"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="9" Text="Key Algorithm"/>
        <ComboBox Grid.Column="2" Grid.Row="9"  HorizontalAlignment="Stretch" SelectedIndex="2" Name="cmbKeyAlgo">
            <ComboBoxItem Content="TDES"/>
            <ComboBoxItem Content="RSA1024"/>
            <ComboBoxItem Content="RSA2048"/>
            <ComboBoxItem Content="ECCP256"/>
            <ComboBoxItem Content="ECCP384"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="10" Text="CCID Only Mode"/>
        <CheckBox Grid.Column="2" Grid.Row="10" Name="RequestNewSetCCIDOnlyMode" VerticalAlignment="Center"/>

        <TextBlock Grid.Column="0" Grid.Row="13">
            <TextBlock.Style>
                <Style TargetType="TextBlock" BasedOn="{StaticResource {x:Type TextBlock}}">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding ElementName=chkReset,Path=IsChecked}" Value="False">
                            <Setter Property="Text" Value="Current PIN"/>
                        </DataTrigger>
                        <DataTrigger Binding="{Binding ElementName=chkReset,Path=IsChecked}" Value="True">
                            <Setter Property="Text" Value="New PIN"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </TextBlock.Style>
        </TextBlock>
        <PasswordBox Grid.Column="2" Grid.Row="13" Name="pwdPin1" HorizontalAlignment="Left"/>

        <TextBlock Grid.Column="0" Grid.Row="14" Text="New PIN (Again)" Visibility="{Binding ElementName=chkReset,Path=IsChecked, Converter={StaticResource VisCon}}"/>
        <PasswordBox Grid.Column="2" Grid.Row="14" Name="pwdPin2" HorizontalAlignment="Left" Visibility="{Binding ElementName=chkReset,Path=IsChecked, Converter={StaticResource VisCon}}"/>

        <Button Grid.Column="2" Grid.Row="16" Name="btnEnroll" Content="Enroll" Width="90" HorizontalAlignment="Right"/>

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

        <TextBlock Grid.Column="0" Grid.Row="5" Text="Target Slot"/>
        <ComboBox Grid.Column="2" Grid.Row="5" HorizontalAlignment="Stretch" Name="cmbSlot" SelectedIndex="0">
            <ComboBoxItem Content="Slot 9a: PIV Authentication" Tag="9a"/>
            <ComboBoxItem Content="Slot 9c: Digital Signature" Tag="9c"/>
            <ComboBoxItem Content="Slot 9d: Key Management" Tag="9d"/>
            <ComboBoxItem Content="Slot 9e: Card Authentication" Tag="9e"/>
            <ComboBoxItem Content="Slot f9: Attestation" Tag="f9"/>
        </ComboBox>

        <TextBlock Grid.Column="0" Grid.Row="6" Text="Current PIN"/>
        <PasswordBox Grid.Column="2" Grid.Row="6" Name="pwdPin" HorizontalAlignment="Left"/>

        <Button Grid.Column="2" Grid.Row="8" Name="btnEnroll" Content="Retrieve" Width="90" HorizontalAlignment="Right"/>
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
#endregion
Show-MainWindow




#######################################################################
#                                                                     #
# Merged by user: administrator                                       #
# On computer:    DC01                                                #
# Date:           2021-02-13 23:12:04                                 #
# No code signing certificate found!                                  #
#                                                                     #
#######################################################################
