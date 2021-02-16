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