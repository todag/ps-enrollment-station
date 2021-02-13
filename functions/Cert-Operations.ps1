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