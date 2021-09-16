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
    $Win.txtSubject.Text = "$($env:Username)"

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