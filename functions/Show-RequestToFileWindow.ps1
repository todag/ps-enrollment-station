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