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