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