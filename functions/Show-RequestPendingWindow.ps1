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