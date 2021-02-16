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

    $Win.btnCancel.add_Click({
        $Win.Window.Close()
    })

    $Win.btnEnroll.Add_Click({
        try{
            $Id = $Win.txtId.Text
            $Slot = $Win.cmbSlot.SelectedItem.Tag
            $Pin = $Win.pwdPin.Password

            $request = Request-Certificate -Id $Id

            if($request.ReturnCode -eq 5) {
                [System.Windows.MessageBox]::Show("Certificate request is still pending CA Manager approval.`nRequest id: $($Id)", "Information", 'Ok', 'Information') | Out-Null
                Set-ResultText -Success "Enrollment pending approval, id: $($Id)"
                return
            } elseif($request.ReturnCode -eq 3) {
                Import-Certificate -Card $Card -Pin $Pin -Slot $Slot -CertBase64 $request.Base64
                Reset-Chuid -Card $Card -Pin $Pin
                [System.Windows.MessageBox]::Show("Certificate enrolled successfully!", "Information", 'Ok', 'Information') | Out-Null
                [System.Windows.MessageBox]::Show("The Card Holder Unique Identifier (CHUID) has been reset.`n`nYou should remove and reinsert the key before enrolling other certificates or doing any signing operations.", "Information", 'Ok', 'Information') | Out-Null
            } else {
                throw "Unexpected return code [$($request.ReturnCode)] while requesting certificate."
            }
        } catch {
            [System.Windows.MessageBox]::Show("Request failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })
    $Win.Window.ShowDialog()
}