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