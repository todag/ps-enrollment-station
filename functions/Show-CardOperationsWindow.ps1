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
            [System.Windows.MessageBox]::Show("PIN Changed on $($Card.DeviceType)", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PIN Change failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnChangePuk.Add_Click({
        try{
            Validate-Puk -Puk1 $Win.pwdChangePukPuk1.Password -Puk2 $Win.pwdChangePukPuk2.Password
            $Win.Window.Close()
            Set-Puk -Card $Card -CurrentPuk $Win.pwdChangePukPuk.Password -NewPuk $Win.pwdChangePukPuk1.Password
            [System.Windows.MessageBox]::Show("PUK Changed on $($Card.DeviceType)", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PUK Change failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnUnblockPin.Add_Click({
        try{
            Validate-Pin -Pin1 $Win.pwdUnblockPinPin1.Password -Pin2 $Win.pwdUnblockPinPin1.Password
            $Win.Window.Close()
            Unblock-Pin -Card $Card -CurrentPuk $Win.pwdUnblockPinPuk.Password -NewPin $Win.pwdUnblockPinPin1.Password
            [System.Windows.MessageBox]::Show("PIN Unblocked and changed on $($Card.DeviceType)", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PIN Unblock failed!`n$(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $Win.btnResetPiv.Add_Click({
        if(([System.Windows.Forms.MessageBox]::Show("This will reset the PIV application, continue?`n`nWarning! All keys will be lost!","Warning",1,48)) -ne 'Ok') {
            return
        }

        try{
            $Win.Window.Close()
            Reset-Piv -Card $Card
            [System.Windows.MessageBox]::Show("PIV on $($Card.DeviceType) reset successfully", "Information", 'Ok', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("PIV reset failed on card $(Hide-Secrets -String $_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })




    $Win.Window.ShowDialog()

}