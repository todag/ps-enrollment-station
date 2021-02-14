function Show-MainWindow(){
    # Setup Window
    #
    $MainWindow = @{}
    $MainWindow.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_MainWindow))
    $xaml_MainWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $MainWindow.$($_.Name) = $MainWindow.Window.FindName($_.Name)
    }

    #
    # Hide console window
    #
    $MainWindow.Window.add_Loaded({
        $consolePtr = [Console.Window]::GetConsoleWindow()
        [Console.Window]::ShowWindow($consolePtr, 0)
    })

    #
    # Show/Hide console button clicked
    #
    $MainWindow.btnShowConsole.add_Click({
        $consolePtr = [Console.Window]::GetConsoleWindow()
        if($MainWindow.btnShowConsole.IsChecked)
        {
            [Console.Window]::ShowWindow($consolePtr, 1)
            Write-Log -LogString "Showing console... *** Warning! *** Closing console window will terminate the script. Use togglebutton to hide it again." -Severity Warning
        }
        else
        {
            Write-Log -LogString "Hiding console..." -Severity Debug
            [Console.Window]::ShowWindow($consolePtr, 0)
        }
    })

    #
    # Appinfo button clicked
    #
    $MainWindow.btnShowAppInfo.add_Click({
        [System.Windows.MessageBox]::Show($appAbout, "Information", 'Ok', 'Information') | Out-Null
    })

    function Check-ValidCardIsSelected{
        if(($MainWindow.lstReaders.SelectedIndex -eq -1) -or (-not $MainWindow.lstReaders.SelectedItem.CardOk)) {
            [System.Windows.MessageBox]::Show("You must select a compatible card.", "Information", 'Ok', 'Information') | Out-Null
            return $false
        } else {
            return $true
        }
    }

    $MainWindow.Window.add_ContentRendered( {        
        $MainWindow.lstReaders.ItemsSource = Get-SmartCards
    })

    $MainWindow.ReloadCardsButton.Add_Click({
        $MainWindow.lstReaders.ItemsSource = Get-SmartCards
    })

    $MainWindow.btnShowEnrollWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
           $result = Show-EnrollWindow -Card $MainWindow.lstReaders.SelectedItem
        }
    })

    $MainWindow.btnShowAdvReqWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-AdvReqWindow -Card $MainWindow.lstReaders.SelectedItem
        }
    })

    $MainWindow.btnShowRequestPendingWindow.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-RequestPendingWindow -Card $MainWindow.lstReaders.SelectedItem
        }
    })

    $MainWindow.btnChangePin.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "ChangePIN"
        }
    })

    $MainWindow.btnChangePuk.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "ChangePUK"
        }
    })

    $MainWindow.btnUnblockPin.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "UnblockPIN"
        }
    })

    $MainWindow.btnResetPiv.Add_Click({
        if(Check-ValidCardIsSelected) {
            Show-CardOperationsWindow -Card $MainWindow.lstReaders.SelectedItem -Operation "ResetPIV"
        }
    })

    $MainWindow.Window.ShowDialog()

}