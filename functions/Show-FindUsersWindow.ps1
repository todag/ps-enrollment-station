function Show-FindUsersWindow() {
    #
    # Setup Window
    #
    $FindUsersWindow = @{}
    $FindUsersWindow.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml_FindUsersWindow))
    $xaml_FindUsersWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
        $FindUsersWindow.$($_.Name) = $FindUsersWindow.Window.FindName($_.Name)
    }

    $FindUsersWindow.SearchButton.add_Click({
        try {
            $users = (Get-AdUsers -SearchString $FindUsersWindow.SearchTextBox.Text)
            $FindUsersWindow.DataGrid.ItemsSource = $users
            $FindUsersWindow.CountTextBlock.Text = "Search matched $($users.Count) users"
        } catch {
            [System.Windows.MessageBox]::Show("$($_)", "Error", 'Ok', 'Error') | Out-Null
        }
    })

    $FindUsersWindow.OkButton.add_Click({
        $FindUsersWindow.Window.Close()
    })

    $FindUsersWindow.CancelButton.add_Click({
        $FindUsersWindow.Window.Close()
    })

    $FindUsersWindow.Window.ShowDialog() | Out-Null

    if($FindUsersWindow.OkButton.IsChecked)
    {
        return "$((Get-WmiObject Win32_NTDOMAIN).DomainName)\$(($FindUsersWindow.DataGrid.SelectedItem).samAccountName)".Trim()
    }
}