Set-StrictMode -Version 2.0
$appVersion = "0.1 - 2020-02-13"
$appAbout = @"
Enrollment Station v $($appVersion)

Copyright (C) 2021 github.com/todag

Icons from:
http://modernuiicons.com/
https://materialdesignicons.com/
"@

Write-Host ("::Loading enrollment-station v" + $appVersion)

#
# ---------------------- Script scope variables ----------------------
#
$script:ykman = "C:\Program Files\Yubico\YubiKey Manager\ykman.exe"
$script:certreq = "C:\Windows\system32\certreq.exe"
$script:workDir = "$($env:APPDATA)\ps-enrollment-station"
$script:hideSecrets = $true
$script:ShowVerboseOutput = $true
$script:ShowDebugOutput = $true
$script:ca = "DC01.AD.LOCAL\AD-DC01-CA"

#
# Load Required assemblies
#
Write-Host ("::Loading assemblies... ") -NoNewline
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
        '

Write-Host ("Done!") -ForegroundColor Green
If(!(Test-Path $script:workDir)) {
    New-Item -ItemType Directory -Force -Path $script:workDir | Out-Null
}

#region DotSource
#
# DotSource all files in .\functions
#
Get-ChildItem -Path "$($PSScriptRoot)\functions\*.ps1" -Exclude $($MyInvocation.MyCommand.Name) | ForEach-Object {
    Write-Host ("::Dot sourcing function: " + $_.Name)
    . $_.FullName
}
#endregion

#region XAML
#
# Read WPF resources
#
[xml]$xaml_MainWindow = Get-Content -Path "$($PSScriptRoot)\resources\MainWindow.xaml"
[xml]$xaml_EnrollWindow = Get-Content -Path "$($PSScriptRoot)\resources\EnrollWindow.xaml"
[xml]$xaml_AdvReqWindow = Get-Content -Path "$($PSScriptRoot)\resources\AdvReqWindow.xaml"
[xml]$xaml_RequestPendingWindow = Get-Content -Path "$($PSScriptRoot)\resources\RequestPendingWindow.xaml"
[xml]$xaml_FindUsersWindow = Get-Content -Path "$($PSScriptRoot)\resources\FindUsersWindow.xaml"
[xml]$xaml_CardOperationsWindow = Get-Content -Path "$($PSScriptRoot)\resources\CardOperationsWindow.xaml"
#endregion
Show-MainWindow



