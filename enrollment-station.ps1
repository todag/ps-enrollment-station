Set-StrictMode -Version 2.0
$appVersion = "0.3.1 - 2021-09-16"
$appAbout = @"
Enrollment Station v $($appVersion)

Copyright (C) 2021 github.com/todag

Icons from:
http://modernuiicons.com/
https://materialdesignicons.com/
"@

Write-Host ("::Loading enrollment-station v" + $appVersion)
$ErrorActionPreference = "Stop"

#
# ---------------------- Script scope variables ----------------------
#
$script:ykman = "C:\Program Files\Yubico\YubiKey Manager\ykman.exe"
$script:workDir = "$($env:APPDATA)\ps-enrollment-station"
$script:hideSecrets = $true
$script:ShowDebugOutput = $true
$script:ca = (New-Object -ComObject CertificateAuthority.Config).GetConfig(0)

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
if(!(Test-Path $script:workDir)) {
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
[xml]$xaml_RequestToFileWindow = Get-Content -Path "$($PSScriptRoot)\resources\RequestToFileWindow.xaml"
[xml]$xaml_RequestPendingWindow = Get-Content -Path "$($PSScriptRoot)\resources\RequestPendingWindow.xaml"
[xml]$xaml_FindUsersWindow = Get-Content -Path "$($PSScriptRoot)\resources\FindUsersWindow.xaml"
[xml]$xaml_CardOperationsWindow = Get-Content -Path "$($PSScriptRoot)\resources\CardOperationsWindow.xaml"
#endregion
Show-MainWindow




