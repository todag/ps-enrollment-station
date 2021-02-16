###############################################################################
#.SYNOPSIS
#   Merges the project into one single .ps1 file.
#   Offers option to sign the resulting file if a code signing
#   certificate is found.
#
#   This is just a quick (and ugly) hack...
#
###############################################################################

$VerbosePreference = "Continue"

#
# The merged project till be written to this file
#
$outputFile = "enrollment-station-merged.ps1"


$data = (Get-Content ".\enrollment-station.ps1")
[System.Collections.Generic.List[string]]$script:outputData = New-Object System.Collections.Generic.List[string]

#region Functions
function Add-Functions
{
    Write-Output "Merging functions"
    $script:outputData.Add("#region Functions")
    Get-ChildItem -Path .\functions -Filter *.ps1 | ForEach-Object {
        Write-Verbose ("Adding function: " + $_.Name)
        $function = (Get-Content $_.FullName)
        foreach($line in $function)
        {
            $script:outputData.Add($line)
        }
    }
    $script:outputData.Add("#endregion")
}

function Add-XAML
{
    Write-Output "Merging XAML resources"
    $script:outputData.Add("#region XAML")
    $xamlFiles = @{
        xaml_MainWindow = "MainWindow.xaml"
        xaml_EnrollWindow = "EnrollWindow.xaml"
        xaml_RequestToFileWindow = "RequestToFileWindow.xaml"
        xaml_RequestPendingWindow = "RequestPendingWindow.xaml"
        xaml_FindUsersWindow = "FindUsersWindow.xaml"
        xaml_CardOperationsWindow = "CardOperationsWindow.xaml"
    }

    foreach($key in $xamlFiles.Keys) {
        $path = ".\resources\$($xamlFiles.Item($key))"
        Write-Verbose "Adding $path"
        $script:outputData.Add("[xml]`$$key = @`"`n")
        foreach($line in (Get-Content $path)){
            $script:outputData.Add($line)
        }
        $script:outputData.Add("`n`"@")
    }
    $script:outputData.Add("#endregion")
}
#endregion

[bool]$skip = $false
[string]$skipUntil = $null
foreach($line in $data)
{
    if($skip -eq $true -and $line.StartsWith($skipUntil))
    {
        $skip = $false
        $skipUntil = $null
        continue
    }
    elseif($skip -eq $true -and !$line.StartsWith($skipUntil))
    {
        continue
    }

    if($line.StartsWith("#region DotSource"))
    {
        $skip = $true
        $skipUntil = "#endregion"
        Add-Functions
    }
    elseif($line.StartsWith("#region XAML"))
    {
        $skip = $true
        $skipUntil = "#endregion"
        Add-XAML
    }
    else
    {
        $script:outputData.Add($line) | Out-Null
    }
}

#
# Write $script:outputData to $outputFile
#
$script:outputData.Add(("#").PadRight(70,"#") + "#")
$script:outputData.Add(("#").PadRight(70," ") + "#")
$script:outputData.Add(("# Merged by user: " + $env:USERNAME).PadRight(70," ") + "#")
$script:outputData.Add(("# On computer:    " + $env:COMPUTERNAME).PadRight(70," ") + "#")
$script:outputData.Add(("# Date:           " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")).PadRight(70," ") + "#")
if(-not (Get-ChildItem cert:\CurrentUser\My -codesign))
{
    $script:outputData.Add(("# No code signing certificate found!").PadRight(70," ") + "#")
}


$script:outputData.Add(("#").PadRight(70," ") + "#")
$script:outputData.Add(("#").PadRight(70,"#") + "#")

Set-Content $outputFile $script:outputData
Write-Output ("Merged project file created")
Write-Output ("Total line count: " + $script:outputData.Count)

#
# Check if code signing certificate exists and ask if merged script should be signed
#
if((Get-ChildItem cert:\CurrentUser\My -codesign))
{
    $answer = Read-Host "Found code signing certificate, sign merged file? (y/n)"
    if($answer -eq "y")
    {
        $index = 0
        foreach($cert in (Get-ChildItem cert:\CurrentUser\My -codesign))
        {
            Write-Output ("Index [" + $index.ToString() + "] Subject: " + $cert.Subject + " TP: " + $cert.Thumbprint)
        }

        [int]$certIndex = Read-Host "Type index of certificate to sign with: "
        Set-AuthenticodeSignature $outputFile @(Get-ChildItem cert:\CurrentUser\My -codesign)[$certIndex]
    }
}
else
{
    Write-Output "*** No code signing certificate found! ***"
}
Write-Output ("Merged file size: " + (Get-Item $outputFile).Length + " bytes")
Write-Output "Merge operations finished. Script terminated, press enter to exit session..."
Read-Host