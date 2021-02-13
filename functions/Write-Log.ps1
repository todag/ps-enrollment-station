Function Write-Log
{
    <#
    .SYNOPSIS
        Writes log to console
    .PARAMETER LogString
        The string to log/output
    .PARAMETER Severity
        Severity of the message
    #>
    param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$LogString,
    [Parameter(Mandatory = $false)]
    [ValidateSet("Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug")]
    [string]$Severity = "Informational"
    )

    $LogString = Hide-Secrets -String $LogString

    [int]$intSeverity = 0

    if($Severity -eq "Emergency") { $intSeverity = 0; $color = "Red" }
    if($Severity -eq "Alert") { $intSeverity = 1; $color = "Red" }
    if($Severity -eq "Critical") { $intSeverity = 2; $color = "Red" }
    if($Severity -eq "Error") { $intSeverity = 3; $color = "Red" }
    if($Severity -eq "Warning") { $intSeverity = 4; $color = "Magenta" }
    if($Severity -eq "Notice") { $intSeverity = 5; $color = "Cyan" }
    if($Severity -eq "Informational") { $intSeverity = 6; $color = "White" }
    if($Severity -eq "Debug") { $intSeverity = 7; $color = "Yellow" }

    if($intSeverity -le 5)
    {
        Write-Host $LogString -Foreground $color
    }
    elseif(($intSeverity -eq 6) -and ($script:ShowVerboseOutput))
    {
        Write-Host $LogString -Foreground $color
    }
    elseif(($intSeverity -eq 7) -and ($script:ShowDebugOutput))
    {
        Write-Host $LogString -Foreground $color
    }
}