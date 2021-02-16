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
    [ValidateSet("Critical", "Warning", "Notice", "Debug")]
    [string]$Severity = "Notice"
    )

    $LogString = Hide-Secrets -String $LogString

    [int]$intSeverity = 0

    if($Severity -eq "Critical") { $intSeverity = 2; $color = "Red" }
    if($Severity -eq "Warning") { $intSeverity = 4; $color = "Magenta" }
    if($Severity -eq "Notice") { $intSeverity = 5; $color = "Cyan" }
    if($Severity -eq "Debug") { $intSeverity = 7; $color = "Yellow" }

    if(($Severity -eq "Debug") -and (-not $script:ShowDebugOutput))
    {
        return
    }

    $TimeStamp = ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))

    if($LogString.Contains([Environment]::NewLine)) {
        $LogString = ($TimeStamp + " [" + $Severity + "] [" + $((Get-PSCallStack)[1].Command) + "] `n" + $LogString)
    } else {
        $LogString = ($TimeStamp + " [" + $Severity + "] [" + $((Get-PSCallStack)[1].Command) + "] " + $LogString)
    }




    Write-Host $LogString -Foreground $color

}