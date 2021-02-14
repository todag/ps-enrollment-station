function Execute() {
    <#
    .SYNOPSIS
        Runs an executable or command and logs the output
    .PARAMETER Desc
        Description of the execution, is presented in the ProgressBar
    .PARAMETER ExeFile
        The file or command to execute
    .PARAMETER Arguments
        The arguments for the executable
    .PARAMETER NoThrow
        Don't throw exception if the execution return code is > 0
    #>
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $Desc,
        [Parameter(Mandatory = $true)]
        [string] $ExeFile,
        [Parameter(Mandatory = $true)]
        [string] $Arguments,
        [Parameter(Mandatory = $false)]
        [switch] $NoThrow
    )

    Write-Log -LogString "Executing: $([System.IO.Path]::GetFileName($exeFile)) $arguments" -Severity Notice

    $MainWindow.ProgressBar.IsIndeterminate = $true
    $MainWindow.txtStatus.Text = $desc

    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.Status = ""
    $runSpace = [runspacefactory]::CreateRunspace()
    $runSpace.ApartmentState = "STA"
    $runSpace.ThreadOptions = "ReuseThread"
    $runSpace.Open()
    $runSpace.SessionStateProxy.SetVariable("syncHash", $syncHash)
    $runSpace.SessionStateProxy.SetVariable("arguments", $arguments)
    $runSpace.SessionStateProxy.SetVariable("exeFile", $exeFile)

    $powershell = [powershell]::Create().AddScript({
        Try {
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = $exeFile
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = $arguments
                $pinfo.CreateNoWindow = $true
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $syncHash.result = [pscustomobject]@{
                    stdout   = $p.StandardOutput.ReadToEnd()
                    stderr   = $p.StandardError.ReadToEnd()
                    ExitCode = $p.ExitCode
                }
                $p.WaitForExit()
                #
                # Hide secrets from output
                #
                $syncHash.result.stdout = Hide-Secrets -String $syncHash.result.stdout
                $syncHash.result.stderr = Hide-Secrets -String $syncHash.result.stderr                
                $arguments = Hide-Secrets -String $arguments
            }
            Catch {
                Write-Host "CATCH!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            }
        })

    $powershell.Runspace = $runSpace
    $object = $powershell.BeginInvoke()

    while (!$object.IsCompleted) {
        Start-Sleep -Milliseconds 50
        [System.Windows.Forms.Application]::DoEvents()
    }

    $MainWindow.ProgressBar.IsIndeterminate = $false
    $MainWindow.txtStatus.Text = ""

    Write-Log -LogString "Return code: ---$($syncHash.result.ExitCode)---" -Severity Debug

    if (-Not ([string]::IsNullOrEmpty($syncHash.result.stdout))) {
        Write-Log -LogString "Stdout: $($syncHash.result.stdout)" -Severity Debug
    }
    if (-Not ([string]::IsNullOrEmpty($syncHash.result.stderr))) {
        Write-Log -LogString "Stderr: $($syncHash.result.stderr)" -Severity Critical
    }

    if($syncHash.result.ExitCode -ne 0) {
        Write-Log -LogString "Executing $exeFile with arguments: $arguments failed with message: $($syncHash.result.stderr) `n $($syncHash.result.stdout)" -Severity Critical
        if(-not $NoThrow) {
            throw "Executing $exeFile with arguments: $arguments failed with message: $($syncHash.result.stderr) `n $($syncHash.result.stdout)"
        }
    }

    return ,$syncHash.result
}