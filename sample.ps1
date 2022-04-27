Test-Path -Path "HKLM:\Software\ACN\rDWPMode\"

True

Test-Path -Path "HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy"

False

$rDWPRegPath = "HKLM:\Software\ACN\rDWPMode\"
$rDWPCmode = "CurrentrDWPMode"
$mModeVal = "Maintenance"
$pModeVal = "Production"

Test-Path $rDWPRegPath
    New-Item -Path $rDWPRegPath -Force | Out-Null
    New-ItemProperty -Path $rDWPRegPath -Name $rDWPCmode -Value "None" 