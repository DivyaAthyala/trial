function getCurrentMode
{

$rDWPRegPath = "HKLM:\Software\ACN\rDWPMode\"
$rDWPCmode = "CurrentrDWPMode"
$mModeVal = "Maintenance"
$pModeVal = "Production"

If((Test-Path $rDWPRegPath)){
    $rMode = Get-ItemProperty -path "$rDWPRegPath" -Name "$rDWPCmode" -ErrorAction SilentlyContinue
    
        If ($rMode.CurrentrDWPMode -eq "None") 
            {$cMode = "None"}

        elseif($rMode.CurrentrDWPMode -eq "Production")
            {$cMode = "Production"}

        elseif($rMode.CurrentrDWPMode -eq "Maintenance")
            {$cMode = "Maintenance"}
            
        Else{$cMode = "Unknown"}
    }

    Return $cMode
}

getCurrentMode
$Mode = getCurrentMode
