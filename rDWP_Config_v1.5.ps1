
<#
.Synopsis
  Siemens rDWP Client Mode Configuration Script.
.Description
	This script built to configure and switch rDWP client configuration
.Example
	C:\PS>rDWP_Config_v1.1.ps1

.Notes
	Name: rDWP Config
	Author: Accenture
	Last Edit: 03/09/2022
.Inputs
	None
.Outputs
	None
.Version History
    v1.1 - Amended for desktop background
    v1.2 - Fixed for mode detection reg key, improvised for trey message
    v1.3 - Changed logs location, fixed mmc block-in function, added NonAdmin-Restrictions function
    v1.4 - Fixed to apply mmc snap-ins, desktop background all users (profile is already created) on device
#>




# Function to write logs 
function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path="C:\ProgramData\Accenture\Applogs\rDWP_Config.log", 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info") 
          

 # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
      if (!(Test-Path $Path)) {$NewLogFile = New-Item $Path -Force -ItemType File             } 
      else{} 
 
   # Format Date for our Log File 
      $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
   # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
} 


    (
    [Parameter(Mandatory=$true)]
    [ValidateSet('Production','Maintenance')]
    [string]$rDWPMode)


function Get-rDWPMode
{

$rDWPRegPath = "HKLM:\Software\ACN\rDWPMode\"
$rDWPCmode = "CurrentrDWPMode"
$mModeVal = "Maintenance"
$pModeVal = "Production"

If(!(Test-Path $rDWPRegPath)){
    New-Item -Path $rDWPRegPath -Force | Out-Null
    New-ItemProperty -Path $rDWPRegPath -Name $rDWPCmode -Value "None" | Out-Null }

Else{
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

function block-mmcsnapins
{

$mmckeyname = "RestrictToPermittedSnapins"
$mmckeyvalue = "1"


$drive = (Get-Location).Drive.Root
$users = Get-ChildItem "$($drive)Users"


# For each user, load and edit their registry
foreach ( $user in $users ) {


    If( $user.Name -ne $env:username ) {
        reg.exe LOAD HKU\Temp "$($drive)Users\$($user.Name)\NTUSER.DAT"
        $regmmc = "Registry::HKEY_USERS\Temp\Software\Policies\Microsoft\MMC"}

    Else{$regmmc = "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC"}


   If(!(Test-Path $regmmc)){
        New-Item -Path $regmmc -Force | Out-Null
        New-ItemProperty -Path $regmmc -Name $mmckeyname -Value $mmckeyvalue -Force| Out-Null

        Write-Log -Level Info -Message "mmc snap-ins blocked for user: $user"}

    Else{
       New-ItemProperty -Path $regmmc -Name $mmckeyname -Value $mmckeyvalue -Force | Out-Null
       Write-Log -Level Info -Message "mmc snap-ins blocked for user: $user"}
            
            
    # Unload user's hive
    if ( $user.Name -ne $env:username ) {
    [gc]::Collect()
    reg.exe UNLOAD HKU\Temp }
  }

  #Add key for "Default" users
    REG LOAD "HKU\thive" C:\users\default\ntuser.dat
    REG ADD "HKU\thive\Software\Policies\Microsoft\MMC" /v RestrictToPermittedSnapins /t REG_DWORD /d 1
    REG UNLOAD "HKU\thive"

}

function Enable-mmcsnapins
{

$mmckeyname = "RestrictToPermittedSnapins"
$mmckeyvalue = "1"


$drive = (Get-Location).Drive.Root
$users = Get-ChildItem "$($drive)Users"


# For each user, load and edit their registry
foreach ( $user in $users ) {


    If( $user.Name -ne $env:username ) {
        reg.exe LOAD HKU\Temp "$($drive)Users\$($user.Name)\NTUSER.DAT"
        $regmmc = "Registry::HKEY_USERS\Temp\Software\Policies\Microsoft\MMC"}

    Else{$regmmc = "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC"}


   If((Test-Path $regmmc)){
        Remove-ItemProperty -Path $regmmc -Name $mmckeyname -Force | Out-Null
        Write-Log -Level Info -Message "MMC snap-ins is enabled for user: $user"}

    Else{}
                   
            
    # Unload user's hive
    if ( $user.Name -ne $env:username ) {
    [gc]::Collect()
    reg.exe UNLOAD HKU\Temp }
  }

  #Remove key for "Default" users
    REG LOAD "HKU\thive" C:\users\default\ntuser.dat
    REG DELETE "HKU\thive\Software\Policies\Microsoft\MMC" /v RestrictToPermittedSnapins /f
    REG UNLOAD "HKU\thive"

}

function set-backgroundPMode
{


    # Get each folder under "Users"
$drive = (Get-Location).Drive.Root
$users = Get-ChildItem "$($drive)Users"


# For each user, load and edit their registry
foreach ( $user in $users ) {

  If( $user.Name -ne $env:username ) {
    reg.exe LOAD HKU\Temp "$($drive)Users\$($user.Name)\NTUSER.DAT"
    $dir = "Registry::HKEY_USERS\Temp\Control Panel\Desktop"}

   Else{
        $dir = "Registry::HKEY_CURRENT_USER\Control Panel\Desktop"}

if ( (Test-Path $dir) ) {
    Set-ItemProperty -Path $dir -Name "Wallpaper" -value "C:\ProgramData\Accenture\Siemens_rDWP_pMode.jpg" }

# Unload user's hive
    if ( $user.Name -ne $env:username ) {
    [gc]::Collect()
    reg.exe UNLOAD HKU\Temp }
}
     
    #Add key for "Default" users
    REG LOAD "HKU\temphive" C:\users\default\ntuser.dat
    REG ADD "HKU\temphive\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /t REG_SZ /d "C:\ProgramData\Accenture\Siemens_rDWP_pMode.jpg" /f
    REG ADD "HKU\temphive\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v WallpaperStyle /t REG_SZ /d 4 /f
    REG UNLOAD "HKU\temphive"


     Write-Log -Level Info -Message "Background image Set"
}

function set-backgroundMMode
{


    # Get each folder under "Users"
$drive = (Get-Location).Drive.Root
$users = Get-ChildItem "$($drive)Users"


# For each user, load and edit their registry
foreach ( $user in $users ) {

  If( $user.Name -ne $env:username ) {
    reg.exe LOAD HKU\Temp "$($drive)Users\$($user.Name)\NTUSER.DAT"
    $dir = "Registry::HKEY_USERS\Temp\Control Panel\Desktop"}

   Else{
        $dir = "Registry::HKEY_CURRENT_USER\Control Panel\Desktop"}

if ( (Test-Path $dir) ) {
    Set-ItemProperty -Path $dir -Name "Wallpaper" -value "C:\ProgramData\Accenture\Siemens_rDWP_mMode.jpg" }

# Unload user's hive
    if ( $user.Name -ne $env:username ) {
    [gc]::Collect()
    reg.exe UNLOAD HKU\Temp }
}
     
    #Add key for "Default" users
    REG LOAD "HKU\temphive" C:\users\default\ntuser.dat
    REG ADD "HKU\temphive\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /t REG_SZ /d "C:\ProgramData\Accenture\Siemens_rDWP_mMode.jpg" /f
    REG ADD "HKU\temphive\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v WallpaperStyle /t REG_SZ /d 4 /f
    REG UNLOAD "HKU\temphive"


     Write-Log -Level Info -Message "Background image Set"
}

Function Invoke-BalloonTip 
{

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,HelpMessage="The message text to display. Keep it short and simple.")]
        [string]$Message,

        [Parameter(HelpMessage="The message title")]
         [string]$Title="Attention $env:username",

        [Parameter(HelpMessage="The message type: Info,Error,Warning,None")]
        [System.Windows.Forms.ToolTipIcon]$MessageType="Info",
     
        [Parameter(HelpMessage="The path to a file to use its icon in the system tray")]
        [string]$SysTrayIconPath='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',     

        [Parameter(HelpMessage="The number of milliseconds to display the message.")]
        [int]$Duration=10000
    )

    Add-Type -AssemblyName System.Windows.Forms

    If (-NOT $global:balloon) {
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon

        #Mouse double click on icon to dispose
        [void](Register-ObjectEvent -InputObject $balloon -EventName MouseDoubleClick -SourceIdentifier IconClicked -Action {
            #Perform cleanup actions on balloon tip
            Write-Verbose 'Disposing of balloon'
            $global:balloon.dispose()
            Unregister-Event -SourceIdentifier IconClicked
            Remove-Job -Name IconClicked
            Remove-Variable -Name balloon -Scope Global
        })
    }

    #Need an icon for the tray
    $path = Get-Process -id $pid | Select-Object -ExpandProperty Path

    #Extract the icon from the file
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($SysTrayIconPath)

    #Can only use certain TipIcons: [System.Windows.Forms.ToolTipIcon] | Get-Member -Static -Type Property
    $balloon.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]$MessageType
    $balloon.BalloonTipText  = $Message
    $balloon.BalloonTipTitle = $Title
    $balloon.Visible = $true

    #Display the tip and specify in milliseconds on how long balloon will stay visible
    $balloon.ShowBalloonTip($Duration)

    Write-Verbose "Ending function"

}

Function Apply-NonAdminRestrictions
{

$Regpol = $PSScriptRoot + '\' + 'S-1-5-32-545'

   if(!(test-path 'C:\Windows\System32\GroupPolicyUsers\S-1-5-32-545\User\Registry.pol'))
    {
        try{
            Copy-Item $Regpol -Destination C:\Windows\System32\GroupPolicyUsers -Force -Recurse
            gpupdate /force
            Write-Log -Level Info -Message "Applied restriction for Non-admin users for cmd prompt, regedit, control panel, run...etc!"}
    
        catch{
            Write-Log -Level Error -Message "Error:$($_.Exception.Message)" }
    }
    else{}

}
 
#Get current rDWP mode for machine
Get-rDWPMode
$PrDWPMode = Get-rDWPMode


#Perform rDWP device configuration based on target mode   
If ($PrDWPMode -eq "None" -or $PrDWPMode -eq "Maintenance")
    {
    Write-Host "Current rDWP Mode: $PrDWPMode" -ForegroundColor Cyan
    Write-Host "Device is being configured for Production Mode" -ForegroundColor Green
    Write-Log -Level Info -Message "Device is being configured for Production Mode"

    #Block mmc snap-ins
    Write-Log -Level Info -Message "Blocking mmc snap-ins"
    block-mmcsnapins


    #Set desktop background
    Write-Log -Level Info -Message "Setting up desktop background"
    $PModejpg = $PSScriptRoot + '\' + 'Siemens_rDWP_pMode.jpg'
    copy-item -Path $PModejpg -Destination "C:\ProgramData\Accenture\" -Force
    set-backgroundPMode

    #Apply certain restrictions for non-admin user using local group policy
    Apply-NonAdminRestrictions


    Invoke-BalloonTip -Message "Device is being configured for Production Mode, Please restart system" -MessageType Warning
    #[reflection.assembly]::loadwithpartialname('System.Windows.Forms')
    #[reflection.assembly]::loadwithpartialname('System.Drawing')
    #$notify = new-object system.windows.forms.notifyicon
    #$notify.icon = [System.Drawing.SystemIcons]::Warning
    #$notify.visible = $true
    #$notify.showballoontip(10,'Attention Please..!','Device configured for Production Mode',[system.windows.forms.tooltipicon]::None)

    Set-ItemProperty -Path "HKLM:\Software\ACN\rDWPMode\" -Name "CurrentrDWPMode" -Value "Production" | Out-Null

    }
  
 Elseif($PrDWPMode -eq "Production"){
        Write-Host "Current rDWP Mode: $PrDWPMode" -ForegroundColor Cyan
        Write-Host "Device is being configured for Maintenance Mode" -ForegroundColor Green
        Write-Log -Level Info -Message "Device is being configured for Maintenance Mode"

    #Enable mmc snap-ins
    Write-Log -Level Info -Message "Enabling mmc snap-ins"
    Enable-mmcsnapins

    #Set desktop background
    Write-Log -Level Info -Message "Setting up desktop background"
    $PModejpg = $PSScriptRoot + '\' + 'Siemens_rDWP_mMode.jpg'
    copy-item -Path $PModejpg -Destination "C:\ProgramData\Accenture\" -Force
    set-backgroundMMode

    #Pop-up message
    Invoke-BalloonTip -Message "Device is being configured for Maintenance Mode, Please restart system" -MessageType Warning
    #[reflection.assembly]::loadwithpartialname('System.Windows.Forms')
    #[reflection.assembly]::loadwithpartialname('System.Drawing')
    #$notify = new-object system.windows.forms.notifyicon
    #$notify.icon = [System.Drawing.SystemIcons]::Warning
    #$notify.visible = $true
    #$notify.showballoontip(10,'Attention Please..!','Device configured for Maintenance Mode',[system.windows.forms.tooltipicon]::None)


    Set-ItemProperty -Path "HKLM:\Software\ACN\rDWPMode\" -Name "CurrentrDWPMode" -Value "Maintenance" | Out-Null

    }

 Else{Write-Host "Failed to identify current rDWP Mode, Script terminated..!!" -BackgroundColor Red
    Write-Log -Level Error -Message "Failed to identify current rDWP Mode, Script terminated..!!"
             
 Exit}

