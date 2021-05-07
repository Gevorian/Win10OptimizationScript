<#
MIT License
Copyright (c) 2021 Gevorian
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>
<#
Run this in powershell or you will be unable to use the script.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
You will have to manually add some values because they're bound to your internet adapters name in regedit.
In Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\(Whatever your internet adapter is, will contain your IP address)
Add 3 Dword 32 bit values with names (case sensitive)
-MTU             Value: 1470
-TcpNoDelay      Value: 1
-TcpAckFrequency Value: 1
#>
$tweaks = @(
    "RegistryOptimizations"
)
    $confirmation = Read-Host "How much ram do you have? (Integer Value only)"
    if ($confirmation -eq 4) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
    }

    elseif ($confirmation -eq 6) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 6291456
    }

    elseif ($confirmation -eq 8) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 8388608
    }

    elseif ($confirmation -eq 16) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 16777216
    }

    elseif ($confirmation -eq 24) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 25165824
    }

    elseif ($confirmation -eq 32) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 33554432
    }

    elseif ($confirmationn -eq 64) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 67108864
    }
#Reduced latency, optimizing GPU and CPU function, reduced internet lag.
Function RegistryOptimizations {
    Write-Host "Optimizing Registry..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 32
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SizReqBuf" -Type DWord -Value 17424
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 64
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TCP1323Opts" -Type DWord -Value 1
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxFreeTcbs" -Type DWord -Value 65536
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "GlobalMaxTcpWindowSize" -Type DWord -Value 65535
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettings" -Type DWord -Value 1
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Type DWord -Value 3
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type DWord -Value 3
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Type DWord -Value 0
    New-Item -Path "HKLM:SYSTEM\CurrentControlSet\Control\Power" -Name "PowerThrottling" -ItemType "directory"
    New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type DWord -Value High
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type DWord -Value High
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value ffffffff
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 00000000
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Type DWord -Value 0
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type DWord -Value 0
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type DWord -Value 0
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type DWord -Value 0
    New-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Type DWord -Value 1
}
##########
# Parse parameters and apply tweaks
##########
$confirmation = Read-Host "If you're sure you want to run this, press y and ENTER. If not, just press ENTER to cancel."
if ($confirmation -ne 'y') {
    Write-Host
    Write-Host "Cancelled script execution."
    exit
}
Write-Host
Write-Host "Let's roll!"
# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}
# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
