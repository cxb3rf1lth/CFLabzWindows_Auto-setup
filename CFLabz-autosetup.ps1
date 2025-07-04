#!/usr/bin/env pwsh

Param(
    [string]$AutoLoginUser = "",
    [string]$AutoLoginPass = "",
    [switch]$ForceAutoLogin,
    [switch]$Silent,
    [switch]$SkipWSL,
    [switch]$InstallSecurityTools
)

$ErrorActionPreference = 'Stop'
$LogPath = "C:\ZedSecLogs"
$ToolsPath = "C:\ZedSecTools"
$ZedRepo = "https://github.com/cxb3rf1lth"
$ProgressPreference = 'SilentlyContinue'

function Log($msg) {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp :: $msg" | Out-File "$LogPath\install.log" -Append
    if (-not $Silent) { Write-Host "$msg" -ForegroundColor Cyan }
}

function Init-Env {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    New-Item -Path $ToolsPath -ItemType Directory -Force | Out-Null
    Log "[+] Environment initialized."
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "[-] This script must be run as Administrator."
        exit 1
    }
    if (!(Test-Connection -ComputerName google.com -Count 1 -Quiet)) {
        Write-Error "[-] Internet connection is required."
        exit 1
    }
}

function Disable-WindowsSecurity {
    Log "[+] Disabling Defender, Firewall, SmartScreen, UAC, telemetry..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    } catch { Log "[!] Defender settings skipped or already disabled." }

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\SmartScreen" -Name "EnableSmartScreen" -Value 0 -Force
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    } catch { Log "[!] Registry hardening failed or already applied." }
    Log "[+] Security features disabled."
}

function Install-Choco {
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Log "[+] Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    Log "[+] Chocolatey is ready."
}

function Install-CoreTools {
    Log "[+] Installing core tools via Chocolatey..."
    $pkgs = @("python", "git", "windows-terminal", "nmap", "wireshark", "vscode", "7zip", "notepadplusplus", "processhacker")
    foreach ($pkg in $pkgs) {
        if (-not (choco list --localonly | Where-Object { $_ -match $pkg })) {
            choco install $pkg -y --no-progress
        }
    }
    & "$env:ChocolateyInstall\helpers\refreshenv.cmd"
    Log "[+] Core tools installed."
}

function Install-PwshModules {
    Log "[+] Installing PowerShell modules..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module PSReadLine -Force -Scope CurrentUser -AllowClobber
    Install-Module oh-my-posh -Force -Scope CurrentUser -AllowClobber
    Log "[+] PowerShell modules installed."
}

function Setup-WSL-Kali {
    if ($SkipWSL) { Log "[~] Skipping WSL+Kali setup."; return }
    Log "[+] Setting up WSL2 with Kali..."
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
    $msiPath = "$env:TEMP\wsl_update.msi"
    Invoke-WebRequest -Uri "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi" -OutFile $msiPath
    Start-Process -FilePath msiexec.exe -Wait -ArgumentList "/i $msiPath /quiet"
    wsl --set-default-version 2
    $kaliAvailable = wsl --list --online | Select-String -Pattern "kali"
    if ($kaliAvailable) { wsl --install -d kali-linux }
    Log "[+] Kali installed in WSL."
}

function Clone-ZedSecRepo {
    Log "[+] Cloning ZedSec GitHub repo..."
    $destPath = "$ToolsPath\ZedSecLabz"
    if (!(Test-Path $destPath)) {
        git clone $ZedRepo $destPath
    }
    Log "[+] Repository cloned."
}

function Setup-AutoLogin {
    if ($AutoLoginUser -and $AutoLoginPass -and $ForceAutoLogin) {
        Log "[+] Enabling auto-login for $AutoLoginUser"
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon" -Value "1"
        Set-ItemProperty -Path $RegPath -Name "DefaultUsername" -Value $AutoLoginUser
        Set-ItemProperty -Path $RegPath -Name "DefaultPassword" -Value $AutoLoginPass
        Log "[+] Auto-login configured."
    } else {
        Log "[~] Auto-login not configured (missing params or flag)."
    }
}

function Install-SecurityTools {
    if ($InstallSecurityTools) {
        Log "[+] Installing red/blue team tools..."
        $secPath = "$ToolsPath\Security"
        New-Item -Path $secPath -ItemType Directory -Force | Out-Null
        $secTools = @(
            @{name="BloodHound-win32-x64.zip"; url="https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-win32-x64.zip"},
            @{name="SharpHound.exe"; url="https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe"},
            @{name="PowerView.ps1"; url="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"}
        )
        foreach ($tool in $secTools) {
            $dest = Join-Path -Path $secPath -ChildPath $tool.name
            Invoke-WebRequest -Uri $tool.url -OutFile $dest -UseBasicParsing -ErrorAction SilentlyContinue
        }
        Log "[+] Security tools downloaded."
    }
}

function Finalize-And-Reboot {
    Log "[+] Rebooting in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer
}

Init-Env
Disable-WindowsSecurity
Install-Choco
Install-CoreTools
Install-PwshModules
Setup-WSL-Kali
Clone-ZedSecRepo
Setup-AutoLogin
Install-SecurityTools
Finalize-And-Reboot
