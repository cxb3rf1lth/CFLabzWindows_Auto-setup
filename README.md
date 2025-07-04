# CFLabzWindows_installer
A full-spectrum, auto-deploying PowerShell script to prep a Windows box for red teaming, blue teaming, SOC analysis, and Kali-WSL2 integration.

## 🚀 Features
- Disables Windows Defender, firewall, SmartScreen, UAC
- Installs Chocolatey + core tools (Git, Python, VSCode, Nmap, etc.)
- Sets up Kali Linux with WSL2
- Installs PowerShell modules (oh-my-posh, PSReadLine)
- Configures auto-login (optional)
- Downloads red/blue tools: BloodHound, SharpHound, PowerView
- Logs everything to `C:\ZedSecLogs\install.log`

## 📦 Requirements
- Windows 10/11
- Admin rights
- Internet access
- Git 

## 🛠️ Installation
(You can also download the zip file and extract the script files onto your desktop and then just run the script and commands in powershell as admin instead of git clone)
1. Open PowerShell as Administrator
2. Run:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
git clone https://github.com/cxb3rf1lth/CFLabzWindows_installer
CFLabZ_autosetup.ps1  -AutoLoginUser "YourUser" -AutoLoginPass "YourPass" -ForceAutoLogin -InstallSecurityTools
