# WindowsProtectionScript
This PowerShell script enhances security and optimizes Windows performance by enabling "God Mode," configuring the firewall, applying secure WiFi settings, disabling automatic updates, and cleaning up hidden files. It also disables potentially unwanted network components to strengthen privacy and system protection.

## Prerequisites

Before running the script, ensure you have the **PsExec** tool installed. PsExec allows you to execute commands as the SYSTEM user, granting necessary permissions for full script execution.

## Steps to Run the Script

### 1. Download PsExec
[Download PsExec from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) and extract it to a known location.

### 2. Open a System-Level PowerShell Session
Run the following command in **Command Prompt (cmd)** with administrator privileges:

```powershell
& PsExec.exe -i -s powershell


