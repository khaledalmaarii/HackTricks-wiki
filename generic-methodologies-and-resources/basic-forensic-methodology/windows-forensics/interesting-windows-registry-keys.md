# Interessante Windows-Registrierungsschlüssel

### Interessante Windows-Registrierungsschlüssel

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


### **Windows-Version und Eigentümerinformationen**
- Unter **`Software\Microsoft\Windows NT\CurrentVersion`** finden Sie die Windows-Version, den Service Pack, die Installationszeit und den Namen des registrierten Eigentümers auf einfache Weise.

### **Computername**
- Der Hostname befindet sich unter **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Zeitzoneneinstellung**
- Die Zeitzoneneinstellung des Systems wird in **`System\ControlSet001\Control\TimeZoneInformation`** gespeichert.

### **Zugriffszeitverfolgung**
- Standardmäßig ist die Verfolgung der letzten Zugriffszeit deaktiviert (**`NtfsDisableLastAccessUpdate=1`**). Um sie zu aktivieren, verwenden Sie:
`fsutil behavior set disablelastaccess 0`

### Windows-Versionen und Service Packs
- Die **Windows-Version** gibt die Edition (z. B. Home, Pro) und ihre Veröffentlichung (z. B. Windows 10, Windows 11) an, während **Service Packs** Updates sind, die Fehlerbehebungen und manchmal neue Funktionen enthalten.

### Aktivieren der letzten Zugriffszeit
- Durch das Aktivieren der Verfolgung der letzten Zugriffszeit können Sie sehen, wann Dateien zuletzt geöffnet wurden, was für forensische Analysen oder Systemüberwachung entscheidend sein kann.

### Netzwerkinformationsdetails
- Die Registrierung enthält umfangreiche Daten zu Netzwerkkonfigurationen, einschließlich **Arten von Netzwerken (drahtlos, Kabel, 3G)** und **Netzwerkkategorien (Öffentlich, Privat/Heim, Domäne/Arbeit)**, die für das Verständnis von Netzwerksicherheitseinstellungen und Berechtigungen wichtig sind.

### Clientseitiges Zwischenspeichern (CSC)
- **CSC** verbessert den Offline-Zugriff auf Dateien, indem Kopien freigegebener Dateien zwischengespeichert werden. Unterschiedliche **CSCFlags**-Einstellungen steuern, wie und welche Dateien zwischengespeichert werden, was sich auf Leistung und Benutzererfahrung auswirkt, insbesondere in Umgebungen mit intermittierender Konnektivität.

### Automatisch startende Programme
- Programme, die in verschiedenen `Run`- und `RunOnce`-Registrierungsschlüsseln aufgeführt sind, werden automatisch beim Start ausgeführt und beeinflussen die Systemstartzeit und können potenziell interessante Punkte zur Identifizierung von Malware oder unerwünschter Software sein.

### Shellbags
- **Shellbags** speichern nicht nur Einstellungen für Ordneransichten, sondern liefern auch forensische Beweise für den Zugriff auf Ordner, auch wenn der Ordner nicht mehr vorhanden ist. Sie sind für Untersuchungen von unschätzbarem Wert und zeigen Benutzeraktivitäten auf, die auf andere Weise nicht offensichtlich sind.

### USB-Informationen und Forensik
- Die im Registrierungsschlüssel gespeicherten Details zu USB-Geräten können dabei helfen, welche Geräte mit einem Computer verbunden waren, und möglicherweise eine Verbindung eines Geräts mit sensiblen Dateiübertragungen oder unbefugtem Zugriff herstellen.

### Volumeseriennummer
- Die **Volumeseriennummer** kann entscheidend sein, um die spezifische Instanz eines Dateisystems zu verfolgen, was in forensischen Szenarien nützlich ist, in denen der Dateiursprung über verschiedene Geräte hinweg ermittelt werden muss.

### **Shutdown-Details**
- Die Shutdown-Zeit und die Anzahl der Neustarts (nur für XP) werden in **`System\ControlSet001\Control\Windows`** und **`System\ControlSet001\Control\Watchdog\Display`** gespeichert.

### **Netzwerkkonfiguration**
- Für detaillierte Informationen zur Netzwerkschnittstelle siehe **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Erste und letzte Netzwerkverbindungsziten, einschließlich VPN-Verbindungen, werden unter verschiedenen Pfaden in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** protokolliert.

### **Freigegebene Ordner**
- Freigegebene Ordner und Einstellungen befinden sich unter **`System\ControlSet001\Services\lanmanserver\Shares`**. Die Einstellungen für das clientseitige Zwischenspeichern (CSC) bestimmen die Verfügbarkeit von Offline-Dateien.

### **Programme, die automatisch starten**
- Pfade wie **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** und ähnliche Einträge unter `Software\Microsoft\Windows\CurrentVersion` geben Auskunft über Programme, die beim Start ausgeführt werden sollen.

### **Suchen und eingegebene Pfade**
- Explorer-Suchen und eingegebene Pfade werden in der Registrierung unter **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** für WordwheelQuery und TypedPaths verfolgt.

### **Zuletzt verwendete Dokumente und Office-Dateien**
- Zuletzt verwendete Dokumente und aufgerufene Office-Dateien werden in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` und spezifischen Office-Version-Pfaden vermerkt.

### **Zuletzt verwendete (MRU) Elemente**
- MRU-Listen, die kürzlich verwendete Dateipfade und Befehle anzeigen, werden in verschiedenen `ComDlg32`- und `Explorer`-Unterschlüsseln unter `NTUSER.DAT` gespeichert.

### **Benutzeraktivitätsverfolgung**
- Die Funktion "User Assist" protokolliert detaillierte Statistiken zur Anwendungsnutzung, einschließlich der Anzahl der Ausführungen und der letzten Ausführungszeit, unter **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags-Analyse**
- Shellbags, die Details zum Zugriff auf Ordner anzeigen, werden in `USRCLASS.DAT` und `NTUSER.DAT` unter `Software\Microsoft\Windows\Shell` gespeichert. Verwenden Sie **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** zur Analyse.

### **USB-Geräteverlauf**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** und **`HKLM\SYSTEM\ControlSet001\Enum\USB`** enthalten umfangreiche Details zu angeschlossenen USB-Geräten, einschließlich Hersteller, Produktname und Verbindungszeitstempel.
- Der Benutzer, der mit einem bestimmten USB-Gerät verbunden ist, kann durch Suche in den `NTUSER.DAT`-Hives nach der **{GUID}** des Geräts ermittelt werden.
- Das zuletzt eingebundene Gerät und seine Volumeseriennummer können über `System\MountedDevices` bzw. `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` verfolgt
