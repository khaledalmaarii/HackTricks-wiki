# Interessante Windows-Registrierungsschlüssel

### Interessante Windows-Registrierungsschlüssel

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
{% endhint %}


### **Windows-Version und Eigentümerinformationen**
- Unter **`Software\Microsoft\Windows NT\CurrentVersion`** finden Sie die Windows-Version, das Service Pack, die Installationszeit und den Namen des registrierten Eigentümers auf einfache Weise.

### **Computername**
- Der Hostname befindet sich unter **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Zeitzoneneinstellung**
- Die Zeitzoneneinstellung des Systems wird unter **`System\ControlSet001\Control\TimeZoneInformation`** gespeichert.

### **Zugriffszeitverfolgung**
- Standardmäßig ist die Verfolgung der letzten Zugriffszeit deaktiviert (**`NtfsDisableLastAccessUpdate=1`**). Um sie zu aktivieren, verwenden Sie:
`fsutil behavior set disablelastaccess 0`

### Windows-Versionen und Service Packs
- Die **Windows-Version** gibt die Edition an (z. B. Home, Pro) und ihre Veröffentlichung (z. B. Windows 10, Windows 11) an, während **Service Packs** Updates sind, die Fixes und manchmal neue Funktionen enthalten.

### Aktivieren der letzten Zugriffszeit
- Das Aktivieren der Verfolgung der letzten Zugriffszeit ermöglicht es Ihnen zu sehen, wann Dateien zuletzt geöffnet wurden, was für forensische Analysen oder Systemüberwachung entscheidend sein kann.

### Netzwerkinformationsdetails
- Die Registrierung enthält umfangreiche Daten zu Netzwerkkonfigurationen, einschließlich **Arten von Netzwerken (drahtlos, Kabel, 3G)** und **Netzwerkkategorien (Öffentlich, Privat/Zuhause, Domäne/Arbeit)**, die für das Verständnis von Netzwerksicherheitseinstellungen und Berechtigungen wichtig sind.

### Client-seitiges Caching (CSC)
- **CSC** verbessert den Offline-Zugriff auf Dateien, indem Kopien gemeinsam genutzter Dateien zwischengespeichert werden. Unterschiedliche **CSCFlags**-Einstellungen steuern, wie und welche Dateien zwischengespeichert werden, was die Leistung und Benutzererfahrung beeinflusst, insbesondere in Umgebungen mit intermittierender Konnektivität.

### Automatisch startende Programme
- Programme, die in verschiedenen `Run`- und `RunOnce`-Registrierungsschlüsseln aufgeführt sind, werden automatisch beim Start ausgeführt, was die Systemstartzeit beeinflusst und potenziell interessante Punkte zur Identifizierung von Malware oder unerwünschter Software sein kann.

### Shellbags
- **Shellbags** speichern nicht nur Einstellungen für Ordneransichten, sondern liefern auch forensische Beweise für den Zugriff auf Ordner, auch wenn der Ordner nicht mehr existiert. Sie sind für Untersuchungen von unschätzbarem Wert und zeigen Benutzeraktivitäten auf, die auf andere Weise nicht offensichtlich sind.

### USB-Informationen und Forensik
- Die im Registrierungsspeicher gespeicherten Details zu USB-Geräten können dabei helfen, festzustellen, welche Geräte mit einem Computer verbunden waren, und möglicherweise eine Verbindung eines Geräts zu sensiblen Dateiübertragungen oder unbefugten Zugriffsvorfällen herstellen.

### Volumenseriennummer
- Die **Volumenseriennummer** kann entscheidend sein, um die spezifische Instanz eines Dateisystems zu verfolgen, was in forensischen Szenarien nützlich ist, in denen die Herkunft einer Datei über verschiedene Geräte hinweg festgestellt werden muss.

### **Herunterfahrdetails**
- Herunterfahrzeit und -anzahl (letztere nur für XP) werden in **`System\ControlSet001\Control\Windows`** und **`System\ControlSet001\Control\Watchdog\Display`** aufbewahrt.

### **Netzwerkkonfiguration**
- Für detaillierte Informationen zur Netzwerkschnittstelle siehe **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Erste und letzte Netzwerkverbindungsziten, einschließlich VPN-Verbindungen, werden unter verschiedenen Pfaden in **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** protokolliert.

### **Freigegebene Ordner**
- Freigegebene Ordner und Einstellungen befinden sich unter **`System\ControlSet001\Services\lanmanserver\Shares`**. Die Einstellungen für das Client-seitige Caching (CSC) bestimmen die Verfügbarkeit von Offline-Dateien.

### **Programme, die automatisch starten**
- Pfade wie **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** und ähnliche Einträge unter `Software\Microsoft\Windows\CurrentVersion` geben Details zu Programmen, die beim Start ausgeführt werden sollen.

### **Suchen und eingegebene Pfade**
- Explorer-Suchen und eingegebene Pfade werden in der Registrierung unter **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** für WordwheelQuery und TypedPaths verfolgt.

### **Zuletzt verwendete Dokumente und Office-Dateien**
- Zuletzt verwendete Dokumente und Office-Dateien werden in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` und spezifischen Office-Version-Pfaden vermerkt.

### **Zuletzt verwendete (MRU) Elemente**
- MRU-Listen, die kürzlich verwendete Dateipfade und Befehle anzeigen, werden in verschiedenen `ComDlg32`- und `Explorer`-Unterschlüsseln unter `NTUSER.DAT` gespeichert.

### **Benutzeraktivitätsverfolgung**
- Das User Assist-Feature protokolliert detaillierte Anwendungsstatistiken, einschließlich Ausführungszähler und letzter Ausführungszeit, unter **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags-Analyse**
- Shellbags, die Details zum Ordnerzugriff anzeigen, werden in `USRCLASS.DAT` und `NTUSER.DAT` unter `Software\Microsoft\Windows\Shell` gespeichert. Verwenden Sie **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** für die Analyse.

### **USB-Gerätehistorie**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** und **`HKLM\SYSTEM\ControlSet001\Enum\USB`** enthalten umfangreiche Details zu angeschlossenen USB-Geräten, einschließlich Hersteller, Produktname und Verbindungszeitstempel.
- Der Benutzer, der mit einem bestimmten USB-Gerät verbunden ist, kann durch Suche in den `NTUSER.DAT`-Hives nach der **{GUID}** des Geräts ermittelt werden.
- Das zuletzt eingebundene Gerät und seine Volumenseriennummer können über `System\MountedDevices` und `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` zurückverfolgt werden.

Dieser Leitfaden fasst die wesentlichen Pfade und Methoden zur Zugriff auf detaillierte Informationen zu Systemen, Netzwerken und Benutzeraktivitäten auf Windows-Systemen zusammen, mit dem Ziel von Klarheit und Benutzerfreundlichkeit.



{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
{% endhint %}
