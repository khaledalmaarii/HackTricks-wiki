# WmicExec

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## Funktionsweise erklärt

Prozesse können auf Hosts geöffnet werden, bei denen der Benutzername und entweder das Passwort oder der Hash bekannt sind, indem WMI verwendet wird. Befehle werden mit WMI durch Wmiexec ausgeführt und bieten eine halbinteraktive Shell-Erfahrung.

**dcomexec.py:** Mit verschiedenen DCOM-Endpunkten bietet dieses Skript eine halbinteraktive Shell ähnlich wie wmiexec.py und nutzt speziell das ShellBrowserWindow DCOM-Objekt. Es unterstützt derzeit MMC20. Anwendung, Shell Windows und Shell Browser Window Objekte. (Quelle: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI-Grundlagen

### Namespace

Strukturiert in einer verzeichnisähnlichen Hierarchie ist der oberste Container von WMI \root, unter dem zusätzliche Verzeichnisse, die als Namespaces bezeichnet werden, organisiert sind.
Befehle zum Auflisten von Namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klassen innerhalb eines Namensraums können mit folgendem Befehl aufgelistet werden:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klassen**

Das Wissen um den Namen einer WMI-Klasse, wie z.B. win32\_process, und den Namespace, in dem sie sich befindet, ist für jede WMI-Operation entscheidend.
Befehle zum Auflisten von Klassen, die mit `win32` beginnen:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Aufruf einer Klasse:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methoden

Methoden, die eine oder mehrere ausführbare Funktionen von WMI-Klassen sind, können ausgeführt werden.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI-Enumeration

### WMI-Dienststatus

Befehle zur Überprüfung, ob der WMI-Dienst betriebsbereit ist:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### System- und Prozessinformationen

Sammeln von System- und Prozessinformationen über WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Für Angreifer ist WMI ein mächtiges Werkzeug, um sensible Daten über Systeme oder Domänen zu ermitteln.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Manuelle Remote-WMI-Abfrage**

Eine unauffällige Identifizierung von lokalen Administratoren auf einem Remote-Rechner und angemeldeten Benutzern kann durch spezifische WMI-Abfragen erreicht werden. `wmic` unterstützt auch das Lesen aus einer Textdatei, um Befehle gleichzeitig auf mehreren Knoten auszuführen.

Um einen Prozess über WMI remote auszuführen, wie z.B. das Bereitstellen eines Empire-Agenten, wird die folgende Befehlsstruktur verwendet. Eine erfolgreiche Ausführung wird durch einen Rückgabewert von "0" angezeigt:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Dieser Prozess veranschaulicht die Fähigkeit von WMI zur Remote-Ausführung und Systemenumeration und hebt seine Nützlichkeit sowohl für die Systemverwaltung als auch für Penetrationstests hervor.


## Referenzen
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatische Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
