# WmiExec

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Wie es funktioniert

Prozesse können auf Hosts geöffnet werden, bei denen der Benutzername und entweder das Passwort oder der Hash bekannt sind, durch die Verwendung von WMI. Befehle werden über WMI von Wmiexec ausgeführt, was ein semi-interaktives Shell-Erlebnis bietet.

**dcomexec.py:** Durch die Nutzung verschiedener DCOM-Endpunkte bietet dieses Skript eine semi-interaktive Shell ähnlich wie wmiexec.py, wobei speziell das ShellBrowserWindow DCOM-Objekt verwendet wird. Es unterstützt derzeit MMC20. Anwendungs-, Shell-Fenster- und Shell-Browser-Fensterobjekte. (Quelle: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI-Grundlagen

### Namespace

Strukturiert in einer hierarchischen Verzeichnisstruktur ist WMI's oberster Container \root, unter dem zusätzliche Verzeichnisse, die als Namespaces bezeichnet werden, organisiert sind.  
Befehle zum Auflisten von Namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klassen innerhalb eines Namensraums können aufgelistet werden mit:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klassen**

Das Wissen um einen WMI-Klassennamen, wie z.B. win32\_process, und den Namespace, in dem er sich befindet, ist entscheidend für jede WMI-Operation.  
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
## WMI Enumeration

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
Für Angreifer ist WMI ein leistungsfähiges Werkzeug zur Auflistung sensibler Daten über Systeme oder Domänen.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Remote-Abfragen von WMI nach spezifischen Informationen, wie lokalen Administratoren oder angemeldeten Benutzern, sind mit sorgfältiger Befehlskonstruktion machbar.

### **Manuelle Remote-WMI-Abfragen**

Die heimliche Identifizierung von lokalen Administratoren auf einem Remote-Computer und angemeldeten Benutzern kann durch spezifische WMI-Abfragen erreicht werden. `wmic` unterstützt auch das Lesen aus einer Textdatei, um Befehle gleichzeitig auf mehreren Knoten auszuführen.

Um einen Prozess über WMI remote auszuführen, wie das Bereitstellen eines Empire-Agenten, wird die folgende Befehlsstruktur verwendet, wobei eine erfolgreiche Ausführung durch einen Rückgabewert von "0" angezeigt wird:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Dieser Prozess veranschaulicht die Fähigkeit von WMI zur Remote-Ausführung und Systemenumeration und hebt seinen Nutzen sowohl für die Systemadministration als auch für das Pentesting hervor.

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
