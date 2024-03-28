# macOS Kernel & Systemerweiterungen

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## XNU-Kernel

Der **Kern von macOS ist XNU**, was für "X is Not Unix" steht. Dieser Kernel besteht grundlegend aus dem **Mach-Mikrokernel** (später diskutiert) **und** Elementen aus der Berkeley Software Distribution (**BSD**). XNU bietet auch eine Plattform für **Kernel-Treiber über ein System namens I/O Kit**. Der XNU-Kernel ist Teil des Darwin Open Source-Projekts, was bedeutet, dass **sein Quellcode frei zugänglich ist**.

Aus der Perspektive eines Sicherheitsforschers oder eines Unix-Entwicklers kann sich **macOS** ziemlich **ähnlich** zu einem **FreeBSD**-System mit einer eleganten GUI und einer Vielzahl von benutzerdefinierten Anwendungen anfühlen. Die meisten für BSD entwickelten Anwendungen können ohne Änderungen auf macOS kompiliert und ausgeführt werden, da die den Unix-Benutzern vertrauten Befehlszeilentools alle in macOS vorhanden sind. Da der XNU-Kernel jedoch Mach integriert, gibt es einige signifikante Unterschiede zwischen einem traditionellen Unix-ähnlichen System und macOS, und diese Unterschiede können potenzielle Probleme verursachen oder einzigartige Vorteile bieten.

Open-Source-Version von XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ist ein **Mikrokernel**, der darauf ausgelegt ist, **UNIX-kompatibel** zu sein. Eines seiner wichtigsten Designprinzipien war es, die Menge an **Code** im **Kernel**-Raum zu **minimieren** und stattdessen viele typische Kernel-Funktionen wie Dateisystem, Netzwerk und I/O als Benutzeraufgaben auszuführen.

In XNU ist Mach **für viele der kritischen Low-Level-Operationen** verantwortlich, die ein Kernel typischerweise handhabt, wie Prozessorplanung, Multitasking und virtuelle Speicherverwaltung.

### BSD

Der XNU **Kernel** **integriert** auch eine signifikante Menge an Code, der aus dem **FreeBSD**-Projekt abgeleitet ist. Dieser Code **läuft als Teil des Kernels zusammen mit Mach** im gleichen Adressraum. Der FreeBSD-Code innerhalb von XNU kann jedoch erheblich vom ursprünglichen FreeBSD-Code abweichen, da Änderungen erforderlich waren, um seine Kompatibilität mit Mach sicherzustellen. FreeBSD trägt zu vielen Kerneloperationen bei, darunter:

* Prozessverwaltung
* Signalbehandlung
* Grundlegende Sicherheitsmechanismen, einschließlich Benutzer- und Gruppenverwaltung
* Systemaufrufinfrastruktur
* TCP/IP-Stack und Sockets
* Firewall und Paketfilterung

Das Verständnis der Interaktion zwischen BSD und Mach kann aufgrund ihrer unterschiedlichen konzeptionellen Rahmenbedingungen komplex sein. Zum Beispiel verwendet BSD Prozesse als seine grundlegende Ausführungseinheit, während Mach auf Threads basiert. Dieser Unterschied wird in XNU dadurch gelöst, dass **jedem BSD-Prozess eine Mach-Aufgabe zugeordnet wird**, die genau einen Mach-Thread enthält. Wenn der BSD-Befehl fork() verwendet wird, verwendet der BSD-Code im Kernel Mach-Funktionen, um eine Aufgabe und eine Thread-Struktur zu erstellen.

Darüber hinaus **verwalten Mach und BSD jeweils unterschiedliche Sicherheitsmodelle**: Das Sicherheitsmodell von **Mach** basiert auf **Portrechten**, während das Sicherheitsmodell von BSD auf **Prozessbesitz** basiert. Unterschiede zwischen diesen beiden Modellen haben gelegentlich zu lokalen Privileg-Eskalations-Schwachstellen geführt. Neben typischen Systemaufrufen gibt es auch **Mach-Traps, die es Benutzerprogrammen ermöglichen, mit dem Kernel zu interagieren**. Diese verschiedenen Elemente bilden zusammen die vielschichtige, hybride Architektur des macOS-Kernels.

### I/O Kit - Treiber

Das I/O Kit ist ein Open-Source, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel, das **dynamisch geladene Gerätetreiber** verwaltet. Es ermöglicht die Hinzufügung modularer Codes zum Kernel im laufenden Betrieb und unterstützt verschiedene Hardware.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Interprozesskommunikation

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Der **Kernelcache** ist eine **vorab kompilierte und vorverknüpfte Version des XNU-Kernels** zusammen mit wichtigen Gerätetreibern und Kernelerweiterungen. Er wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Speicher dekomprimiert. Der Kernelcache ermöglicht eine **schnellere Bootzeit**, indem eine betriebsbereite Version des Kernels und wichtige Treiber verfügbar sind, was die Zeit und Ressourcen reduziert, die sonst für das dynamische Laden und Verknüpfen dieser Komponenten beim Booten aufgewendet würden.

In iOS befindet er sich in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. In macOS können Sie ihn mit **`find / -name kernelcache 2>/dev/null`** oder **`mdfind kernelcache | grep kernelcache`** finden.

Es ist möglich, **`kextstat`** auszuführen, um die geladenen Kernelerweiterungen zu überprüfen.

#### IMG4

Das IMG4-Dateiformat ist ein Containerformat, das von Apple in seinen iOS- und macOS-Geräten zum sicheren **Speichern und Überprüfen von Firmware**-Komponenten (wie **Kernelcache**) verwendet wird. Das IMG4-Format enthält einen Header und mehrere Tags, die verschiedene Datenstücke einschließen, einschließlich des eigentlichen Payloads (wie ein Kernel oder Bootloader), einer Signatur und einer Reihe von Manifesteigenschaften. Das Format unterstützt die kryptografische Überprüfung, die es dem Gerät ermöglicht, die Echtheit und Integrität der Firmware-Komponente vor der Ausführung zu bestätigen.

Es besteht normalerweise aus den folgenden Komponenten:

* **Payload (IM4P)**:
* Oft komprimiert (LZFSE4, LZSS, …)
* Optional verschlüsselt
* **Manifest (IM4M)**:
* Enthält Signatur
* Zusätzliches Schlüssel/Wert-Verzeichnis
* **Wiederherstellungsinformationen (IM4R)**:
* Auch bekannt als APNonce
* Verhindert das Wiederholen einiger Updates
* OPTIONAL: Normalerweise nicht gefunden

Dekomprimieren des Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Kernelcache Symbole

Manchmal veröffentlicht Apple **Kernelcache** mit **Symbolen**. Sie können einige Firmware mit Symbolen herunterladen, indem Sie den Links auf [https://theapplewiki.com](https://theapplewiki.com/) folgen.

### IPSW

Dies sind Apple **Firmware**, die Sie von [**https://ipsw.me/**](https://ipsw.me/) herunterladen können. Unter anderem enthält es den **Kernelcache**.\
Um die Dateien zu **extrahieren**, können Sie sie einfach **entzippen**.

Nach dem Extrahieren der Firmware erhalten Sie eine Datei wie: **`kernelcache.release.iphone14`**. Es ist im **IMG4**-Format, Sie können die interessanten Informationen extrahieren mit:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Sie können das extrahierte Kernelcache auf Symbole überprüfen mit: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Damit können wir jetzt **alle Erweiterungen** extrahieren oder die **eine, an der Sie interessiert sind:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS Kernel-Erweiterungen

macOS ist **sehr restriktiv beim Laden von Kernel-Erweiterungen** (.kext), aufgrund der hohen Privilegien, mit denen der Code ausgeführt wird. Tatsächlich ist es standardmäßig praktisch unmöglich (es sei denn, es wird ein Umgehungsweg gefunden).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS-Systemerweiterungen

Anstatt Kernel-Erweiterungen zu verwenden, hat macOS die Systemerweiterungen erstellt, die APIs auf Benutzerebene bieten, um mit dem Kernel zu interagieren. Auf diese Weise können Entwickler den Einsatz von Kernel-Erweiterungen vermeiden.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referenzen

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
