# macOS Systemerweiterungen

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Systemerweiterungen / Endpoint-Sicherheitsframework

Im Gegensatz zu Kernelerweiterungen **laufen Systemerweiterungen im Benutzerbereich** anstelle des Kernelbereichs, was das Risiko eines Systemabsturzes aufgrund einer Erweiterungsfehlfunktion verringert.

<figure><img src="../../../.gitbook/assets/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Es gibt drei Arten von Systemerweiterungen: **DriverKit**-Erweiterungen, **Netzwerk**-Erweiterungen und **Endpoint-Sicherheits**-Erweiterungen.

### **DriverKit-Erweiterungen**

DriverKit ist ein Ersatz für Kernelerweiterungen, der **Hardwareunterstützung bereitstellt**. Es ermöglicht, dass Gerätetreiber (wie USB-, Seriell-, NIC- und HID-Treiber) im Benutzerbereich anstelle des Kernelbereichs ausgeführt werden. Das DriverKit-Framework enthält **Benutzerbereichsversionen bestimmter I/O Kit-Klassen**, und der Kernel leitet normale I/O Kit-Ereignisse an den Benutzerbereich weiter, was eine sicherere Umgebung für diese Treiber bietet.

### **Netzwerk-Erweiterungen**

Netzwerk-Erweiterungen bieten die Möglichkeit, Netzwerkverhalten anzupassen. Es gibt verschiedene Arten von Netzwerk-Erweiterungen:

* **App-Proxy**: Dies wird verwendet, um einen VPN-Client zu erstellen, der ein flussorientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Dies bedeutet, dass er Netzwerkverkehr basierend auf Verbindungen (oder Flüssen) und nicht auf einzelnen Paketen verarbeitet.
* **Paket-Tunnel**: Dies wird verwendet, um einen VPN-Client zu erstellen, der ein paketorientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Dies bedeutet, dass er Netzwerkverkehr basierend auf einzelnen Paketen verarbeitet.
* **Datenfilter**: Dies wird verwendet, um Netzwerk "Flüsse" zu filtern. Es kann Netzwerkdaten auf Flussebene überwachen oder ändern.
* **Paketfilter**: Dies wird verwendet, um einzelne Netzwerkpakete zu filtern. Es kann Netzwerkdaten auf Paketebene überwachen oder ändern.
* **DNS-Proxy**: Dies wird verwendet, um einen benutzerdefinierten DNS-Anbieter zu erstellen. Es kann verwendet werden, um DNS-Anfragen und -Antworten zu überwachen oder zu ändern.

## Endpoint-Sicherheitsframework

Endpoint Security ist ein von Apple in macOS bereitgestelltes Framework, das eine Reihe von APIs für die Systemsicherheit bietet. Es ist für die Verwendung durch **Sicherheitsanbieter und Entwickler konzipiert, um Produkte zu erstellen, die die Systemaktivität überwachen und steuern** und so bösartige Aktivitäten erkennen und schützen können.

Dieses Framework bietet eine **Sammlung von APIs zur Überwachung und Steuerung der Systemaktivität**, wie z. B. Prozessausführungen, Dateisystemereignisse, Netzwerk- und Kernelereignisse.

Der Kern dieses Frameworks ist im Kernel implementiert, als Kernelerweiterung (KEXT) unter **`/System/Library/Extensions/EndpointSecurity.kext`**. Diese KEXT besteht aus mehreren Schlüsselkomponenten:

* **EndpointSecurityDriver**: Dies fungiert als "Einstiegspunkt" für die Kernelerweiterung. Es ist der Hauptinteraktionspunkt zwischen dem Betriebssystem und dem Endpoint-Sicherheitsframework.
* **EndpointSecurityEventManager**: Diese Komponente ist dafür verantwortlich, Kernelhaken zu implementieren. Kernelhaken ermöglichen es dem Framework, Systemereignisse zu überwachen, indem Systemaufrufe abgefangen werden.
* **EndpointSecurityClientManager**: Dies verwaltet die Kommunikation mit Benutzerbereichsclients, um zu verfolgen, welche Clients verbunden sind und Ereignisbenachrichtigungen erhalten müssen.
* **EndpointSecurityMessageManager**: Dies sendet Nachrichten und Ereignisbenachrichtigungen an Benutzerbereichsclients.

Die Ereignisse, die das Endpoint-Sicherheitsframework überwachen kann, sind in folgende Kategorien unterteilt:

* Dateiereignisse
* Prozessereignisse
* Socketereignisse
* Kernelereignisse (wie Laden/Entladen einer Kernelerweiterung oder Öffnen eines I/O Kit-Geräts)

### Architektur des Endpoint-Sicherheitsframeworks

<figure><img src="../../../.gitbook/assets/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Die **Kommunikation im Benutzerbereich** mit dem Endpoint-Sicherheitsframework erfolgt über die Klasse IOUserClient. Es werden zwei verschiedene Unterklassen verwendet, abhängig vom Typ des Aufrufers:

* **EndpointSecurityDriverClient**: Dies erfordert die Berechtigung `com.apple.private.endpoint-security.manager`, die nur vom Systemprozess `endpointsecurityd` gehalten wird.
* **EndpointSecurityExternalClient**: Dies erfordert die Berechtigung `com.apple.developer.endpoint-security.client`. Dies wird in der Regel von Sicherheitssoftware von Drittanbietern verwendet, die mit dem Endpoint-Sicherheitsframework interagieren muss.

Die Endpoint-Sicherheitserweiterungen:**`libEndpointSecurity.dylib`** ist die C-Bibliothek, die Systemerweiterungen zur Kommunikation mit dem Kernel verwenden. Diese Bibliothek verwendet das I/O Kit (`IOKit`), um mit der Endpoint-Sicherheits-KEXT zu kommunizieren.

**`endpointsecurityd`** ist ein wichtiger Systemdaemon, der an der Verwaltung und dem Starten von Endpoint-Sicherheitssystemerweiterungen beteiligt ist, insbesondere während des frühen Bootvorgangs. **Nur Systemerweiterungen**, die in ihrer `Info.plist`-Datei mit **`NSEndpointSecurityEarlyBoot`** markiert sind, erhalten diese frühe Bootbehandlung.

Ein weiterer Systemdaemon, **`sysextd`**, **validiert Systemerweiterungen** und verschiebt sie an die richtigen Systempositionen. Anschließend fordert er den relevanten Daemon auf, die Erweiterung zu laden. Das **`SystemExtensions.framework`** ist für das Aktivieren und Deaktivieren von Systemerweiterungen verantwortlich.

## Umgehung von ESF

ESF wird von Sicherheitstools verwendet, die versuchen, einen Red Teamer zu erkennen, daher klingt jede Information darüber, wie dies vermieden werden könnte, interessant.

### CVE-2021-30965

Die Sache ist, dass die Sicherheitsanwendung **Vollzugriff auf das Laufwerk benötigt**. Wenn ein Angreifer das entfernen könnte, könnte er verhindern, dass die Software ausgeführt wird:
```bash
tccutil reset All
```
Für **weitere Informationen** zu diesem Umgehungstrick und verwandten Themen, schauen Sie sich den Vortrag [#OBTS v5.0: "Die Achillesferse der Endpunktsicherheit" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) an.

Am Ende wurde dies behoben, indem der neuen Berechtigung **`kTCCServiceEndpointSecurityClient`** für die Sicherheits-App, die von **`tccd`** verwaltet wird, gegeben wurde, damit `tccutil` ihre Berechtigungen nicht löscht und sie somit nicht ausgeführt werden kann.

## Referenzen

* [**OBTS v3.0: "Endpunktsicherheit & Unsicherheit" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
