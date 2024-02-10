# macOS Systemerweiterungen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Systemerweiterungen / Endpoint Security Framework

Im Gegensatz zu Kernelerweiterungen werden **Systemerweiterungen im Benutzerraum** anstelle des Kernelraums ausgeführt, wodurch das Risiko eines Systemabsturzes aufgrund einer Erweiterungsfehlfunktion verringert wird.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Es gibt drei Arten von Systemerweiterungen: **DriverKit**-Erweiterungen, **Network**-Erweiterungen und **Endpoint Security**-Erweiterungen.

### **DriverKit-Erweiterungen**

DriverKit ist ein Ersatz für Kernelerweiterungen, die **Hardwareunterstützung bieten**. Es ermöglicht Gerätetreibern (wie USB-, Seriell-, NIC- und HID-Treibern), im Benutzerraum anstelle des Kernelraums ausgeführt zu werden. Das DriverKit-Framework enthält **Benutzerraumversionen bestimmter I/O Kit-Klassen**, und der Kernel leitet normale I/O Kit-Ereignisse an den Benutzerraum weiter, um eine sicherere Umgebung für diese Treiber zu bieten.

### **Network-Erweiterungen**

Network-Erweiterungen bieten die Möglichkeit, Netzwerkverhalten anzupassen. Es gibt verschiedene Arten von Network-Erweiterungen:

* **App-Proxy**: Dies wird verwendet, um einen VPN-Client zu erstellen, der ein flussorientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Dies bedeutet, dass er Netzwerkverkehr basierend auf Verbindungen (oder Flows) und nicht auf einzelnen Paketen verarbeitet.
* **Packet Tunnel**: Dies wird verwendet, um einen VPN-Client zu erstellen, der ein paketorientiertes, benutzerdefiniertes VPN-Protokoll implementiert. Dies bedeutet, dass er Netzwerkverkehr basierend auf einzelnen Paketen verarbeitet.
* **Filterdaten**: Dies wird verwendet, um Netzwerk "Flows" zu filtern. Es kann Netzwerkdaten auf Flussebene überwachen oder ändern.
* **Filterpaket**: Dies wird verwendet, um einzelne Netzwerkpakete zu filtern. Es kann Netzwerkdaten auf Paketebene überwachen oder ändern.
* **DNS-Proxy**: Dies wird verwendet, um einen benutzerdefinierten DNS-Anbieter zu erstellen. Es kann verwendet werden, um DNS-Anfragen und -Antworten zu überwachen oder zu ändern.

## Endpoint Security Framework

Endpoint Security ist ein von Apple in macOS bereitgestelltes Framework, das eine Reihe von APIs für die Systemsicherheit bietet. Es ist für die Verwendung durch **Sicherheitsanbieter und Entwickler gedacht, um Produkte zu erstellen, die Systemaktivitäten überwachen und steuern** können, um bösartige Aktivitäten zu erkennen und zu schützen.

Dieses Framework bietet eine **Sammlung von APIs zur Überwachung und Steuerung von Systemaktivitäten**, wie z.B. Prozessausführungen, Dateisystemereignissen, Netzwerk- und Kernelereignissen.

Der Kern dieses Frameworks ist als Kernelerweiterung (KEXT) in der Kernelerweiterung (KEXT) implementiert und befindet sich unter **`/System/Library/Extensions/EndpointSecurity.kext`**. Diese KEXT besteht aus mehreren wichtigen Komponenten:

* **EndpointSecurityDriver**: Dies fungiert als "Einstiegspunkt" für die Kernelerweiterung. Es ist der Hauptpunkt der Interaktion zwischen dem Betriebssystem und dem Endpoint Security Framework.
* **EndpointSecurityEventManager**: Diese Komponente ist für die Implementierung von Kernel-Hooks verantwortlich. Kernel-Hooks ermöglichen es dem Framework, Systemereignisse zu überwachen, indem sie Systemaufrufe abfangen.
* **EndpointSecurityClientManager**: Dies verwaltet die Kommunikation mit Benutzerraum-Clients und verfolgt, welche Clients verbunden sind und Ereignisbenachrichtigungen erhalten müssen.
* **EndpointSecurityMessageManager**: Dies sendet Nachrichten und Ereignisbenachrichtigungen an Benutzerraum-Clients.

Die Ereignisse, die das Endpoint Security Framework überwachen kann, sind in folgende Kategorien unterteilt:

* Dateiereignisse
* Prozessereignisse
* Socketereignisse
* Kernelereignisse (wie das Laden/Entladen einer Kernelerweiterung oder das Öffnen eines I/O Kit-Geräts)

### Architektur des Endpoint Security Frameworks

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Die **Kommunikation im Benutzerraum** mit dem Endpoint Security Framework erfolgt über die Klasse IOUserClient. Es werden zwei verschiedene Unterklassen verwendet, abhängig vom Typ des Aufrufers:

* **EndpointSecurityDriverClient**: Dies erfordert die Berechtigung `com.apple.private.endpoint-security.manager`, die nur vom Systemprozess `endpointsecurityd` gehalten wird.
* **EndpointSecurityExternalClient**: Dies erfordert die Berechtigung `com.apple.developer.endpoint-security.client`. Dies wird in der Regel von Sicherheitssoftware von Drittanbietern verwendet, die mit dem Endpoint Security Framework interagieren muss.

Die Endpoint Security-Erweiterungen:**`libEndpointSecurity.dylib`** ist die C-Bibliothek, die von Systemerweiterungen verwendet wird, um mit dem Kernel zu kommunizieren. Diese Bibliothek verwendet das I/O Kit (`IOKit`), um mit der Endpoint Security KEXT zu kommunizieren.

**`endpointsecurityd`** ist ein wichtiger Systemdämon, der an der Verwaltung und dem Starten von Endpoint Security-Systemerweiterungen beteiligt ist, insbesondere während des frühen Bootvorgangs. **Nur Systemerweiterungen**, die in ihrer `Info.plist`-Datei mit **`NSEndpointSecurityEarlyBoot`** markiert sind, erhalten diese frühe Bootbehandlung.

Ein weiterer Systemdämon, **`sysextd`**, **validiert Systemerweiterungen** und verschiebt sie an die richtigen Systempositionen. Anschließend fordert er den entsprechenden Dämon auf, die Erweiterung zu laden. Das **`SystemExtensions.framework`** ist für das Aktivieren und Deaktivieren von Systemerweiterungen verantwortlich.

## Umgehung von ESF

ESF wird von Sicherheitstools verwendet, die versuchen, einen Red Teamer zu erkennen. Daher klingt jede Information darüber, wie dies vermieden werden kann, interessant.

### CVE-2021-30965

Die Sache ist, dass die Sicherheitsanwendung **Vollzugriff auf die Festplatte** haben muss. Wenn ein Angreifer dies entfernen könnte, könnte er verhindern, dass die Software ausgeführt wird:
```bash
tccutil reset All
```
Für **weitere Informationen** zu diesem Umgehungstrick und verwandten Tricks schauen Sie sich den Vortrag [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) an.

Am Ende wurde dies behoben, indem der Sicherheits-App, die von **`tccd`** verwaltet wird, die neue Berechtigung **`kTCCServiceEndpointSecurityClient`** zugewiesen wurde. Dadurch werden die Berechtigungen der App von `tccutil` nicht gelöscht und sie kann ausgeführt werden.

## Referenzen

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
