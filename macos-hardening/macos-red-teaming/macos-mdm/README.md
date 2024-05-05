# macOS MDM

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

**Um mehr über macOS MDMs zu erfahren, überprüfen Sie:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Grundlagen

### **MDM (Mobile Device Management) Überblick**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) wird zur Verwaltung verschiedener Endbenutzergeräte wie Smartphones, Laptops und Tablets eingesetzt. Insbesondere für Apples Plattformen (iOS, macOS, tvOS) umfasst es eine Reihe spezialisierter Funktionen, APIs und Praktiken. Der Betrieb von MDM hängt von einem kompatiblen MDM-Server ab, der entweder kommerziell verfügbar oder Open Source ist und das [MDM-Protokoll](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) unterstützen muss. Zu den Schlüsselpunkten gehören:

* Zentrale Kontrolle über Geräte.
* Abhängigkeit von einem MDM-Server, der dem MDM-Protokoll entspricht.
* Fähigkeit des MDM-Servers, verschiedene Befehle an Geräte zu senden, z. B. Remote-Datenerfassung oder Konfigurationsinstallation.

### **Grundlagen des DEP (Device Enrollment Program)**

Das [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) von Apple vereinfacht die Integration des Mobile Device Management (MDM), indem es eine Konfiguration ohne Berührung für iOS-, macOS- und tvOS-Geräte ermöglicht. DEP automatisiert den Anmeldeprozess, sodass Geräte sofort einsatzbereit sind, mit minimalem Benutzer- oder administrativem Eingriff. Wesentliche Aspekte sind:

* Ermöglicht es Geräten, sich bei der erstmaligen Aktivierung automatisch bei einem vordefinierten MDM-Server zu registrieren.
* Hauptsächlich für brandneue Geräte vorteilhaft, aber auch für Geräte, die neu konfiguriert werden.
* Ermöglicht eine unkomplizierte Einrichtung, sodass Geräte schnell für den organisatorischen Einsatz bereit sind.

### **Sicherheitsüberlegungen**

Es ist wichtig zu beachten, dass die vereinfachte Anmeldung durch DEP, obwohl vorteilhaft, auch Sicherheitsrisiken bergen kann. Wenn Schutzmaßnahmen für die MDM-Anmeldung nicht angemessen durchgesetzt werden, könnten Angreifer diesen vereinfachten Prozess ausnutzen, um ihr Gerät auf dem MDM-Server der Organisation zu registrieren und sich als Unternehmensgerät auszugeben.

{% hint style="danger" %}
**Sicherheitswarnung**: Die vereinfachte DEP-Anmeldung könnte es unbefugten Geräten ermöglichen, sich auf dem MDM-Server der Organisation zu registrieren, wenn angemessene Sicherheitsvorkehrungen nicht getroffen werden.
{% endhint %}

### Grundlagen Was ist SCEP (Simple Certificate Enrolment Protocol)?

* Ein relativ altes Protokoll, erstellt bevor TLS und HTTPS weit verbreitet waren.
* Bietet Clients eine standardisierte Möglichkeit, eine **Certificate Signing Request** (CSR) zu senden, um ein Zertifikat zu erhalten. Der Client wird den Server bitten, ihm ein signiertes Zertifikat zu geben.

### Was sind Konfigurationsprofile (auch mobileconfigs genannt)?

* Apples offizielle Methode zum **Festlegen/Durchsetzen von Systemkonfigurationen**.
* Dateiformat, das mehrere Nutzlasten enthalten kann.
* Basierend auf Property Lists (der XML-Art).
* „kann signiert und verschlüsselt werden, um ihre Herkunft zu validieren, ihre Integrität sicherzustellen und ihren Inhalt zu schützen.“ Grundlagen — Seite 70, iOS Security Guide, Januar 2018.

## Protokolle

### MDM

* Kombination aus APNs (**Apple-Servern**) + RESTful-API (**MDM-Servern von Anbietern**)
* **Kommunikation** erfolgt zwischen einem **Gerät** und einem Server, der mit einem **Geräteverwaltungsprodukt** verbunden ist
* **Befehle** werden vom MDM an das Gerät in **plist-codierten Wörterbüchern** übermittelt
* Alles über **HTTPS**. MDM-Server können (und werden in der Regel) gepinnt.
* Apple gewährt dem MDM-Anbieter ein **APNs-Zertifikat** zur Authentifizierung

### DEP

* **3 APIs**: 1 für Wiederverkäufer, 1 für MDM-Anbieter, 1 für Gerätekennung (undokumentiert):
* Die sogenannte [DEP-"Cloud-Service"-API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Diese wird von MDM-Servern verwendet, um DEP-Profile mit bestimmten Geräten zu verknüpfen.
* Die [DEP-API, die von autorisierten Apple-Wiederverkäufern verwendet wird](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), um Geräte zu registrieren, den Registrierungsstatus zu überprüfen und den Transaktionsstatus zu überprüfen.
* Die nicht dokumentierte private DEP-API. Diese wird von Apple-Geräten verwendet, um ihr DEP-Profil anzufordern. Auf macOS ist die `cloudconfigurationd`-Binärdatei für die Kommunikation über diese API verantwortlich.
* Moderner und **JSON**-basiert (im Vergleich zu plist)
* Apple gewährt dem MDM-Anbieter ein **OAuth-Token**

**DEP-"Cloud-Service"-API**

* RESTful
* synchronisiert Gerätedatensätze von Apple zum MDM-Server
* synchronisiert „DEP-Profile“ von MDM-Servern zu Apple (die später vom Gerät empfangen werden)
* Ein DEP-"Profil" enthält:
* MDM-Server-URL
* Zusätzliche vertrauenswürdige Zertifikate für Server-URL (optionales Pinning)
* Zusätzliche Einstellungen (z. B. welche Bildschirme im Setup-Assistenten übersprungen werden sollen)

## Seriennummer

Apple-Geräte, die nach 2010 hergestellt wurden, haben im Allgemeinen **12-stellige alphanumerische** Seriennummern, wobei die **ersten drei Ziffern den Herstellungsort**, die folgenden **zwei** das **Jahr** und die **Woche** der Herstellung, die nächsten **drei** eine **eindeutige Kennung** und die **letzten** **vier** die **Modellnummer** darstellen.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Schritte zur Anmeldung und Verwaltung

1. Erstellung des Gerätedatensatzes (Wiederverkäufer, Apple): Der Datensatz für das neue Gerät wird erstellt
2. Zuweisung des Gerätedatensatzes (Kunde): Das Gerät wird einem MDM-Server zugewiesen
3. Synchronisierung des Gerätedatensatzes (MDM-Anbieter): MDM synchronisiert die Gerätedatensätze und sendet die DEP-Profile an Apple
4. DEP-Check-in (Gerät): Gerät erhält sein DEP-Profil
5. Profilabruf (Gerät)
6. Profilinstallation (Gerät) a. inkl. MDM-, SCEP- und Root-CA-Nutzlasten
7. Ausgabe von MDM-Befehlen (Gerät)

![](<../../../.gitbook/assets/image (694).png>)

Die Datei `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exportiert Funktionen, die als **hochrangige "Schritte"** des Anmeldevorgangs betrachtet werden können.
### Schritt 4: DEP-Check-in - Abrufen des Aktivierungsdatensatzes

Dieser Teil des Prozesses tritt auf, wenn ein **Benutzer einen Mac zum ersten Mal startet** (oder nach einem vollständigen Löschen)

![](<../../../.gitbook/assets/image (1044).png>)

oder beim Ausführen von `sudo profiles show -type enrollment`

* Feststellen, ob das Gerät DEP-fähig ist
* Aktivierungsdatensatz ist der interne Name für das **DEP-"Profil"**
* Beginnt, sobald das Gerät mit dem Internet verbunden ist
* Gesteuert durch **`CPFetchActivationRecord`**
* Implementiert durch **`cloudconfigurationd`** über XPC. Der **"Setup-Assistent**" (wenn das Gerät zum ersten Mal gestartet wird) oder der **`profiles`**-Befehl wird diesen Daemon kontaktieren, um den Aktivierungsdatensatz abzurufen.
* LaunchDaemon (läuft immer als Root)

Es folgen einige Schritte zur Abrufung des Aktivierungsdatensatzes durch **`MCTeslaConfigurationFetcher`**. Dieser Prozess verwendet eine Verschlüsselung namens **Absinthe**

1. Zertifikat abrufen
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialisieren** des Zustands aus dem Zertifikat (**`NACInit`**)
1. Verwendet verschiedene gerätespezifische Daten (z. B. **Seriennummer über `IOKit`**)
3. Sitzungsschlüssel abrufen
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Sitzung herstellen (**`NACKeyEstablishment`**)
5. Anfrage senden
1. POST an [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) und sende die Daten `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Die JSON-Payload wird mit Absinthe verschlüsselt (**`NACSign`**)
3. Alle Anfragen über HTTPS, integrierte Stammzertifikate werden verwendet

![](<../../../.gitbook/assets/image (566) (1).png>)

Die Antwort ist ein JSON-Dictionary mit einigen wichtigen Daten wie:

* **url**: URL des MDM-Anbieterhosts für das Aktivierungsprofil
* **anchor-certs**: Array von DER-Zertifikaten, die als vertrauenswürdige Anker verwendet werden

### **Schritt 5: Profilabruf**

![](<../../../.gitbook/assets/image (444).png>)

* Anfrage an **URL im DEP-Profil bereitgestellt**.
* **Ankerzertifikate** werden verwendet, um das Vertrauen zu **bewerten**, wenn bereitgestellt.
* Erinnerung: die **anchor\_certs**-Eigenschaft des DEP-Profils
* **Anfrage ist ein einfaches .plist** mit Gerätekennung
* Beispiele: **UDID, Betriebssystemversion**.
* CMS-signiert, DER-codiert
* Signiert mit dem **Geräteidentitätszertifikat (von APNS)**
* **Zertifikatskette** enthält abgelaufenes **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Schritt 6: Profilinstallation

* Sobald abgerufen, wird das **Profil im System gespeichert**
* Dieser Schritt beginnt automatisch (wenn im **Setup-Assistent**)
* Gesteuert durch **`CPInstallActivationProfile`**
* Implementiert durch mdmclient über XPC
* LaunchDaemon (als Root) oder LaunchAgent (als Benutzer), abhängig vom Kontext
* Konfigurationsprofile haben mehrere Nutlasten zur Installation
* Framework hat eine Plugin-basierte Architektur zur Installation von Profilen
* Jeder Nutlasttyp ist mit einem Plugin verbunden
* Kann XPC (im Framework) oder klassisches Cocoa (in ManagedClient.app) sein
* Beispiel:
* Zertifikat-Nutlasten verwenden CertificateService.xpc

Typischerweise wird das **Aktivierungsprofil**, das von einem MDM-Anbieter bereitgestellt wird, die folgenden Nutlasten enthalten:

* `com.apple.mdm`: um das Gerät in MDM **einzuschreiben**
* `com.apple.security.scep`: um dem Gerät ein **Client-Zertifikat** sicher bereitzustellen.
* `com.apple.security.pem`: um **vertrauenswürdige CA-Zertifikate** in den System-Schlüsselbund des Geräts zu installieren.
* Installation der MDM-Nutlast entspricht dem **MDM-Check-in in der Dokumentation**
* Nutlast enthält Schlüsseleigenschaften:
*
* MDM Check-In-URL (**`CheckInURL`**)
* MDM-Befehlsabfrage-URL (**`ServerURL`**) + APNs-Thema, um es auszulösen
* Um die MDM-Nutlast zu installieren, wird die Anfrage an **`CheckInURL`** gesendet
* Implementiert in **`mdmclient`**
* MDM-Nutlast kann von anderen Nutlasten abhängen
* Ermöglicht es, **Anfragen an bestimmte Zertifikate zu binden**:
* Eigenschaft: **`CheckInURLPinningCertificateUUIDs`**
* Eigenschaft: **`ServerURLPinningCertificateUUIDs`**
* Über PEM-Nutlast geliefert
* Ermöglicht es, dem Gerät mit einem Identitätszertifikat zugeordnet zu werden:
* Eigenschaft: IdentityCertificateUUID
* Über SCEP-Nutlast geliefert

### **Schritt 7: Auf MDM-Befehle lauschen**

* Nach Abschluss des MDM-Check-ins kann der Anbieter **Push-Benachrichtigungen über APNs senden**
* Bei Empfang wird dies von **`mdmclient`** behandelt
* Um nach MDM-Befehlen zu suchen, wird die Anfrage an ServerURL gesendet
* Nutzt zuvor installierte MDM-Nutlast:
* **`ServerURLPinningCertificateUUIDs`** für die Anforderungspinnung
* **`IdentityCertificateUUID`** für TLS-Clientzertifikat
