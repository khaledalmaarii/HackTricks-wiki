# macOS MDM

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

**Um mehr über macOS MDMs zu erfahren, überprüfen Sie:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Grundlagen

### **MDM (Mobile Device Management) Überblick**
[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) wird zur Verwaltung verschiedener Endbenutzergeräte wie Smartphones, Laptops und Tablets verwendet. Insbesondere für Apples Plattformen (iOS, macOS, tvOS) umfasst es eine Reihe spezialisierter Funktionen, APIs und Praktiken. Der Betrieb von MDM hängt von einem kompatiblen MDM-Server ab, der entweder kommerziell verfügbar oder Open Source sein muss und das [MDM-Protokoll](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) unterstützen muss. Wichtige Punkte sind:

- Zentrale Kontrolle über Geräte.
- Abhängigkeit von einem MDM-Server, der das MDM-Protokoll einhält.
- Fähigkeit des MDM-Servers, verschiedene Befehle an Geräte zu senden, z. B. Fernlöschung von Daten oder Konfigurationsinstallation.

### **Grundlagen des DEP (Device Enrollment Program)**
Das von Apple angebotene [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereinfacht die Integration von Mobile Device Management (MDM), indem es eine konfigurationsfreie Konfiguration für iOS-, macOS- und tvOS-Geräte ermöglicht. DEP automatisiert den Anmeldevorgang, sodass Geräte direkt aus der Verpackung einsatzbereit sind und nur minimale Benutzer- oder Administratoreingriffe erfordern. Wesentliche Aspekte sind:

- Ermöglicht Geräten, sich bei der ersten Aktivierung automatisch bei einem vordefinierten MDM-Server zu registrieren.
- Hauptsächlich für brandneue Geräte vorteilhaft, aber auch für Geräte, die neu konfiguriert werden.
- Ermöglicht eine unkomplizierte Einrichtung, sodass Geräte schnell für den organisatorischen Einsatz bereit sind.

### **Sicherheitsüberlegungen**
Es ist wichtig zu beachten, dass die einfache Anmeldung, die DEP bietet, während sie vorteilhaft ist, auch Sicherheitsrisiken bergen kann. Wenn für die MDM-Anmeldung nicht ausreichend Schutzmaßnahmen ergriffen werden, könnten Angreifer diesen vereinfachten Prozess ausnutzen, um ihr Gerät auf dem MDM-Server der Organisation zu registrieren und sich als Unternehmensgerät auszugeben.

{% hint style="danger" %}
**Sicherheitswarnung**: Die vereinfachte DEP-Anmeldung könnte es potenziell ermöglichen, dass nicht autorisierte Geräte auf dem MDM-Server der Organisation registriert werden, wenn angemessene Sicherheitsvorkehrungen nicht getroffen werden.
{% endhint %}

### Grundlagen Was ist SCEP (Simple Certificate Enrolment Protocol)?

* Ein relativ altes Protokoll, das vor der Verbreitung von TLS und HTTPS erstellt wurde.
* Bietet Clients eine standardisierte Möglichkeit, eine **Certificate Signing Request** (CSR) zu senden, um ein Zertifikat zu erhalten. Der Client fordert vom Server ein signiertes Zertifikat an.

### Was sind Konfigurationsprofile (auch mobileconfigs genannt)?

* Die offizielle Methode von Apple zur **Festlegung/Durchsetzung der Systemkonfiguration**.
* Dateiformat, das mehrere Nutzlasten enthalten kann.
* Basierend auf Property Lists (der XML-Art).
* "können signiert und verschlüsselt werden, um ihre Herkunft zu validieren, ihre Integrität sicherzustellen und ihren Inhalt zu schützen." Grundlagen - Seite 70, iOS Security Guide, Januar 2018.

## Protokolle

### MDM

* Kombination aus APNs (**Apple-Servern**) + RESTful API (**MDM-** **Anbieter-Server**)
* **Kommunikation** erfolgt zwischen einem **Gerät** und einem Server, der mit einem **Geräteverwaltungsprodukt** verbunden ist
* **Befehle** werden vom MDM an das Gerät in **plist-codierten Wörterbüchern** übermittelt
* Alles über **HTTPS**. MDM-Server können (und werden normalerweise) gepinnt.
* Apple gewährt dem MDM-Anbieter ein **APNs-Zertifikat** zur Authentifizierung

### DEP

* **3 APIs**: 1 für Wiederverkäufer, 1 für MDM-Anbieter, 1 für Geräteidentität (undokumentiert):
* Die sogenannte [DEP "Cloud-Service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Diese wird von MDM-Servern verwendet, um DEP-Profile mit bestimmten Geräten zu verknüpfen.
* Die [DEP-API, die von autorisierten Apple-Wiederverkäufern verwendet wird](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), um Geräte zu registrieren, den Registrierungsstatus zu überprüfen und den Transaktionsstatus zu überprüfen.
* Die nicht dokumentierte private DEP-API. Diese wird von Apple-Geräten verwendet, um ihr DEP-Profil anzufordern. Unter macOS ist die ausführbare Datei `cloudconfigurationd` für die Kommunikation über diese API verantwortlich.
* Moderner und basierend auf **JSON** (im Vergleich zu plist)
* Apple gewährt dem MDM-Anbieter ein **OAuth-Token**

**DEP "Cloud-Service" API**

* RESTful
* Synchronisieren von Geräterekorden von Apple zum MDM-Server
* Synchronisieren von "DEP-Profilen" von MDM-Servern zu Apple (später an das Gerät geliefert)
* Ein DEP-"Profil" enthält:
* MDM-Anbieter-Server-URL
* Zusätzliche vertrauenswürdige Zertifikate für die Server-URL (optionales Pinning)
* Zusätzliche Einstellungen (z. B. welche Bildschirme im Setup-Assistenten übersprungen werden sollen)

## Seriennummer

Apple-Geräte, die nach 2010 hergestellt wurden, haben in der Regel eine **12-stellige alphanumerische** Seriennummer, wobei die **ersten drei Ziffern den Herstellungsort**, die nächsten **zwei** das **Jahr** und die **Woche** der Herstellung, die nächsten **drei** Ziffern eine **eindeutige** **Kennung** und die **letzten** **vier** Ziffern die **Modellnummer** darstellen.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Schritte für die Anmeldung und Verwaltung

1. Erstellung des Geräterekords (Wiederverkäufer, Apple): Der Rekord für das neue Gerät wird erstellt.
2. Zuordnung des Geräterekords (Kunde): Das Gerät wird einem MDM-Server zugeordnet.
3. Synchronisierung des Geräterekords (MDM-Anbieter): MDM synchronisiert die Geräterekords und sendet die DEP-Profile an Apple.
4. DEP-Check-in (Gerät): Das Gerät erhält sein DEP-Profil.
5. Profilabruf (Gerät)
6. Profilinstallation (Gerät) a. einschließlich MDM-, SCEP- und Root-CA-Nutzlasten
7. Ausgabe von MDM
### Schritt 4: DEP-Check-in - Abrufen des Aktivierungsdatensatzes

Dieser Teil des Prozesses tritt auf, wenn ein Benutzer einen Mac zum ersten Mal startet (oder nach einer vollständigen Löschung)

![](<../../../.gitbook/assets/image (568).png>)

oder beim Ausführen von `sudo profiles show -type enrollment`

- Bestimmen Sie, ob das Gerät DEP-fähig ist
- Aktivierungsdatensatz ist der interne Name für das DEP-"Profil"
- Beginnt, sobald das Gerät mit dem Internet verbunden ist
- Gesteuert durch `CPFetchActivationRecord`
- Implementiert von `cloudconfigurationd` über XPC. Der "Setup-Assistent" (wenn das Gerät zum ersten Mal gestartet wird) oder der `profiles`-Befehl werden diesen Daemon kontaktieren, um den Aktivierungsdatensatz abzurufen.
- LaunchDaemon (läuft immer als Root)

Es folgen einige Schritte, um den Aktivierungsdatensatz durch `MCTeslaConfigurationFetcher` abzurufen. Dieser Prozess verwendet eine Verschlüsselung namens Absinthe.

1. Zertifikat abrufen
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Zustand aus Zertifikat initialisieren (`NACInit`)
1. Verwendet verschiedene gerätespezifische Daten (z. B. Seriennummer über `IOKit`)
3. Sitzungsschlüssel abrufen
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Sitzung herstellen (`NACKeyEstablishment`)
5. Anfrage stellen
1. POST an [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) und senden der Daten `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Die JSON-Payload wird mit Absinthe verschlüsselt (`NACSign`)
3. Alle Anfragen über HTTPS, eingebaute Stammzertifikate werden verwendet

![](<../../../.gitbook/assets/image (566).png>)

Die Antwort ist ein JSON-Dictionary mit einigen wichtigen Daten wie:

- **url**: URL des MDM-Anbieterhosts für das Aktivierungsprofil
- **anchor-certs**: Array von DER-Zertifikaten, die als vertrauenswürdige Anker verwendet werden

### **Schritt 5: Profilabruf**

![](<../../../.gitbook/assets/image (567).png>)

- Anfrage an **in DEP-Profil angegebene URL** gesendet.
- **Ankerzertifikate** werden zur Überprüfung des Vertrauens verwendet, sofern angegeben.
- Erinnerung: Die Eigenschaft **anchor\_certs** des DEP-Profils
- Die Anfrage ist ein einfacher .plist mit Geräteidentifikation
- Beispiele: **UDID, Betriebssystemversion**.
- CMS-signiert, DER-kodiert
- Signiert mit dem **Geräteidentitätszertifikat (von APNS)**
- **Zertifikatskette** enthält abgelaufenes **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### Schritt 6: Profilinstallation

- Sobald abgerufen, wird das **Profil im System gespeichert**
- Dieser Schritt beginnt automatisch (wenn im **Setup-Assistenten**)
- Gesteuert durch `CPInstallActivationProfile`
- Implementiert von mdmclient über XPC
- LaunchDaemon (als Root) oder LaunchAgent (als Benutzer), abhängig vom Kontext
- Konfigurationsprofile haben mehrere Nutzlasten zur Installation
- Das Framework hat eine pluginbasierte Architektur zur Installation von Profilen
- Jeder Nutzlasttyp ist mit einem Plugin verbunden
- Kann XPC (im Framework) oder klassisches Cocoa (in ManagedClient.app) sein
- Beispiel:
- Zertifikat-Nutzlasten verwenden CertificateService.xpc

Normalerweise enthält das **Aktivierungsprofil**, das von einem MDM-Anbieter bereitgestellt wird, die folgenden Nutzlasten:

- `com.apple.mdm`: um das Gerät in MDM **einzuschreiben**
- `com.apple.security.scep`: um dem Gerät sicher ein **Clientzertifikat** bereitzustellen.
- `com.apple.security.pem`: um vertrauenswürdige CA-Zertifikate in den System-Schlüsselbund des Geräts zu **installieren**.
- Installation der MDM-Nutzlast, die dem **MDM-Check-in in der Dokumentation** entspricht
- Die Nutzlast enthält **Schlüsselattribute**:
- MDM Check-In-URL (**`CheckInURL`**)
- MDM-Befehlsabfrage-URL (**`ServerURL`**) + APNs-Thema, um es auszulösen
- Um die MDM-Nutzlast zu installieren, wird eine Anfrage an **`CheckInURL`** gesendet
- Implementiert in **`mdmclient`**
- MDM-Nutzlast kann von anderen Nutzlasten abhängen
- Ermöglicht das **Anheften von Anfragen an bestimmte Zertifikate**:
- Eigenschaft: **`CheckInURLPinningCertificateUUIDs`**
- Eigenschaft: **`ServerURLPinningCertificateUUIDs`**
- Über PEM-Nutzlast geliefert
- Ermöglicht die Zuordnung des Geräts zu einem Identitätszertifikat:
- Eigenschaft: IdentityCertificateUUID
- Über SCEP-Nutzlast geliefert

### **Schritt 7: Auf MDM-Befehle warten**

- Nach Abschluss des MDM-Check-ins kann der Anbieter über APNs Push-Benachrichtigungen senden
- Bei Eingang von Benachrichtigungen behandelt von **`mdmclient`**
- Um nach MDM-Befehlen zu suchen, wird eine Anfrage an ServerURL gesendet
- Verwendet zuvor installierte MDM-Nutzlast:
- **`ServerURLPinningCertificateUUIDs`** zum Anheften der Anfrage
- **`IdentityCertificateUUID`** für TLS-Clientzertifikat
