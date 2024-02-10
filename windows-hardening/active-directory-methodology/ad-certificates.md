# AD-Zertifikate

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats gibt den Besitzer an.
- Ein **öffentlicher Schlüssel** ist mit einem privat gehaltenen Schlüssel verknüpft, um das Zertifikat seinem rechtmäßigen Besitzer zuzuordnen.
- Der **Gültigkeitszeitraum**, definiert durch die Daten **NotBefore** und **NotAfter**, kennzeichnet die wirksame Dauer des Zertifikats.
- Eine eindeutige **Seriennummer**, bereitgestellt von der Zertifizierungsstelle (CA), identifiziert jedes Zertifikat.
- Der **Issuer** bezieht sich auf die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und erhöht die Flexibilität bei der Identifizierung.
- **Basic Constraints** identifizieren, ob das Zertifikat für eine CA oder eine Endentität bestimmt ist, und definieren Verwendungsbeschränkungen.
- **Extended Key Usages (EKUs)** grenzen die spezifischen Zwecke des Zertifikats ein, wie z.B. Codesignierung oder E-Mail-Verschlüsselung, über Objektidentifikatoren (OIDs).
- Der **Signaturalgorithmus** gibt die Methode zur Signierung des Zertifikats an.
- Die **Signatur**, erstellt mit dem privaten Schlüssel des Ausstellers, garantiert die Echtheit des Zertifikats.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domänen entscheidend ist. Eine sichere Ausgabeprozesse sind wichtig, um Risiken von Identitätsdiebstahl durch Angreifer zu vermeiden, die die SAN-Spezifikation manipulieren.

### Zertifizierungsstellen (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einem AD-Forest über bestimmte Container an, die jeweils einzigartige Rollen erfüllen:

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Enterprise-CAs und deren Zertifikatvorlagen.
- Das Objekt **NTAuthCertificates** enthält für die AD-Authentifizierung autorisierte CA-Zertifikate.
- Der Container **AIA (Authority Information Access)** erleichtert die Validierung von Zertifikatsketten mit Zwischen- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Ablauf der Client-Zertifikatsanforderung

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise-CA finden.
2. Nachdem ein öffentlich-privater Schlüsselpaar generiert wurde, wird ein CSR erstellt, das einen öffentlichen Schlüssel und andere Details enthält.
3. Die CA prüft den CSR anhand verfügbarer Zertifikatvorlagen und stellt das Zertifikat auf der Grundlage der Berechtigungen der Vorlage aus.
4. Nach Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und gibt es an den Client zurück.

### Zertifikatvorlagen

Diese Vorlagen, die in AD definiert sind, legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest, einschließlich erlaubter EKUs und Anmelde- oder Änderungsrechten, die für die Verwaltung des Zugriffs auf Zertifikatsdienste entscheidend sind.

## Zertifikatanmeldung

Der Anmeldevorgang für Zertifikate wird von einem Administrator initiiert, der eine Zertifikatvorlage erstellt, die dann von einer Enterprise-Zertifizierungsstelle (CA) veröffentlicht wird. Dadurch wird die Vorlage für die Client-Anmeldung verfügbar, indem der Name der Vorlage zum Feld `certificatetemplates` eines Active Directory-Objekts hinzugefügt wird.

Damit ein Client ein Zertifikat anfordern kann, müssen ihm **Anmeldeberechtigungen** gewährt werden. Diese Berechtigungen werden durch Sicherheitsdeskriptoren auf der Zertifikatvorlage und der Enterprise-CA selbst definiert. Berechtigungen müssen an beiden Stellen gewährt werden, damit eine Anforderung erfolgreich ist.

### Anmeldeberechtigungen für Vorlagen

Diese Berechtigungen werden durch Access Control Entries (ACEs) festgelegt und umfassen Berechtigungen wie:
- **Certificate-Enrollment** und **Certificate-AutoEnrollment**-Rechte, die jeweils mit spezifischen GUIDs verknüpft sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen ermöglichen.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage bieten.

### Anmeldeberechtigungen für Enterprise-CA

Die Rechte der CA werden in ihrem Sicherheitsdeskriptor festgelegt, der über die Verwaltungskonsole der Zertifizierungsstelle zugänglich ist. Einige Einstellungen ermöglichen sogar Benutzern mit niedrigen Privilegien den Remotezugriff, was ein Sicherheitsrisiko darstellen könnte.

### Zusätzliche Ausgabesteuerungen

Es können bestimmte Steuerungen gelten, wie z.B.:
- **Managergenehmigung**: Setzt Anfragen in einen ausstehenden Zustand, bis sie von einem Zertifikatsmanager genehmigt werden.
- **Anmeldeagenten und autorisierte Signaturen**: Legen die Anzahl der erforderlichen Signaturen auf einem CSR und die erforderlichen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können über folgende Methoden angefordert werden:
1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) unter Verwendung von DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR) über benannte Pipes oder TCP/IP.
3. Die **Zertifikatanforderungs-Web-Schnittstelle** mit installierter Rolle für die Zertifizierungsstellen-Webanmeldung.
4. Der **Certificate Enrollment Service** (CES) in Verbindung mit dem Certificate Enrollment Policy (CEP) Service.
5. Der **Network Device Enrollment Service** (NDES) für Netzwerkgeräte unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Befehlszeilentools (`certreq.exe` oder den PowerShell-Befehl `Get-Certificate`) anfordern.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt die Zertifikatsauthentifizierung, hauptsächlich unter Verwendung der Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anforderung eines Ticket Granting Tickets (TGT) eines Benutzers mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anforderung wird vom Domänencontroller mehreren Validierungen unterzogen, einschließlich der **Gültigkeit**, **Pfad** und **Sperrstatus** des Zertifikats. Zu den Validierungen gehört auch die Überprüfung, ob das Zertifikat von einer vertrauenswürdigen Quelle stammt und ob der Aussteller im **NTAUTH-Zertifikatsspeicher** vorhanden ist. Erfolgreiche Validierungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD befindet sich unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
### Sichere Kanal (Schannel) Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen, bei denen der Client während des Handshakes ein Zertifikat vorlegt, das bei erfolgreicher Validierung den Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann die Funktion **S4U2Self** von Kerberos oder den **Subject Alternative Name (SAN)** des Zertifikats umfassen, unter anderem.

### Enumeration der AD-Zertifikatsdienste

Die Zertifikatsdienste von AD können durch LDAP-Abfragen aufgelistet werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt werden. Dies ist für jeden domänenauthentifizierten Benutzer ohne besondere Privilegien zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Aufzählung und Schwachstellenbewertung in AD CS-Umgebungen verwendet.

Befehle zur Verwendung dieser Tools sind:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referenzen

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
