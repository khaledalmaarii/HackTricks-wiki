# AD-Zertifikate

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

## Einführung

### Komponenten eines Zertifikats

- Der **Betreff** des Zertifikats bezeichnet seinen Eigentümer.
- Ein **Öffentlicher Schlüssel** wird mit einem privat gehaltenen Schlüssel gekoppelt, um das Zertifikat mit seinem rechtmäßigen Eigentümer zu verknüpfen.
- Der **Gültigkeitszeitraum**, definiert durch **NotBefore** und **NotAfter** Daten, markiert die effektive Dauer des Zertifikats.
- Eine eindeutige **Seriennummer**, die von der Zertifizierungsstelle (CA) bereitgestellt wird, identifiziert jedes Zertifikat.
- Der **Aussteller** bezieht sich auf die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Betreff und verbessert die Identifikationsflexibilität.
- **Basic Constraints** identifizieren, ob das Zertifikat für eine CA oder eine Endstelle gedacht ist und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** umreißen die spezifischen Zwecke des Zertifikats, wie Code-Signierung oder E-Mail-Verschlüsselung, durch Objektbezeichner (OIDs).
- Der **Signaturalgorithmus** gibt die Methode zum Signieren des Zertifikats an.
- Die **Signatur**, erstellt mit dem privaten Schlüssel des Ausstellers, garantiert die Authentizität des Zertifikats.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domänen entscheidend ist. Sichere Ausstellungsprozesse sind wichtig, um das Risiko der Identitätsübernahme durch Angreifer, die die SAN-Spezifikation manipulieren, zu vermeiden.

### Zertifizierungsstellen (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einem AD-Wald durch bestimmte Container an, die jeweils einzigartige Rollen erfüllen:

- Der **Zertifizierungsstellen**-Container enthält vertrauenswürdige Root-CA-Zertifikate.
- Der **Enrollment Services**-Container beschreibt Enterprise-CAs und deren Zertifikatvorlagen.
- Das **NTAuthCertificates**-Objekt umfasst CA-Zertifikate, die für die AD-Authentifizierung autorisiert sind.
- Der **AIA (Authority Information Access)**-Container erleichtert die Validierung der Zertifikatskette mit Zwischen- und Cross-CA-Zertifikaten.

### Zertifikatserwerbung: Client-Zertifikatsanforderungsfluss

1. Der Anforderungsprozess beginnt mit Clients, die eine Enterprise CA finden.
2. Ein CSR wird erstellt, der einen öffentlichen Schlüssel und andere Details enthält, nachdem ein öffentlich-privates Schlüsselpaar generiert wurde.
3. Die CA bewertet den CSR anhand der verfügbaren Zertifikatvorlagen und stellt das Zertifikat basierend auf den Berechtigungen der Vorlage aus.
4. Nach Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und gibt es an den Client zurück.

### Zertifikatvorlagen

Diese Vorlagen, die innerhalb von AD definiert sind, umreißen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten, einschließlich erlaubter EKUs und Anmelde- oder Änderungsrechte, die entscheidend für die Verwaltung des Zugriffs auf Zertifikatsdienste sind.

## Zertifikatsanmeldung

Der Anmeldeprozess für Zertifikate wird von einem Administrator initiiert, der **eine Zertifikatvorlage erstellt**, die dann von einer Enterprise-Zertifizierungsstelle (CA) **veröffentlicht** wird. Dies macht die Vorlage für die Client-Anmeldung verfügbar, ein Schritt, der erreicht wird, indem der Name der Vorlage in das Feld `certificatetemplates` eines Active Directory-Objekts eingefügt wird.

Damit ein Client ein Zertifikat anfordern kann, müssen **Anmeldeberechtigungen** gewährt werden. Diese Berechtigungen werden durch Sicherheitsbeschreibungen auf der Zertifikatvorlage und der Enterprise CA selbst definiert. Berechtigungen müssen an beiden Stellen gewährt werden, damit eine Anfrage erfolgreich ist.

### Vorlagenanmeldeberechtigungen

Diese Berechtigungen werden durch Access Control Entries (ACEs) spezifiziert, die Berechtigungen wie Folgendes detaillieren:
- **Certificate-Enrollment** und **Certificate-AutoEnrollment**-Rechte, die jeweils mit spezifischen GUIDs verbunden sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen erlauben.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage bieten.

### Enterprise CA-Anmeldeberechtigungen

Die Rechte der CA sind in ihrem Sicherheitsdescriptor umreißt, der über die Verwaltungs-Konsole der Zertifizierungsstelle zugänglich ist. Einige Einstellungen erlauben sogar Benutzern mit niedrigen Berechtigungen den Remote-Zugriff, was ein Sicherheitsrisiko darstellen könnte.

### Zusätzliche Ausstellungssteuerungen

Bestimmte Kontrollen können gelten, wie z.B.:
- **Managergenehmigung**: Versetzt Anfragen in einen ausstehenden Zustand, bis sie von einem Zertifikatsmanager genehmigt werden.
- **Anmeldungsagenten und autorisierte Signaturen**: Geben die Anzahl der erforderlichen Signaturen auf einem CSR und die notwendigen Anwendungsrichtlinien-OIDs an.

### Methoden zur Anforderung von Zertifikaten

Zertifikate können angefordert werden über:
1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), unter Verwendung von DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR), über benannte Pipes oder TCP/IP.
3. Die **Zertifikatsanmeldungs-Webschnittstelle**, mit der Rolle der Webanmeldung der Zertifizierungsstelle installiert.
4. Der **Zertifikatsanmeldedienst** (CES), in Verbindung mit dem Zertifikatsanmeldepolitikdienst (CEP).
5. Der **Network Device Enrollment Service** (NDES) für Netzwerkgeräte, unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können auch Zertifikate über die GUI (`certmgr.msc` oder `certlm.msc`) oder Befehlszeilentools (`certreq.exe` oder PowerShells `Get-Certificate`-Befehl) anfordern.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatauthentifizierung

Active Directory (AD) unterstützt die Zertifikatauthentifizierung, hauptsächlich unter Verwendung der **Kerberos**- und **Secure Channel (Schannel)**-Protokolle.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage unterliegt mehreren Validierungen durch den Domänencontroller, einschließlich der **Gültigkeit**, **Pfad** und **Widerrufsstatus** des Zertifikats. Zu den Validierungen gehört auch die Überprüfung, dass das Zertifikat von einer vertrauenswürdigen Quelle stammt und die Bestätigung der Anwesenheit des Ausstellers im **NTAUTH-Zertifikatspeicher**. Erfolgreiche Validierungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is zentral für die Etablierung von Vertrauen für die Zertifikatauthentifizierung.

### Secure Channel (Schannel) Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen, bei denen der Client während eines Handshakes ein Zertifikat präsentiert, das, wenn es erfolgreich validiert wird, den Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann die **S4U2Self**-Funktion von Kerberos oder den **Subject Alternative Name (SAN)** des Zertifikats sowie andere Methoden umfassen.

### AD-Zertifikatdienste Aufzählung

Die Zertifikatdienste von AD können durch LDAP-Abfragen aufgezählt werden, die Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offenbaren. Dies ist für jeden domänenauthentifizierten Benutzer ohne besondere Berechtigungen zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Aufzählung und Schwachstellenbewertung in AD CS-Umgebungen verwendet.

Befehle zur Verwendung dieser Tools umfassen:
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
