# Zertifikate

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Was ist ein Zertifikat

Ein **öffentlicher Schlüsselzertifikat** ist eine digitale ID, die in der Kryptographie verwendet wird, um zu beweisen, dass jemand im Besitz eines öffentlichen Schlüssels ist. Es enthält die Details des Schlüssels, die Identität des Besitzers (das Subjekt) und eine digitale Signatur einer vertrauenswürdigen Behörde (dem Aussteller). Wenn die Software dem Aussteller vertraut und die Signatur gültig ist, ist eine sichere Kommunikation mit dem Besitzer des Schlüssels möglich.

Zertifikate werden hauptsächlich von [Zertifizierungsstellen](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) in einer [Public-Key-Infrastruktur](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI)-Konfiguration ausgestellt. Eine andere Methode ist das [Vertrauensnetzwerk](https://en.wikipedia.org/wiki/Web\_of\_trust), bei dem Benutzer die Schlüssel anderer direkt überprüfen. Das gängige Format für Zertifikate ist [X.509](https://en.wikipedia.org/wiki/X.509), das gemäß RFC 5280 für spezifische Anforderungen angepasst werden kann.

## x509 Gemeinsame Felder

### **Gemeinsame Felder in x509-Zertifikaten**

In x509-Zertifikaten spielen mehrere **Felder** eine entscheidende Rolle für die Gültigkeit und Sicherheit des Zertifikats. Hier ist eine Aufschlüsselung dieser Felder:

* Die **Versionsnummer** kennzeichnet die Version des x509-Formats.
* Die **Seriennummer** identifiziert das Zertifikat eindeutig innerhalb des Systems einer Zertifizierungsstelle (CA), hauptsächlich zur Nachverfolgung von Widerrufungen.
* Das **Subjekt**-Feld repräsentiert den Besitzer des Zertifikats, der eine Maschine, eine Person oder eine Organisation sein kann. Es enthält detaillierte Identifikationen wie:
* **Common Name (CN)**: Domänen, die vom Zertifikat abgedeckt sind.
* **Land (C)**, **Ort (L)**, **Bundesland oder Provinz (ST, S oder P)**, **Organisation (O)** und **Organisationseinheit (OU)** bieten geografische und organisatorische Details.
* Der **Distinguished Name (DN)** umfasst die vollständige Subjektidentifikation.
* Der **Aussteller** gibt an, wer das Zertifikat überprüft und signiert hat, einschließlich ähnlicher Unterfelder wie das Subjekt für die CA.
* Der **Gültigkeitszeitraum** wird durch Zeitstempel **Not Before** und **Not After** markiert, um sicherzustellen, dass das Zertifikat nicht vor oder nach einem bestimmten Datum verwendet wird.
* Der Abschnitt **Öffentlicher Schlüssel**, der für die Sicherheit des Zertifikats entscheidend ist, gibt Algorithmus, Größe und andere technische Details des öffentlichen Schlüssels an.
* **x509v3-Erweiterungen** verbessern die Funktionalität des Zertifikats und geben **Schlüsselverwendung**, **Erweiterte Schlüsselverwendung**, **Alternativer Subjektname** und andere Eigenschaften an, um die Anwendung des Zertifikats zu optimieren.

#### **Schlüsselverwendung und Erweiterungen**

* **Schlüsselverwendung** identifiziert kryptografische Anwendungen des öffentlichen Schlüssels, wie digitale Signatur oder Schlüsselverschlüsselung.
* **Erweiterte Schlüsselverwendung** grenzt die Anwendungsfälle des Zertifikats weiter ein, z. B. für die TLS-Serverauthentifizierung.
* **Alternativer Subjektname** und **Grundlegende Einschränkung** definieren zusätzliche Hostnamen, die vom Zertifikat abgedeckt sind, und ob es sich um ein CA- oder Endgerätezertifikat handelt.
* Bezeichner wie **Subjektschlüsselkennung** und **Ausstellungsschlüsselkennung** gewährleisten Eindeutigkeit und Rückverfolgbarkeit von Schlüsseln.
* **Behördeninformationszugriff** und **CRL-Verteilungspunkte** bieten Pfade zur Überprüfung der ausstellenden CA und zur Überprüfung des Widerrufsstatus des Zertifikats.
* **CT-Vor-Zertifikat-SCTs** bieten Transparenzprotokolle, die für das öffentliche Vertrauen in das Zertifikat entscheidend sind.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Unterschied zwischen OCSP und CRL-Verteilungspunkten**

**OCSP** (**RFC 2560**) beinhaltet einen Client und einen Responder, die zusammenarbeiten, um zu überprüfen, ob ein digitales öffentliches Schlüsselzertifikat widerrufen wurde, ohne die vollständige **CRL** herunterladen zu müssen. Diese Methode ist effizienter als die traditionelle **CRL**, die eine Liste der widerrufenen Zertifikats-Seriennummern bereitstellt, aber das Herunterladen einer potenziell großen Datei erfordert. CRLs können bis zu 512 Einträge enthalten. Weitere Details sind [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm) verfügbar.

### **Was ist Zertifikatstransparenz**

Zertifikatstransparenz hilft, zertifikatsbezogene Bedrohungen zu bekämpfen, indem sichergestellt wird, dass die Ausstellung und Existenz von SSL-Zertifikaten für Domain-Besitzer, CAs und Benutzer sichtbar sind. Ihre Ziele sind:

* Verhindern, dass CAs SSL-Zertifikate für eine Domain ausstellen, ohne dass der Domain-Besitzer davon weiß.
* Ein offenes Prüfsystem zur Verfolgung irrtümlich oder bösartig ausgestellter Zertifikate etablieren.
* Benutzer vor betrügerischen Zertifikaten schützen.

#### **Zertifikat-Logs**

Zertifikat-Logs sind öffentlich überprüfbare, nur anhängbare Aufzeichnungen von Zertifikaten, die von Netzwerkdiensten gepflegt werden. Diese Logs bieten kryptografische Beweise für Prüfzwecke. Ausstellungsbehörden und die Öffentlichkeit können Zertifikate an diese Logs übermitteln oder sie zur Überprüfung abfragen. Obwohl die genaue Anzahl der Log-Server nicht festgelegt ist, wird erwartet, dass sie weltweit weniger als tausend sind. Diese Server können unabhängig von CAs, ISPs oder jeder interessierten Partei verwaltet werden.

#### **Abfrage**

Um Zertifikatstransparenz-Logs für eine beliebige Domain zu erkunden, besuchen Sie [https://crt.sh/](https://crt.sh).

Es existieren verschiedene Formate zum Speichern von Zertifikaten, jedes mit eigenen Anwendungsfällen und Kompatibilität. Diese Zusammenfassung behandelt die Hauptformate und bietet Anleitungen zur Konvertierung zwischen ihnen.

## **Formate**

### **PEM-Format**

* Am weitesten verbreitetes Format für Zertifikate.
* Erfordert separate Dateien für Zertifikate und private Schlüssel, codiert in Base64 ASCII.
* Übliche Erweiterungen: .cer, .crt, .pem, .key.
* Hauptsächlich von Apache und ähnlichen Servern verwendet.

### **DER-Format**

* Ein binäres Format von Zertifikaten.
* Fehlt den "BEGIN/END CERTIFICATE"-Anweisungen, die in PEM-Dateien zu finden sind.
* Übliche Erweiterungen: .cer, .der.
* Wird häufig mit Java-Plattformen verwendet.

### **P7B/PKCS#7-Format**

* Gespeichert in Base64 ASCII, mit Erweiterungen .p7b oder .p7c.
* Enthält nur Zertifikate und Zertifikatsketten, ohne den privaten Schlüssel.
* Unterstützt von Microsoft Windows und Java Tomcat.

### **PFX/P12/PKCS#12-Format**

* Ein binäres Format, das Serverzertifikate, Zwischenzertifikate und private Schlüssel in einer Datei kapselt.
* Erweiterungen: .pfx, .p12.
* Hauptsächlich auf Windows für den Import und Export von Zertifikaten verwendet.

### **Konvertierung von Formaten**

**PEM-Konvertierungen** sind für die Kompatibilität unerlässlich:

* **x509 zu PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM zu DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER zu PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM zu P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 zu PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX-Konvertierungen** sind entscheidend für das Verwalten von Zertifikaten unter Windows:

* **PFX zu PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX zu PKCS#8** beinhaltet zwei Schritte:
1. Konvertiere PFX zu PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konvertiere PEM zu PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B zu PFX** erfordert auch zwei Befehle:
1. Konvertiere P7B zu CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konvertiere CER und privaten Schlüssel in PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
