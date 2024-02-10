# Zertifikate

<details>

<summary>Lernen Sie das Hacken von AWS von Null auf Held mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter @hacktricks_live.
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den HackTricks- und HackTricks Cloud-GitHub-Repositories einreichen.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Was ist ein Zertifikat

Ein **öffentlicher Schlüsselzertifikat** ist eine digitale ID, die in der Kryptographie verwendet wird, um nachzuweisen, dass jemand im Besitz eines öffentlichen Schlüssels ist. Es enthält die Details des Schlüssels, die Identität des Eigentümers (das Subjekt) und eine digitale Signatur einer vertrauenswürdigen Behörde (der Aussteller). Wenn die Software dem Aussteller vertraut und die Signatur gültig ist, ist eine sichere Kommunikation mit dem Eigentümer des Schlüssels möglich.

Zertifikate werden hauptsächlich von [Zertifizierungsstellen](https://de.wikipedia.org/wiki/Zertifizierungsstelle) (CAs) in einer [Public-Key-Infrastruktur](https://de.wikipedia.org/wiki/Public-Key-Infrastruktur) (PKI) erstellt. Eine andere Methode ist das [Web of Trust](https://de.wikipedia.org/wiki/Web_of_Trust), bei dem Benutzer die Schlüssel direkt überprüfen. Das gängige Format für Zertifikate ist [X.509](https://de.wikipedia.org/wiki/X.509), das gemäß RFC 5280 an spezifische Anforderungen angepasst werden kann.

## x509 Gemeinsame Felder

### Gemeinsame Felder in x509-Zertifikaten

In x509-Zertifikaten spielen mehrere **Felder** eine wichtige Rolle für die Gültigkeit und Sicherheit des Zertifikats. Hier ist eine Aufschlüsselung dieser Felder:

- Die **Versionsnummer** gibt die Version des x509-Formats an.
- Die **Seriennummer** identifiziert das Zertifikat eindeutig innerhalb des Systems einer Zertifizierungsstelle (CA), hauptsächlich zur Nachverfolgung von Widerrufungen.
- Das **Subjekt**-Feld repräsentiert den Eigentümer des Zertifikats, der eine Maschine, eine Person oder eine Organisation sein kann. Es enthält detaillierte Identifikationen wie:
- **Common Name (CN)**: Domänen, die vom Zertifikat abgedeckt sind.
- **Land (C)**, **Ort (L)**, **Bundesland oder Provinz (ST, S oder P)**, **Organisation (O)** und **Organisationseinheit (OU)** geben geografische und organisatorische Details an.
- **Distinguished Name (DN)** umfasst die vollständige Identifikation des Subjekts.
- **Aussteller** gibt an, wer das Zertifikat überprüft und signiert hat, einschließlich ähnlicher Unterfelder wie beim Subjekt für die CA.
- Der **Gültigkeitszeitraum** wird durch die Zeitstempel **Not Before** und **Not After** markiert und stellt sicher, dass das Zertifikat nicht vor oder nach einem bestimmten Datum verwendet wird.
- Der Abschnitt **Öffentlicher Schlüssel**, der für die Sicherheit des Zertifikats entscheidend ist, gibt die Algorithmus, Größe und andere technische Details des öffentlichen Schlüssels an.
- **x509v3-Erweiterungen** verbessern die Funktionalität des Zertifikats und geben Eigenschaften wie **Key Usage**, **Extended Key Usage**, **Subject Alternative Name** und andere an, um das Zertifikat anwendungsspezifisch anzupassen.

#### **Key Usage und Erweiterungen**

- **Key Usage** identifiziert kryptografische Anwendungen des öffentlichen Schlüssels, wie digitale Signatur oder Schlüsselverschlüsselung.
- **Extended Key Usage** schränkt die Anwendungsfälle des Zertifikats weiter ein, z. B. für die TLS-Serverauthentifizierung.
- **Subject Alternative Name** und **Basic Constraint** definieren zusätzliche Hostnamen, die vom Zertifikat abgedeckt sind, und ob es sich um ein CA- oder Endbenutzerzertifikat handelt.
- Bezeichner wie **Subject Key Identifier** und **Authority Key Identifier** gewährleisten Eindeutigkeit und Rückverfolgbarkeit von Schlüsseln.
- **Authority Information Access** und **CRL Distribution Points** bieten Pfade zur Überprüfung der ausstellenden CA und zur Überprüfung des Widerrufsstatus des Zertifikats.
- **CT Precertificate SCTs** bieten Transparenzprotokolle, die für das öffentliche Vertrauen in das Zertifikat entscheidend sind.
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

**OCSP** (**RFC 2560**) beinhaltet eine Zusammenarbeit zwischen einem Client und einem Responder, um zu überprüfen, ob ein digitales öffentliches Schlüsselzertifikat widerrufen wurde, ohne die vollständige **CRL** herunterladen zu müssen. Diese Methode ist effizienter als die traditionelle **CRL**, die eine Liste der widerrufenen Zertifikatsseriennummern bereitstellt, aber das Herunterladen einer potenziell großen Datei erfordert. CRLs können bis zu 512 Einträge enthalten. Weitere Details finden Sie [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Was ist Certificate Transparency**

Certificate Transparency hilft, zertifikatsbezogene Bedrohungen zu bekämpfen, indem es sicherstellt, dass die Ausstellung und Existenz von SSL-Zertifikaten für Domain-Besitzer, CAs und Benutzer sichtbar sind. Die Ziele sind:

* Verhindern, dass CAs SSL-Zertifikate für eine Domain ohne das Wissen des Domain-Besitzers ausstellen.
* Einrichtung eines offenen Prüfsystems zur Verfolgung von irrtümlich oder bösartig ausgestellten Zertifikaten.
* Benutzer vor betrügerischen Zertifikaten schützen.

#### **Zertifikatsprotokolle**

Zertifikatsprotokolle sind öffentlich überprüfbare, nur anhängbare Aufzeichnungen von Zertifikaten, die von Netzwerkdiensten verwaltet werden. Diese Protokolle bieten kryptografische Nachweise für Prüfungszwecke. Sowohl Ausgabestellen als auch die Öffentlichkeit können Zertifikate in diese Protokolle einreichen oder sie zur Überprüfung abfragen. Die genaue Anzahl der Protokollserver ist nicht festgelegt, es wird jedoch erwartet, dass sie weltweit weniger als tausend sind. Diese Server können unabhängig von CAs, ISPs oder anderen interessierten Einrichtungen verwaltet werden.

#### **Abfrage**

Um Certificate Transparency-Protokolle für eine beliebige Domain zu erkunden, besuchen Sie [https://crt.sh/](https://crt.sh).

Es gibt verschiedene Formate zur Speicherung von Zertifikaten, von denen jedes seine eigenen Anwendungsfälle und Kompatibilität hat. Diese Zusammenfassung behandelt die wichtigsten Formate und gibt Anleitungen zur Konvertierung zwischen ihnen.

## **Formate**

### **PEM-Format**
- Am häufigsten verwendetes Format für Zertifikate.
- Erfordert separate Dateien für Zertifikate und private Schlüssel, codiert in Base64 ASCII.
- Häufige Erweiterungen: .cer, .crt, .pem, .key.
- Hauptsächlich von Apache und ähnlichen Servern verwendet.

### **DER-Format**
- Ein binäres Format von Zertifikaten.
- Enthält nicht die "BEGIN/END CERTIFICATE"-Anweisungen, die in PEM-Dateien zu finden sind.
- Häufige Erweiterungen: .cer, .der.
- Wird oft mit Java-Plattformen verwendet.

### **P7B/PKCS#7-Format**
- Gespeichert in Base64 ASCII mit den Erweiterungen .p7b oder .p7c.
- Enthält nur Zertifikate und Kettenzertifikate, ohne den privaten Schlüssel.
- Unterstützt von Microsoft Windows und Java Tomcat.

### **PFX/P12/PKCS#12-Format**
- Ein binäres Format, das Serverzertifikate, Zwischenzertifikate und private Schlüssel in einer Datei zusammenfasst.
- Erweiterungen: .pfx, .p12.
- Hauptsächlich auf Windows für den Import und Export von Zertifikaten verwendet.

### **Konvertierung von Formaten**

**PEM-Konvertierungen** sind für die Kompatibilität unerlässlich:

- **x509 zu PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM zu DER**

To convert a PEM (Privacy-Enhanced Mail) certificate file to DER (Distinguished Encoding Rules) format, you can use the OpenSSL command-line tool.

```plaintext
openssl x509 -outform der -in certificate.pem -out certificate.der
```

This command will take the input file `certificate.pem` in PEM format and convert it to DER format, saving the output as `certificate.der`.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER zu PEM**

Um ein Zertifikat im DER-Format in das PEM-Format zu konvertieren, können Sie den folgenden Befehl verwenden:

```bash
openssl x509 -inform der -in certificate.der -out certificate.pem
```

Ersetzen Sie `certificate.der` durch den Pfad zu Ihrer DER-Datei und `certificate.pem` durch den gewünschten Namen für die PEM-Datei.
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM zu P7B**

To convert a PEM certificate file to P7B format, you can use the OpenSSL command-line tool. The P7B format is commonly used for certificate chain files.

Here is the command to convert a PEM file to P7B:

```plaintext
openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b
```

Replace `certificate.pem` with the path to your PEM file, and `certificate.p7b` with the desired output file name.

This command will create a P7B file containing the certificate(s) from the PEM file. The `-nocrl` option is used to exclude any Certificate Revocation Lists (CRLs) from the output.

After running the command, you will have the converted P7B file ready for use.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 zu PEM**

To convert a PKCS7 certificate to PEM format, you can use the following OpenSSL command:

```plaintext
openssl pkcs7 -print_certs -in certificate.p7b -out certificate.pem
```

This command will extract the certificates from the PKCS7 file and save them in PEM format in the specified output file.

Make sure you have OpenSSL installed on your system before running this command.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX-Konvertierungen** sind entscheidend für das Verwalten von Zertifikaten unter Windows:

- **PFX zu PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX zu PKCS#8** umwandeln erfordert zwei Schritte:
1. PFX in PEM umwandeln
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM in PKCS8 umwandeln

Manchmal müssen Sie möglicherweise ein Zertifikat im PEM-Format in das PKCS8-Format konvertieren. Dies kann nützlich sein, wenn Sie das Zertifikat in einer bestimmten Anwendung verwenden möchten, die nur das PKCS8-Format akzeptiert.

Um ein PEM-Zertifikat in das PKCS8-Format umzuwandeln, können Sie das OpenSSL-Tool verwenden. Verwenden Sie den folgenden Befehl:

```plaintext
openssl pkcs8 -topk8 -inform PEM -outform DER -in certificate.pem -out privatekey.pk8
```

Ersetzen Sie "certificate.pem" durch den Dateinamen des PEM-Zertifikats, das Sie konvertieren möchten, und "privatekey.pk8" durch den gewünschten Dateinamen für das PKCS8-Zertifikat.

Nachdem Sie den Befehl ausgeführt haben, wird das PEM-Zertifikat in das PKCS8-Format konvertiert und in der angegebenen Datei gespeichert. Sie können dann das PKCS8-Zertifikat in Ihrer Anwendung verwenden.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B zu PFX** erfordert ebenfalls zwei Befehle:
1. Konvertiere P7B zu CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konvertieren Sie CER und privaten Schlüssel in PFX

Manchmal müssen Sie möglicherweise ein Zertifikat im CER-Format und den dazugehörigen privaten Schlüssel in das PFX-Format konvertieren. Dies kann nützlich sein, wenn Sie das Zertifikat auf einem anderen System verwenden möchten, das das PFX-Format erfordert.

Um CER und privaten Schlüssel in PFX zu konvertieren, können Sie die OpenSSL-Befehlszeilentools verwenden. Stellen Sie sicher, dass Sie OpenSSL auf Ihrem System installiert haben, bevor Sie fortfahren.

Führen Sie den folgenden Befehl aus, um die Konvertierung durchzuführen:

```plaintext
openssl pkcs12 -export -out certificate.pfx -inkey privatekey.key -in certificate.cer
```

Ersetzen Sie `privatekey.key` durch den Pfad zu Ihrem privaten Schlüssel und `certificate.cer` durch den Pfad zu Ihrem Zertifikat im CER-Format. Der Befehl erstellt eine neue Datei mit dem Namen `certificate.pfx`, die das konvertierte Zertifikat und den privaten Schlüssel enthält.

Sie werden aufgefordert, ein Kennwort für die PFX-Datei einzugeben. Geben Sie ein sicheres Kennwort ein und merken Sie es sich gut, da es zum Importieren des PFX-Zertifikats verwendet wird.

Nachdem der Befehl erfolgreich ausgeführt wurde, haben Sie eine PFX-Datei erstellt, die das Zertifikat und den privaten Schlüssel enthält. Sie können diese Datei nun auf anderen Systemen verwenden, die das PFX-Format unterstützen.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
