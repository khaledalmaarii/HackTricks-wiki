# AD CS Zertifikat Diebstahl

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

**Dies ist eine kurze Zusammenfassung der Diebstahlkapitel der großartigen Forschung von [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Was kann ich mit einem Zertifikat tun

Bevor Sie herausfinden, wie Sie die Zertifikate stehlen können, finden Sie hier einige Informationen darüber, wofür das Zertifikat nützlich ist:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportieren von Zertifikaten mithilfe der Crypto-APIs – DIEBSTAHL1

In einer **interaktiven Desktop-Sitzung** kann das Extrahieren eines Benutzer- oder Maschinenzertifikats zusammen mit dem privaten Schlüssel einfach durchgeführt werden, insbesondere wenn der **private Schlüssel exportierbar ist**. Dies kann erreicht werden, indem man zum Zertifikat in `certmgr.msc` navigiert, mit der rechten Maustaste darauf klickt und `Alle Aufgaben → Exportieren` auswählt, um eine passwortgeschützte .pfx-Datei zu generieren.

Für einen **programmatischen Ansatz** stehen Tools wie das PowerShell-Cmdlet `ExportPfxCertificate` oder Projekte wie [TheWover's CertStealer C#-Projekt](https://github.com/TheWover/CertStealer) zur Verfügung. Diese nutzen die **Microsoft CryptoAPI** (CAPI) oder die Cryptography API: Next Generation (CNG), um mit dem Zertifikatsspeicher zu interagieren. Diese APIs bieten eine Reihe von kryptografischen Diensten, einschließlich derjenigen, die für die Zertifikatspeicherung und -authentifizierung erforderlich sind.

Wenn jedoch ein privater Schlüssel als nicht exportierbar festgelegt ist, blockieren sowohl CAPI als auch CNG normalerweise die Extraktion solcher Zertifikate. Um diese Einschränkung zu umgehen, können Tools wie **Mimikatz** eingesetzt werden. Mimikatz bietet die Befehle `crypto::capi` und `crypto::cng`, um die jeweiligen APIs zu patchen und so die Exportierung privater Schlüssel zu ermöglichen. Speziell `crypto::capi` patcht die CAPI im aktuellen Prozess, während `crypto::cng` den Speicher von **lsass.exe** zum Patchen verwendet.

## Diebstahl von Benutzerzertifikaten über DPAPI – DIEBSTAHL2

Weitere Informationen zu DPAPI finden Sie unter:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows werden **private Schlüssel von Zertifikaten durch DPAPI geschützt**. Es ist wichtig zu beachten, dass die **Speicherorte für Benutzer- und Maschinenprivate Schlüssel** unterschiedlich sind und die Dateistrukturen je nach der von dem Betriebssystem verwendeten kryptografischen API variieren. Das Tool **SharpDPAPI** kann diese Unterschiede automatisch erkennen, wenn es die DPAPI-Blobs entschlüsselt.

**Benutzerzertifikate** befinden sich hauptsächlich in der Registrierung unter `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, aber einige können auch im Verzeichnis `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` gefunden werden. Die entsprechenden **privaten Schlüssel** für diese Zertifikate werden in der Regel in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` für **CAPI**-Schlüssel und `%APPDATA%\Microsoft\Crypto\Keys\` für **CNG**-Schlüssel gespeichert.

Um ein Zertifikat und den zugehörigen privaten Schlüssel zu **extrahieren**, umfasst der Prozess folgende Schritte:

1. **Auswahl des Zielzertifikats** aus dem Speicher des Benutzers und Abrufen des Namen des Schlüsselspeichers.
2. **Auffinden des erforderlichen DPAPI-Meisterkeys**, um den entsprechenden privaten Schlüssel zu entschlüsseln.
3. **Entschlüsseln des privaten Schlüssels**, indem der Klartext-DPAPI-Meisterkey verwendet wird.

Für das **Erhalten des Klartext-DPAPI-Meisterkeys** können die folgenden Ansätze verwendet werden:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Um die Entschlüsselung von Masterkey-Dateien und privaten Schlüsseldateien zu optimieren, erweist sich der Befehl `certificates` von [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) als nützlich. Er akzeptiert `/pvk`, `/mkfile`, `/password` oder `{GUID}:KEY` als Argumente, um die privaten Schlüssel und zugehörigen Zertifikate zu entschlüsseln und anschließend eine `.pem`-Datei zu generieren.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Maschinenzertifikat-Diebstahl über DPAPI – THEFT3

Maschinenzertifikate, die von Windows im Registrierungsschlüssel `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` gespeichert werden, und die dazugehörigen privaten Schlüssel, die sich in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (für CAPI) und `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (für CNG) befinden, werden mit den DPAPI-Masterschlüsseln der Maschine verschlüsselt. Diese Schlüssel können nicht mit dem DPAPI-Backup-Schlüssel der Domäne entschlüsselt werden. Stattdessen wird der **DPAPI_SYSTEM LSA-Secret** benötigt, auf den nur der SYSTEM-Benutzer zugreifen kann.

Die manuelle Entschlüsselung kann durch Ausführen des Befehls `lsadump::secrets` in **Mimikatz** erreicht werden, um das DPAPI_SYSTEM LSA-Secret zu extrahieren, und anschließend wird dieser Schlüssel verwendet, um die Maschinen-Masterschlüssel zu entschlüsseln. Alternativ kann der Befehl `crypto::certificates /export /systemstore:LOCAL_MACHINE` von Mimikatz verwendet werden, nachdem CAPI/CNG wie zuvor beschrieben gepatcht wurde.

**SharpDPAPI** bietet einen automatisierteren Ansatz mit seinem Befehl `certificates`. Wenn die Option `/machine` mit erhöhten Berechtigungen verwendet wird, eskaliert sie zu SYSTEM, dumpet das DPAPI_SYSTEM LSA-Secret, verwendet es zur Entschlüsselung der Maschinen-DPAPI-Masterschlüssel und verwendet dann diese Klartextschlüssel als Suchtabelle zur Entschlüsselung beliebiger privater Maschinenzertifikatsschlüssel.


## Auffinden von Zertifikatdateien – THEFT4

Zertifikate werden manchmal direkt im Dateisystem gefunden, z. B. in Dateifreigaben oder im Download-Ordner. Die am häufigsten in Windows-Umgebungen anzutreffenden Arten von Zertifikatdateien sind `.pfx`- und `.p12`-Dateien. Weniger häufig treten auch Dateien mit den Erweiterungen `.pkcs12` und `.pem` auf. Weitere bemerkenswerte Zertifikatdateierweiterungen sind:
- `.key` für private Schlüssel,
- `.crt`/`.cer` nur für Zertifikate,
- `.csr` für Zertifikatanforderungen, die keine Zertifikate oder privaten Schlüssel enthalten,
- `.jks`/`.keystore`/`.keys` für Java Key Stores, die Zertifikate zusammen mit privaten Schlüsseln enthalten können, die von Java-Anwendungen verwendet werden.

Diese Dateien können mit PowerShell oder der Eingabeaufforderung durch Suche nach den genannten Erweiterungen gesucht werden.

In Fällen, in denen eine PKCS#12-Zertifikatdatei gefunden wird und sie durch ein Passwort geschützt ist, ist es möglich, den Hash durch Verwendung von `pfx2john.py` zu extrahieren, das auf [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) verfügbar ist. Anschließend kann JohnTheRipper verwendet werden, um zu versuchen, das Passwort zu knacken.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM-Anmeldeinformationen-Diebstahl über PKINIT – THEFT5

Der folgende Inhalt erklärt eine Methode für den Diebstahl von NTLM-Anmeldeinformationen über PKINIT, speziell durch die als THEFT5 bezeichnete Diebstahlsmethode. Hier ist eine erneute Erklärung in der Passivform, wobei der Inhalt anonymisiert und gegebenenfalls zusammengefasst wird:

Um die NTLM-Authentifizierung [MS-NLMP] für Anwendungen zu unterstützen, die keine Kerberos-Authentifizierung ermöglichen, ist der KDC so konzipiert, dass er die NTLM-Einwegfunktion (OWF) des Benutzers im Privileg-Attribut-Zertifikat (PAC) zurückgibt, speziell im `PAC_CREDENTIAL_INFO`-Puffer, wenn PKCA verwendet wird. Folglich wird, wenn ein Konto sich über PKINIT authentifiziert und ein Ticket-Granting Ticket (TGT) sichert, automatisch ein Mechanismus bereitgestellt, der es dem aktuellen Host ermöglicht, den NTLM-Hash aus dem TGT zu extrahieren, um veraltete Authentifizierungsprotokolle aufrechtzuerhalten. Dieser Prozess beinhaltet die Entschlüsselung der `PAC_CREDENTIAL_DATA`-Struktur, die im Wesentlichen eine NDR-serialisierte Darstellung des NTLM-Klartexts ist.

Das Dienstprogramm **Kekeo**, erreichbar unter [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), wird als in der Lage erwähnt, ein TGT anzufordern, das diese spezifischen Daten enthält und somit die Wiederherstellung des NTLM des Benutzers ermöglicht. Der für diesen Zweck verwendete Befehl lautet wie folgt:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Zusätzlich wird darauf hingewiesen, dass Kekeo Zertifikate, die durch Smartcards geschützt sind, verarbeiten kann, sofern die PIN abgerufen werden kann. Hierzu wird auf [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) verwiesen. Die gleiche Funktionalität wird auch von **Rubeus** unterstützt, das unter [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) verfügbar ist.

Diese Erklärung umfasst den Prozess und die Tools, die bei der NTLM-Anmeldeinformationen-Diebstahl über PKINIT beteiligt sind. Dabei liegt der Fokus auf dem Abrufen von NTLM-Hashes über TGT, die mit PKINIT erhalten wurden, sowie den Dienstprogrammen, die diesen Prozess erleichtern.

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
