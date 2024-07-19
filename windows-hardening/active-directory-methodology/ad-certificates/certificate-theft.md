# AD CS Zertifikatsdiebstahl

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

**Dies ist eine kleine Zusammenfassung der Diebstahlkapitel der großartigen Forschung von [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## Was kann ich mit einem Zertifikat machen

Bevor du überprüfst, wie man die Zertifikate stiehlt, hast du hier einige Informationen darüber, wie man herausfindet, wofür das Zertifikat nützlich ist:
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
## Exportieren von Zertifikaten mit den Crypto-APIs – THEFT1

In einer **interaktiven Desktop-Sitzung** kann das Extrahieren eines Benutzer- oder Maschinenzertifikats zusammen mit dem privaten Schlüssel einfach durchgeführt werden, insbesondere wenn der **private Schlüssel exportierbar** ist. Dies kann erreicht werden, indem man zu dem Zertifikat in `certmgr.msc` navigiert, mit der rechten Maustaste darauf klickt und `Alle Aufgaben → Exportieren` auswählt, um eine passwortgeschützte .pfx-Datei zu erstellen.

Für einen **programmgesteuerten Ansatz** stehen Tools wie das PowerShell-Cmdlet `ExportPfxCertificate` oder Projekte wie [TheWover’s CertStealer C#-Projekt](https://github.com/TheWover/CertStealer) zur Verfügung. Diese nutzen die **Microsoft CryptoAPI** (CAPI) oder die Cryptography API: Next Generation (CNG), um mit dem Zertifikatspeicher zu interagieren. Diese APIs bieten eine Reihe von kryptografischen Diensten, einschließlich derjenigen, die für die Speicherung und Authentifizierung von Zertifikaten erforderlich sind.

Wenn jedoch ein privater Schlüssel als nicht exportierbar festgelegt ist, blockieren sowohl CAPI als auch CNG normalerweise die Extraktion solcher Zertifikate. Um diese Einschränkung zu umgehen, können Tools wie **Mimikatz** eingesetzt werden. Mimikatz bietet die Befehle `crypto::capi` und `crypto::cng`, um die jeweiligen APIs zu patchen, was die Exportation von privaten Schlüsseln ermöglicht. Insbesondere patcht `crypto::capi` die CAPI innerhalb des aktuellen Prozesses, während `crypto::cng` den Speicher von **lsass.exe** zum Patchen anvisiert.

## Diebstahl von Benutzerzertifikaten über DPAPI – THEFT2

Weitere Informationen zu DPAPI finden Sie in:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

In Windows werden **private Schlüssel von Zertifikaten durch DPAPI** geschützt. Es ist wichtig zu erkennen, dass die **Speicherorte für Benutzer- und Maschinenprivate Schlüssel** unterschiedlich sind und die Dateistrukturen je nach der vom Betriebssystem verwendeten kryptografischen API variieren. **SharpDPAPI** ist ein Tool, das diese Unterschiede automatisch navigieren kann, wenn es darum geht, die DPAPI-Blobs zu entschlüsseln.

**Benutzerzertifikate** befinden sich überwiegend in der Registrierung unter `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, einige sind jedoch auch im Verzeichnis `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` zu finden. Die entsprechenden **privaten Schlüssel** für diese Zertifikate werden typischerweise in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` für **CAPI**-Schlüssel und `%APPDATA%\Microsoft\Crypto\Keys\` für **CNG**-Schlüssel gespeichert.

Um **ein Zertifikat und seinen zugehörigen privaten Schlüssel zu extrahieren**, umfasst der Prozess:

1. **Auswählen des Zielzertifikats** aus dem Benutzerstore und Abrufen des Schlüsselspeichernamens.
2. **Lokalisieren des erforderlichen DPAPI-Masterkeys**, um den entsprechenden privaten Schlüssel zu entschlüsseln.
3. **Entschlüsseln des privaten Schlüssels** durch Verwendung des Klartext-DPAPI-Masterkeys.

Für **den Erwerb des Klartext-DPAPI-Masterkeys** können die folgenden Ansätze verwendet werden:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Um die Entschlüsselung von Masterkey-Dateien und privaten Schlüsseldateien zu optimieren, erweist sich der Befehl `certificates` von [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) als nützlich. Er akzeptiert `/pvk`, `/mkfile`, `/password` oder `{GUID}:KEY` als Argumente, um die privaten Schlüssel und die zugehörigen Zertifikate zu entschlüsseln und anschließend eine `.pem`-Datei zu generieren.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Maschinenzertifikatdiebstahl über DPAPI – THEFT3

Maschinenzertifikate, die von Windows in der Registrierung unter `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` gespeichert sind, und die zugehörigen privaten Schlüssel, die sich in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (für CAPI) und `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (für CNG) befinden, sind mit den DPAPI-Master-Schlüsseln der Maschine verschlüsselt. Diese Schlüssel können nicht mit dem DPAPI-Backup-Schlüssel der Domäne entschlüsselt werden; stattdessen ist das **DPAPI_SYSTEM LSA-Geheimnis**, auf das nur der SYSTEM-Benutzer zugreifen kann, erforderlich.

Die manuelle Entschlüsselung kann erreicht werden, indem der Befehl `lsadump::secrets` in **Mimikatz** ausgeführt wird, um das DPAPI_SYSTEM LSA-Geheimnis zu extrahieren, und anschließend dieser Schlüssel verwendet wird, um die Maschinen-Masterkeys zu entschlüsseln. Alternativ kann der Befehl `crypto::certificates /export /systemstore:LOCAL_MACHINE` von Mimikatz verwendet werden, nachdem CAPI/CNG wie zuvor beschrieben gepatcht wurde.

**SharpDPAPI** bietet einen automatisierteren Ansatz mit seinem Zertifikatsbefehl. Wenn das Flag `/machine` mit erhöhten Berechtigungen verwendet wird, eskaliert es zu SYSTEM, dumpft das DPAPI_SYSTEM LSA-Geheimnis, verwendet es zur Entschlüsselung der Maschinen-DPAPI-Masterkeys und verwendet dann diese Klartextschlüssel als Nachschlagetabelle, um private Schlüssel von Maschinenzertifikaten zu entschlüsseln.


## Finden von Zertifikatdateien – THEFT4

Zertifikate werden manchmal direkt im Dateisystem gefunden, z. B. in Dateifreigaben oder im Downloads-Ordner. Die am häufigsten vorkommenden Arten von Zertifikatdateien, die auf Windows-Umgebungen abzielen, sind `.pfx`- und `.p12`-Dateien. Obwohl seltener, erscheinen auch Dateien mit den Erweiterungen `.pkcs12` und `.pem`. Weitere bemerkenswerte, zertifikatsbezogene Dateierweiterungen sind:
- `.key` für private Schlüssel,
- `.crt`/`.cer` nur für Zertifikate,
- `.csr` für Zertifikatsanforderungen, die keine Zertifikate oder privaten Schlüssel enthalten,
- `.jks`/`.keystore`/`.keys` für Java Keystores, die Zertifikate zusammen mit privaten Schlüsseln enthalten können, die von Java-Anwendungen verwendet werden.

Diese Dateien können mit PowerShell oder der Eingabeaufforderung gesucht werden, indem nach den genannten Erweiterungen gesucht wird.

In Fällen, in denen eine PKCS#12-Zertifikatdatei gefunden wird und sie durch ein Passwort geschützt ist, ist die Extraktion eines Hashs durch die Verwendung von `pfx2john.py` möglich, das unter [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) verfügbar ist. Anschließend kann JohnTheRipper verwendet werden, um zu versuchen, das Passwort zu knacken.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Der gegebene Inhalt erklärt eine Methode zum Diebstahl von NTLM-Anmeldeinformationen über PKINIT, insbesondere durch die Diebstahlmethode, die als THEFT5 bezeichnet wird. Hier ist eine erneute Erklärung in passiver Stimme, wobei der Inhalt anonymisiert und zusammengefasst wurde, wo dies zutreffend ist:

Um die NTLM-Authentifizierung [MS-NLMP] für Anwendungen zu unterstützen, die keine Kerberos-Authentifizierung ermöglichen, ist der KDC so konzipiert, dass er die NTLM-Einwegfunktion (OWF) des Benutzers im Privilegienattributzertifikat (PAC) zurückgibt, insbesondere im `PAC_CREDENTIAL_INFO`-Puffer, wenn PKCA verwendet wird. Folglich, wenn ein Konto sich authentifiziert und ein Ticket-Granting Ticket (TGT) über PKINIT sichert, wird ein Mechanismus bereitgestellt, der es dem aktuellen Host ermöglicht, den NTLM-Hash aus dem TGT zu extrahieren, um die Legacy-Authentifizierungsprotokolle aufrechtzuerhalten. Dieser Prozess umfasst die Entschlüsselung der `PAC_CREDENTIAL_DATA`-Struktur, die im Wesentlichen eine NDR-serialisierte Darstellung des NTLM-Plaintexts ist.

Das Tool **Kekeo**, zugänglich unter [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), wird erwähnt, da es in der Lage ist, ein TGT anzufordern, das diese spezifischen Daten enthält, und somit die Abfrage der NTLM-Anmeldeinformationen des Benutzers zu erleichtern. Der für diesen Zweck verwendete Befehl lautet wie folgt:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Zusätzlich wird angemerkt, dass Kekeo smartcard-geschützte Zertifikate verarbeiten kann, sofern die PIN abgerufen werden kann, mit Verweis auf [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Die gleiche Fähigkeit wird auch von **Rubeus** unterstützt, verfügbar unter [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Diese Erklärung fasst den Prozess und die Werkzeuge zusammen, die an dem Diebstahl von NTLM-Anmeldeinformationen über PKINIT beteiligt sind, wobei der Fokus auf dem Abrufen von NTLM-Hashes durch TGT liegt, das mit PKINIT erhalten wurde, sowie den Dienstprogrammen, die diesen Prozess erleichtern.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
