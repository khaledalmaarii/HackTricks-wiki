# Access Tokens

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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utafutaji inayotumiwa na **dark-web** ambayo inatoa kazi za **bure** kuangalia kama kampuni au wateja wake wamekuwa **compromised** na **stealer malwares**.

Lengo lao kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulizi ya ransomware yanayotokana na malware inayopora taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao kwa **bure** kwenye:

{% embed url="https://whiteintel.io" %}

***

## Access Tokens

Kila **mtumiaji aliyeingia** kwenye mfumo **ana token ya ufikiaji yenye taarifa za usalama** kwa ajili ya kikao hicho cha kuingia. Mfumo huunda token ya ufikiaji wakati mtumiaji anaingia. **Kila mchakato unaotekelezwa** kwa niaba ya mtumiaji **una nakala ya token ya ufikiaji**. Token hiyo inatambulisha mtumiaji, vikundi vya mtumiaji, na ruhusa za mtumiaji. Token pia ina SID ya kuingia (Identifier ya Usalama) inayotambulisha kikao cha sasa cha kuingia.

Unaweza kuona taarifa hii ukitekeleza `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### Msimamizi wa ndani

Wakati msimamizi wa ndani anapoingia, **tokeni mbili za ufikiaji zinaundwa**: Moja ikiwa na haki za msimamizi na nyingine ikiwa na haki za kawaida. **Kwa default**, wakati mtumiaji huyu anatekeleza mchakato, ile yenye **haki za kawaida** (zisizo za msimamizi) **inatumika**. Wakati mtumiaji huyu anajaribu **kutekeleza** chochote **kama msimamizi** ("Run as Administrator" kwa mfano) **UAC** itatumika kuomba ruhusa.\
Ikiwa unataka [**kujifunza zaidi kuhusu UAC soma ukurasa huu**](../authentication-credentials-uac-and-efs/#uac)**.**

### Ujanja wa utambulisho wa mtumiaji

Ikiwa una **uthibitisho halali wa mtumiaji mwingine yeyote**, unaweza **kuunda** **sehemu mpya ya kuingia** kwa kutumia uthibitisho huo:
```
runas /user:domain\username cmd.exe
```
The **access token** ina **rejea** ya vikao vya kuingia ndani ya **LSASS**, hii ni muhimu ikiwa mchakato unahitaji kufikia baadhi ya vitu vya mtandao.\
Unaweza kuzindua mchakato ambao **unatumia sifa tofauti za kufikia huduma za mtandao** kwa kutumia:
```
runas /user:domain\username /netonly cmd.exe
```
Hii ni muhimu ikiwa una akidi muhimu za kufikia vitu katika mtandao lakini akidi hizo si halali ndani ya mwenyeji wa sasa kwani zitatumika tu katika mtandao (katika mwenyeji wa sasa, ruhusa za mtumiaji wako wa sasa zitatumika).

### Aina za tokeni

Kuna aina mbili za tokeni zinazopatikana:

* **Tokeni Kuu**: Inatumika kama uwakilishi wa akidi za usalama za mchakato. Uundaji na uhusiano wa tokeni kuu na michakato ni vitendo vinavyohitaji ruhusa za juu, ikisisitiza kanuni ya kutenganisha ruhusa. Kwa kawaida, huduma ya uthibitishaji inawajibika kwa uundaji wa tokeni, wakati huduma ya kuingia inashughulikia uhusiano wake na kiolesura cha mfumo wa uendeshaji wa mtumiaji. Inafaa kutaja kwamba michakato inarithi tokeni kuu ya mchakato wao wa mzazi wakati wa uundaji.
* **Tokeni ya Kuiga**: Inamuwezesha programu ya seva kuchukua kitambulisho cha mteja kwa muda ili kufikia vitu salama. Mekanismu hii imegawanywa katika viwango vinne vya uendeshaji:
* **Kujulikana**: Inatoa ufikiaji wa seva sawa na wa mtumiaji asiyejulikana.
* **Utambulisho**: Inaruhusu seva kuthibitisha kitambulisho cha mteja bila kukitumia kwa ufikiaji wa vitu.
* **Kuiga**: Inamuwezesha seva kufanya kazi chini ya kitambulisho cha mteja.
* **Delegation**: Kama Kuiga lakini inajumuisha uwezo wa kupanua dhana hii ya kitambulisho kwa mifumo ya mbali ambayo seva inawasiliana nayo, kuhakikisha uhifadhi wa akidi.

#### Tokeni za Kuiga

Kwa kutumia moduli ya _**incognito**_ ya metasploit ikiwa una ruhusa za kutosha unaweza kwa urahisi **orodhesha** na **kuiga** tokeni nyingine. Hii inaweza kuwa muhimu kufanya **vitendo kana kwamba wewe ni mtumiaji mwingine**. Unaweza pia **kuinua ruhusa** kwa kutumia mbinu hii.

### Ruhusa za Tokeni

Jifunze ni zipi **ruhusa za tokeni zinaweza kutumika vibaya ili kuinua ruhusa:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Angalia [**ruhusa zote zinazowezekana za tokeni na baadhi ya maelezo kwenye ukurasa huu wa nje**](https://github.com/gtworek/Priv2Admin).

## Marejeleo

Jifunze zaidi kuhusu tokeni katika mafunzo haya: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) na [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utafutaji inayotumiwa na **dark-web** inayotoa kazi za **bure** kuangalia ikiwa kampuni au wateja wake wamekuwa **wameathiriwa** na **stealer malwares**.

Lengo lao kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulizi ya ransomware yanayotokana na malware ya kuiba taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao **bure** kwenye:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
