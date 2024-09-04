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


## Access Tokens

Kila **mtumiaji aliyeingia** kwenye mfumo **ana token ya ufikiaji yenye taarifa za usalama** kwa ajili ya kikao hicho cha kuingia. Mfumo huunda token ya ufikiaji wakati mtumiaji anapoingia. **Kila mchakato unaotekelezwa** kwa niaba ya mtumiaji **una nakala ya token ya ufikiaji**. Token hiyo inatambulisha mtumiaji, vikundi vya mtumiaji, na ruhusa za mtumiaji. Token pia ina SID ya kuingia (Identifier ya Usalama) inayotambulisha kikao cha sasa cha kuingia.

Unaweza kuona taarifa hii kwa kutekeleza `whoami /all`
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
The **access token** ina **rejea** ya vikao vya kuingia ndani ya **LSASS**, hii ni muhimu ikiwa mchakato unahitaji kufikia vitu fulani vya mtandao.\
Unaweza kuzindua mchakato ambao **unatumia sifa tofauti za kufikia huduma za mtandao** kwa kutumia:
```
runas /user:domain\username /netonly cmd.exe
```
This is useful if you have useful credentials to access objects in the network but those credentials aren't valid inside the current host as they are only going to be used in the network (in the current host your current user privileges will be used).

### Types of tokens

There are two types of tokens available:

* **Primary Token**: Inatumika kama uwakilishi wa sifa za usalama za mchakato. Uundaji na uhusiano wa tokeni za msingi na michakato ni vitendo vinavyohitaji mamlaka ya juu, ikisisitiza kanuni ya kutenganisha mamlaka. Kwa kawaida, huduma ya uthibitishaji inawajibika kwa uundaji wa tokeni, wakati huduma ya kuingia inashughulikia uhusiano wake na kiolesura cha mfumo wa uendeshaji wa mtumiaji. Inafaa kutaja kwamba michakato inarithi tokeni ya msingi ya mchakato wake wa mzazi wakati wa uundaji.
* **Impersonation Token**: Inamuwezesha programu ya seva kuchukua kitambulisho cha mteja kwa muda ili kufikia vitu salama. Mekanismu hii imegawanywa katika viwango vinne vya uendeshaji:
* **Anonymous**: Inatoa ufikiaji wa seva sawa na wa mtumiaji asiyejulikana.
* **Identification**: Inaruhusu seva kuthibitisha kitambulisho cha mteja bila kukitumia kwa ufikiaji wa vitu.
* **Impersonation**: Inamwezesha seva kufanya kazi chini ya kitambulisho cha mteja.
* **Delegation**: Ni sawa na Impersonation lakini inajumuisha uwezo wa kupanua dhana hii ya kitambulisho kwa mifumo ya mbali ambayo seva inawasiliana nayo, kuhakikisha uhifadhi wa sifa.

#### Impersonate Tokens

Using the _**incognito**_ module of metasploit if you have enough privileges you can easily **list** and **impersonate** other **tokens**. This could be useful to perform **actions as if you where the other user**. You could also **escalate privileges** with this technique.

### Token Privileges

Learn which **token privileges can be abused to escalate privileges:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Take a look to [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

Learn more about tokens in this tutorials: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) and [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)


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
