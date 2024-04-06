# Access Tokens

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Vitambulisho vya Upatikanaji

Kila **mtumiaji aliyeingia** kwenye mfumo **ana kitambulisho cha upatikanaji chenye habari za usalama** kwa kikao hicho cha kuingia. Mfumo hujenga kitambulisho cha upatikanaji wakati mtumiaji anaingia kwenye mfumo. **Kila mchakato unaoendeshwa** kwa niaba ya mtumiaji **una nakala ya kitambulisho cha upatikanaji**. Kitambulisho hicho kinamtambulisha mtumiaji, vikundi vya mtumiaji, na mamlaka za mtumiaji. Kitambulisho pia kinajumuisha SID ya kuingia (Kitambulisho cha Usalama) ambayo inamtambulisha kikao cha kuingia cha sasa.

Unaweza kuona habari hii kwa kutekeleza `whoami /all`

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

au tumia _Process Explorer_ kutoka Sysinternals (chagua mchakato na ufikie kichupo cha "Usalama"):

![](<../../.gitbook/assets/image (321).png>)

### Msimamizi wa ndani

Wakati msimamizi wa ndani anapoingia, **vitambulisho viwili vya ufikiaji** vinatengenezwa: Kimoja chenye haki za msimamizi na kingine chenye haki za kawaida. **Kwa chaguo-msingi**, wakati mtumiaji huyu anatekeleza mchakato, kile chenye haki za **kawaida** (si msimamizi) **kitatumika**. Wakati mtumiaji huyu anapojaribu **kutekeleza** kitu **kama msimamizi** ("Tekeleza kama Msimamizi" kwa mfano), **UAC** itatumika kuomba idhini.\
Ikiwa unataka [**kujifunza zaidi kuhusu UAC soma ukurasa huu**](../authentication-credentials-uac-and-efs/#uac)**.**

### Uigizaji wa mtumiaji wa vitambulisho

Ikiwa una **vitambulisho halali vya mtumiaji mwingine yeyote**, unaweza **kuunda** kikao kipya cha kuingia kwa kutumia vitambulisho hivyo:

```
runas /user:domain\username cmd.exe
```

**Kitambulisho cha ufikiaji** pia kina **marejeleo** ya vikao vya kuingia ndani ya **LSASS**, hii ni muhimu ikiwa mchakato unahitaji kupata baadhi ya vitu vya mtandao.\
Unaweza kuzindua mchakato ambao **unatumia sifa tofauti za kufikia huduma za mtandao** kwa kutumia:

```
runas /user:domain\username /netonly cmd.exe
```

Hii ni muhimu ikiwa una sifa muhimu za kupata vitu katika mtandao lakini sifa hizo hazifai ndani ya mwenyeji wa sasa kwani zitatumika tu katika mtandao (katika mwenyeji wa sasa, sifa za mtumiaji wako wa sasa zitatumika).

### Aina za alama za ufikiaji

Kuna aina mbili za alama za ufikiaji zinazopatikana:

* **Alama Kuu**: Inatumika kama uwakilishi wa sifa za usalama za mchakato. Uundaji na uunganishaji wa alama kuu na michakato ni hatua zinazohitaji mamlaka ya juu, zikisisitiza kanuni ya kutenganisha mamlaka. Kawaida, huduma ya uwakili inahusika na uundaji wa alama, wakati huduma ya kuingia inashughulikia uunganishaji wake na kifaa cha uendeshaji cha mtumiaji. Ni muhimu kutambua kuwa michakato inarithi alama kuu ya mchakato wao wa mzazi wakati wa uundaji.
* **Alama ya Udanganyifu**: Inaruhusu programu ya seva kuiga kitambulisho cha mteja kwa muda ili kupata vitu salama. Mfumo huu umegawanywa katika viwango vinne vya uendeshaji:
* **Anonimasi**: Inaruhusu ufikiaji wa seva kama mtumiaji asiyejulikana.
* **Utambulisho**: Inaruhusu seva kuthibitisha kitambulisho cha mteja bila kuitumia kwa ufikiaji wa vitu.
* **Udanganyifu**: Inawezesha seva kufanya kazi chini ya kitambulisho cha mteja.
* **Uteuzi**: Kama Udanganyifu lakini inajumuisha uwezo wa kueneza dhana hii ya kitambulisho kwa mifumo ya mbali ambayo seva inashirikiana nayo, ikisimamia uhifadhi wa sifa.

#### Udanganyifu wa Alama

Kwa kutumia moduli ya _**incognito**_ ya metasploit ikiwa una mamlaka ya kutosha, unaweza kwa urahisi **kuorodhesha** na **kudanganya** alama nyingine. Hii inaweza kuwa na manufaa kufanya **vitendo kana kwamba wewe ni mtumiaji mwingine**. Pia unaweza **kuongeza mamlaka** na mbinu hii.

### Mamlaka ya Alama

Jifunze ni **mamlaka gani ya alama yanaweza kutumiwa kwa kuongeza mamlaka:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Angalia [**mamlaka zote za alama zinazowezekana na ufafanuzi fulani kwenye ukurasa huu wa nje**](https://github.com/gtworek/Priv2Admin).

## Marejeo

Jifunze zaidi kuhusu alama katika mafunzo haya: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) na [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je! Unafanya kazi katika **kampuni ya usalama wa mtandao**? Je! Unataka kuona **kampuni yako inatangazwa katika HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
