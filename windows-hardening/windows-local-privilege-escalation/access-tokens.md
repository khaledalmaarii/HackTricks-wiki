# Vitambulisho vya Kufikia

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa **huduma za bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **programu hasidi za kuiba**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za kuiba taarifa.

Unaweza kuangalia tovuti yao na kujaribu injini yao **bure** kwa:

{% embed url="https://whiteintel.io" %}

***

## Vitambulisho vya Kufikia

Kila **mtumiaji aliyeingia** kwenye mfumo **ana kitambulisho cha kufikia chenye habari za usalama** kwa kikao hicho cha kuingia. Mfumo hutoa kitambulisho cha kufikia wakati mtumiaji anaingia. **Kila mchakato unaoendeshwa** kwa niaba ya mtumiaji **una nakala ya kitambulisho cha kufikia**. Kitambulisho hicho huchambua mtumiaji, vikundi vya mtumiaji, na mamlaka ya mtumiaji. Kitambulisho pia kina SID ya kuingia (Kitambulisho cha Usalama) kinachoidhinisha kikao cha kuingia cha sasa.

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
or using _Process Explorer_ kutoka Sysinternals (chagua mchakato na ufikie kichupo cha "Usalama"):

![](<../../.gitbook/assets/image (772).png>)

### Msimamizi wa Mitaa

Wakati msimamizi wa mitaa anapoingia, **vitambulisho viwili vya ufikiaji** vinajengwa: Kimoja chenye haki za msimamizi na kingine chenye haki za kawaida. **Kwa chaguo-msingi**, wakati mtumiaji huyu anaendesha mchakato, kile chenye **haki za kawaida** (si msimamizi) **hutumiwa**. Wakati mtumiaji huyu anajaribu **kuendesha** kitu **kama msimamizi** ("Chalaza kama Msimamizi" kwa mfano) **UAC** itatumika kuomba idhini.\
Ikiwa unataka [**kujifunza zaidi kuhusu UAC soma ukurasa huu**](../authentication-credentials-uac-and-efs/#uac)**.**

### Uigizaji wa Mtumiaji wa Vitambulisho

Ikiwa una **vitambulisho halali vya mtumiaji mwingine**, unaweza **kuunda** kikao **kipya cha kuingia** kwa kutumia vitambulisho hivyo:
```
runas /user:domain\username cmd.exe
```
**Tokeni ya ufikiaji** pia ina **marejeleo** ya vikao vya kuingia ndani ya **LSASS**, hii ni muhimu ikiwa mchakato unahitaji kupata baadhi ya vitu vya mtandao.\
Unaweza kuzindua mchakato ambao **unatumia sifa tofauti kwa ajili ya kupata huduma za mtandao** kwa kutumia:
```
runas /user:domain\username /netonly cmd.exe
```
Hii ni muhimu ikiwa una sifa muhimu za kupata vitu kwenye mtandao lakini sifa hizo si halali ndani ya mwenyeji wa sasa kwani zitatumika tu kwenye mtandao (katika mwenyeji wa sasa, sifa zako za mtumiaji wa sasa zitatumika).

### Aina za Vyeti

Kuna aina mbili za vyeti zilizopo:

* **Cheti Kuu**: Hufanya kama uwakilishi wa sifa za usalama za mchakato. Uundaji na uunganishaji wa vyeti vya msingi na michakato ni vitendo vinavyohitaji mamlaka ya juu, kusisitiza kanuni ya kutenganisha mamlaka. Kwa kawaida, huduma ya uthibitishaji inahusika na uundaji wa cheti, wakati huduma ya kuingia inashughulikia uhusiano wake na kabati la mfumo wa mtumiaji. Ni muhimu kutambua kwamba michakato huirithi cheti kuu cha mchakato wao wa mzazi wakati wa uundaji.
* **Cheti cha Uigizaji**: Humpa programu ya seva uwezo wa kuchukua kitambulisho cha mteja kwa muda kwa kupata vitu salama. Mfumo huu umegawanywa katika viwango vinne vya uendeshaji:
  * **Anonim**: Hutoa ufikiaji wa seva kama wa mtumiaji asiyejulikana.
  * **Utambuzi**: Inaruhusu seva kuthibitisha kitambulisho cha mteja bila kutumia kwa upatikanaji wa vitu.
  * **Uigizaji**: Inawezesha seva kufanya kazi chini ya kitambulisho cha mteja.
  * **Uteuzi**: Kama Uigizaji lakini inajumuisha uwezo wa kuendeleza dhana hii ya kitambulisho kwa mifumo ya mbali ambayo seva inashirikiana nayo, ikisimamia uhifadhi wa sifa.

#### Kujifanya Kuwa na Vyeti

Kwa kutumia moduli ya _**incognito**_ ya metasploit ikiwa una mamlaka za kutosha unaweza kwa urahisi **kuorodhesha** na **kujifanya kuwa** vyeti vingine. Hii inaweza kuwa muhimu kufanya **vitendo kana kwamba wewe ni mtumiaji mwingine**. Pia unaweza **kupandisha vyeo vya mamlaka** kwa kutumia mbinu hii.

### Mamlaka ya Vyeti

Jifunze ni **mamlaka gani ya vyeti yanaweza kutumiwa vibaya kwa kupandisha vyeo vya mamlaka:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Tazama [**mamlaka yote yanayowezekana ya vyeti na baadhi ya ufafanuzi kwenye ukurasa huu wa nje**](https://github.com/gtworek/Priv2Admin).

## Marejeo

Jifunze zaidi kuhusu vyeti katika mafunzo haya: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) na [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** inayotoa huduma za **bure** kuchunguza ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi ya wizi wa habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** hapa:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) **kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
