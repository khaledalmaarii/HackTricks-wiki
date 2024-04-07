# Viwango vya Uadilifu

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Viwango vya Uadilifu

Katika Windows Vista na toleo zingine baadaye, vitu vyote vilivyolindwa huja na lebo ya **kiwango cha uadilifu**. Hii inaweka kimsingi kiwango cha uadilifu "wa kati" kwa faili na funguo za usajili, isipokuwa kwa folda na faili fulani ambazo Internet Explorer 7 inaweza kuandika kwa kiwango cha uadilifu wa chini. Tabia ya msingi ni kwamba michakato iliyozinduliwa na watumiaji wa kawaida ina kiwango cha uadilifu wa kati, wakati huduma kwa kawaida hufanya kazi kwa kiwango cha uadilifu wa mfumo. Lebo ya uadilifu wa juu inalinda saraka ya msingi.

Sheria muhimu ni kwamba vitu haviwezi kuhaririwa na michakato yenye kiwango cha uadilifu cha chini kuliko kiwango cha kitu. Viwango vya uadilifu ni:

* **Isiyoaminika**: Kiwango hiki ni kwa michakato na kuingia kwa siri. %%%Mfano: Chrome%%%
* **Chini**: Hasa kwa mwingiliano wa mtandao, hasa katika Hali ya Kulindwa ya Internet Explorer, ikiaathiri faili na michakato inayohusiana, na folda fulani kama **Folda ya Mtandao ya Muda**. Michakato ya uadilifu wa chini inakabiliwa na vizuizi kubwa, ikiwa ni pamoja na kutokuwa na ufikiaji wa kuandika kwenye usajili na ufikiaji mdogo wa kuandika wa maelezo ya mtumiaji.
* **Kati**: Kiwango cha msingi kwa shughuli nyingi, kikiwekwa kwa watumiaji wa kawaida na vitu bila viwango maalum vya uadilifu. Hata wanachama wa kikundi cha Wasimamizi wanafanya kazi kwa kiwango hiki kwa chaguo-msingi.
* **Ju: Imehifadhiwa kwa wasimamizi, ikiruhusu kuwabadilisha vitu kwa viwango vya uadilifu wa chini, ikiwa ni pamoja na vile vilivyo kwenye kiwango cha juu yenyewe.
* **Mfumo**: Kiwango cha uendeshaji cha juu kwa msingi wa Windows na huduma kuu, nje ya kufikia hata kwa wasimamizi, ikahakikisha ulinzi wa kazi muhimu za mfumo.
* **Msanidi**: Kiwango cha kipekee kinachosimama juu ya vyote vingine, kukiwezesha vitu kwenye kiwango hiki kuondoa kitu kingine chochote.

Unaweza kupata kiwango cha uadilifu wa mchakato kwa kutumia **Process Explorer** kutoka **Sysinternals**, kufikia **mali** ya mchakato na kuona kichupo cha "**Usalama**":

![](<../../.gitbook/assets/image (821).png>)

Unaweza pia kupata **kiwango chako cha sasa cha uadilifu** kwa kutumia `whoami /groups`

![](<../../.gitbook/assets/image (322).png>)

### Viwango vya Uadilifu katika Mfumo wa Faili

Kitu ndani ya mfumo wa faili linaweza kuhitaji **mahitaji ya kiwango cha uadilifu cha chini** na ikiwa mchakato hana kiwango hiki cha uadilifu haitaweza kuingiliana nacho.\
Kwa mfano, hebu **tujaribu kuunda faili ya kawaida kutoka kwa konsoli ya mtumiaji wa kawaida na angalia ruhusa**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Sasa, tuweke kiwango cha chini cha uadilifu kuwa **Kiwango cha Juu** kwa faili. Hii **inapaswa kufanywa kutoka kwenye konsoli** inayotumika kama **msimamizi** kwani **konsoli ya kawaida** itakuwa inafanya kazi kwenye kiwango cha Uadilifu wa Kati na **haitaruhusiwa** kuweka kiwango cha Uadilifu cha Juu kwa kitu:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Hapa ndipo mambo yanapokuwa ya kuvutia. Unaweza kuona kuwa mtumiaji `DESKTOP-IDJHTKP\user` ana **ruhusa KAMILI** juu ya faili (kweli huyu ndiye mtumiaji aliyeanzisha faili), hata hivyo, kutokana na kiwango cha chini cha uadilifu kilichotekelezwa hataweza kuhariri faili tena isipokuwa kama anatumia kiwango cha Uadilifu wa Juu (kumbuka kuwa ataweza kuisoma):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Kwa hivyo, wakati faili ina kiwango cha chini cha uadilifu, ili kuibadilisha unahitaji kuendesha angalau kwa kiwango hicho cha uadilifu.**
{% endhint %}

### Viwango vya Uadilifu katika Programu za Binari

Nilifanya nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na kuweka **kiwango cha uadilifu kuwa cha chini kutoka kwenye konsoli ya msimamizi:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sasa, ninapoendesha `cmd-low.exe` itakuwa **inaendeshwa chini ya kiwango cha usahihi cha chini** badala ya cha kati:

![](<../../.gitbook/assets/image (310).png>)

Kwa watu wenye shauku, ikiwa unapitisha kiwango cha juu cha usahihi kwa faili (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) haitaendeshwa na kiwango cha juu cha usahihi moja kwa moja (ikiwa unaita kutoka kiwango cha kati cha usahihi - kwa chaguo-msingi - itaendeshwa chini ya kiwango cha kati cha usahihi).

### Viwango vya Usahihi katika Michakato

Siyo faili na folda zote zina kiwango cha chini cha usahihi, **lakini michakato yote inaendeshwa chini ya kiwango cha usahihi**. Na kama ilivyotokea na mfumo wa faili, **ikiwa mchakato unataka kuandika ndani ya mchakato mwingine lazima iwe na kiwango sawa cha usahihi**. Hii inamaanisha kwamba mchakato wenye kiwango cha chini cha usahihi hawezi kufungua kushughulikia kwa ufikiaji kamili kwa mchakato wenye kiwango cha kati cha usahihi.

Kutokana na vizuizi vilivyozungumziwa katika sehemu hii na sehemu iliyopita, kutoka mtazamo wa usalama, daima ni **inashauriwa kuendesha mchakato katika kiwango cha chini cha usahihi kinachowezekana**.
