<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Viwango vya Uadilifu

Katika Windows Vista na toleo zingine baadaye, vitu vyote vilivyolindwa vinakuja na lebo ya **kiwango cha uadilifu**. Hii inaweka kiwango cha uadilifu "cha kati" kwa faili na funguo za usajili, isipokuwa kwa folda na faili fulani ambazo Internet Explorer 7 inaweza kuandika kwa kiwango cha uadilifu cha chini. Tabia ya msingi ni kwamba michakato iliyoanzishwa na watumiaji wa kawaida ina kiwango cha uadilifu cha kati, wakati huduma kwa kawaida hufanya kazi kwa kiwango cha uadilifu cha mfumo. Lebo ya kiwango cha juu inalinda saraka ya msingi.

Sheria muhimu ni kwamba vitu haviwezi kuhaririwa na michakato yenye kiwango cha uadilifu cha chini kuliko kiwango cha vitu hivyo. Viwango vya uadilifu ni:

- **Haiaminiki**: Kiwango hiki ni kwa michakato na kuingia kwa siri. %%%Mfano: Chrome%%%
- **Chini**: Hasa kwa mwingiliano wa mtandao, hasa katika Mode ya Kulindwa ya Internet Explorer, ikiafikia faili na michakato inayohusiana, na folda fulani kama **Folda ya Mtandao ya Muda**. Michakato ya kiwango cha chini inakabiliwa na vizuizi kubwa, ikiwa ni pamoja na kutokuwa na ufikiaji wa kuandika kwenye usajili na ufikiaji mdogo wa kuandika kwenye maelezo ya mtumiaji.
- **Kati**: Kiwango cha msingi kwa shughuli nyingi, kinachopewa watumiaji wa kawaida na vitu bila viwango maalum vya uadilifu. Hata wanachama wa kikundi cha Wasimamizi hufanya kazi kwa kiwango hiki kwa chaguo-msingi.
- **Juukuu**: Imehifadhiwa kwa wasimamizi, ikiruhusu kuhariri vitu kwa viwango vya uadilifu vya chini, ikiwa ni pamoja na vile vya kiwango cha juu yenyewe.
- **Mfumo**: Kiwango cha uendeshaji cha juu kabisa kwa msingi wa Windows na huduma kuu, ambacho hata wasimamizi hawawezi kufikia, kuhakikisha ulinzi wa kazi muhimu za mfumo.
- **Msimamizi**: Kiwango cha pekee kinachosimama juu ya viwango vyote vingine, kikiwezesha vitu katika kiwango hiki kuondoa ufungaji wa vitu vingine vyovyote.

Unaweza kupata kiwango cha uadilifu cha michakato kwa kutumia **Process Explorer** kutoka **Sysinternals**, kwa kufikia **mali** ya michakato na kuangalia kichupo cha "**Usalama**":

![](<../../.gitbook/assets/image (318).png>)

Unaweza pia kupata **kiwango chako cha sasa cha uadilifu** kwa kutumia `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Viwango vya Uadilifu katika Mfumo wa Faili

Kitu ndani ya mfumo wa faili linaweza kuwa na **mahitaji ya kiwango cha uadilifu cha chini** na ikiwa mchakato haujapata kiwango hiki cha uadilifu, hautaweza kuingiliana nacho.\
Kwa mfano, hebu **tujaribu kuunda faili ya kawaida kutoka kwenye konsoli ya mtumiaji wa kawaida na angalia ruhusa**:
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
Sasa, acha tuweke kiwango cha chini cha uadilifu kuwa **High** kwa faili. Hii **inapaswa kufanywa kutoka kwenye konsoli** inayotumia **mamlaka ya juu** kwa sababu konsoli ya kawaida itakuwa inafanya kazi kwenye kiwango cha uadilifu cha Kati na **haitaruhusiwa** kuweka kiwango cha uadilifu kuwa High kwa kipengee:
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
Hapa ndipo mambo yanapokuwa ya kuvutia. Unaweza kuona kuwa mtumiaji `DESKTOP-IDJHTKP\user` ana **mamlaka KAMILI** juu ya faili (kwa kweli huyu ndiye mtumiaji aliyetengeneza faili hiyo), hata hivyo, kutokana na kiwango cha chini cha uadilifu kilichotekelezwa, hataweza kubadilisha faili tena isipokuwa anafanya kazi ndani ya Kiwango cha Juu cha Uadilifu (kumbuka kuwa ataweza kuisoma):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Kwa hiyo, wakati faili ina kiwango cha chini cha uadilifu, ili kuibadilisha unahitaji kuendesha angalau katika kiwango hicho cha uadilifu.**
{% endhint %}

## Viwango vya Uadilifu katika Programu za Binari

Nimefanya nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na nimeipa **kiwango cha chini cha uadilifu kutoka kwenye konsoli ya msimamizi:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sasa, ninapoendesha `cmd-low.exe` itaendeshwa **chini ya kiwango cha usalama cha chini** badala ya kiwango cha kati:

![](<../../.gitbook/assets/image (320).png>)

Kwa watu wenye shauku, ikiwa unaweka kiwango cha juu cha usalama kwa faili (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) haitaendeshwa kwa kiwango cha juu cha usalama moja kwa moja (ikiwa unaita kutoka kiwango cha kati --kwa chaguo-msingi-- itaendeshwa kwa kiwango cha kati cha usalama).

## Viwango vya Usalama katika Mchakato

Sio faili na saraka zote zina kiwango cha chini cha usalama, **lakini mchakato wote unaendeshwa kwa kiwango cha usalama**. Na kama ilivyotokea na mfumo wa faili, **ikiwa mchakato unataka kuandika ndani ya mchakato mwingine lazima iwe na kiwango cha usalama sawa angalau**. Hii inamaanisha kuwa mchakato wenye kiwango cha chini cha usalama hawezi kufungua kushughulikia na ufikiaji kamili kwa mchakato wenye kiwango cha kati cha usalama.

Kutokana na vizuizi vilivyotajwa katika sehemu hii na sehemu iliyotangulia, kutoka mtazamo wa usalama, daima **inapendekezwa kuendesha mchakato kwa kiwango cha chini kabisa cha usalama**.


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
