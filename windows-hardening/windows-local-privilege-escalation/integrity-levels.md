# Viwango vya Uadilifu

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** ambayo inatoa huduma za **bure** za kuangalia ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na malware za kuiba habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** hapa:

{% embed url="https://whiteintel.io" %}

---

## Viwango vya Uadilifu

Katika Windows Vista na toleo zingine baadaye, vitu vyote vilivyolindwa huja na lebo ya **kiwango cha uadilifu**. Hii inaweka kimsingi kiwango cha uadilifu "wa kati" kwa faili na funguo za usajili, isipokuwa kwa folda na faili fulani ambazo Internet Explorer 7 inaweza kuandika kwa kiwango cha uadilifu cha chini. Tabia ya msingi ni kwamba michakato iliyozinduliwa na watumiaji wa kawaida ina kiwango cha uadilifu wa kati, wakati huduma kwa kawaida hufanya kazi kwa kiwango cha uadilifu wa mfumo. Lebo ya uadilifu wa juu inalinda saraka ya msingi.

Kanuni muhimu ni kwamba vitu haviwezi kuhaririwa na michakato yenye kiwango cha uadilifu cha chini kuliko kiwango cha kitu. Viwango vya uadilifu ni:

* **Isioaminika**: Kiwango hiki ni kwa michakato na kuingia kwa siri. %%%Mfano: Chrome%%%
* **Chini**: Hasa kwa mwingiliano wa mtandao, hasa katika Hali ya Kulindwa ya Internet Explorer, ikiafikia faili na michakato inayohusiana, na folda fulani kama **Folda ya Mtandao ya Muda**. Michakato ya uadilifu wa chini inakabiliwa na vizuizi kubwa, ikiwa ni pamoja na kutokuwa na ufikiaji wa kuandika usajili na ufikiaji mdogo wa kuandika maelezo ya mtumiaji.
* **Kati**: Kiwango cha msingi kwa shughuli nyingi, kinachopewa watumiaji wa kawaida na vitu bila viwango maalum vya uadilifu. Hata wanachama wa kikundi cha Wasimamizi wanafanya kazi kwa kiwango hiki kwa chaguo-msingi.
* **Ju:** Imehifadhiwa kwa wasimamizi, ikiruhusu kuwabadilisha vitu kwa viwango vya uadilifu wa chini, ikiwa ni pamoja na vile vilivyo kwenye kiwango cha juu yenyewe.
* **Mfumo**: Kiwango cha uendeshaji cha juu kwa msingi wa Windows na huduma kuu, isiyofikiwa hata kwa wasimamizi, ikihakikisha ulinzi wa kazi muhimu za mfumo.
* **Msimbaji**: Kiwango cha kipekee kinachosimama juu ya vingine vyote, kuiruhusu vitu kwenye kiwango hiki kuondoa kitu kingine chochote.

Unaweza kupata kiwango cha uadilifu cha mchakato kwa kutumia **Process Explorer** kutoka **Sysinternals**, kufikia **mali** ya mchakato na kuangalia kichupo cha "**Usalama**":

![](<../../.gitbook/assets/image (821).png>)

Unaweza pia kupata **kiwango chako cha sasa cha uadilifu** kwa kutumia `whoami /groups`

![](<../../.gitbook/assets/image (322).png>)

### Viwango vya Uadilifu katika Mfumo wa Faili

Kitu ndani ya mfumo wa faili linaweza kuhitaji **mahitaji ya kiwango cha uadilifu cha chini** na ikiwa mchakato hana kiwango hiki cha uadilifu haitaweza kuingiliana nacho.\
Kwa mfano, hebu **tujaribu kuunda faili ya kawaida kutoka kwa konsoli ya mtumiaji wa kawaida na kuangalia ruhusa**:
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
Sasa, tuweke kiwango cha chini cha uadilifu kuwa **Kiwango cha Juu** kwa faili. Hii **inapaswa kufanywa kutoka kwenye konsoli** inayotumika kama **msimamizi** kwani konsoli **ya kawaida** itakuwa inafanya kazi kwenye kiwango cha Uadilifu wa Kati na **haitaruhusiwa** kuweka kiwango cha Uadilifu cha Juu kwa kitu:
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
Hapa ndipo mambo yanapokuwa ya kuvutia. Unaweza kuona kuwa mtumiaji `DESKTOP-IDJHTKP\user` ana **ruhusa KAMILI** juu ya faili (kweli huyu ndiye mtumiaji aliyeunda faili), hata hivyo, kutokana na kiwango cha chini cha uadilifu kilichotekelezwa hataweza kuhariri faili tena isipokuwa kama anatumia kiwango cha Uadilifu wa Juu (tambua kuwa ataweza kuisoma):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Kwa hiyo, wakati faili ina kiwango cha chini cha uadilifu, ili kuibadilisha unahitaji kuendesha angalau kwa kiwango hicho cha uadilifu.**
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
Sasa, ninapoendesha `cmd-low.exe` itakuwa **inaendeshwa chini ya kiwango cha usawa cha chini** badala ya cha kati:

![](<../../.gitbook/assets/image (310).png>)

Kwa watu wenye shauku, ikiwa unaweka kiwango cha juu cha usawa kwa faili (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) haitaendeshwa na kiwango cha juu cha usawa moja kwa moja (ikiwa unaita kutoka kiwango cha kati cha usawa - kwa chaguo-msingi - itaendeshwa chini ya kiwango cha kati cha usawa).

### Viwango vya Usawa katika Michakato

Siyo faili na folda zote zina kiwango cha chini cha usawa, **lakini michakato yote inaendeshwa chini ya kiwango cha usawa**. Na kama ilivyotokea na mfumo wa faili, **ikiwa mchakato unataka kuandika ndani ya mchakato mwingine lazima iwe na angalau kiwango sawa cha usawa**. Hii inamaanisha kwamba mchakato wenye kiwango cha chini cha usawa hawezi kufungua kushughulikia na ufikiaji kamili wa mchakato wenye kiwango cha kati cha usawa.

Kutokana na vizuizi vilivyozungumziwa katika sehemu hii na sehemu iliyopita, kutoka mtazamo wa usalama, daima ni **inashauriwa kuendesha mchakato katika kiwango cha chini cha usawa kinachowezekana**.


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ni injini ya utaftaji inayotumia **dark-web** inayotoa **huduma za bure** kuchunguza ikiwa kampuni au wateja wake wameathiriwa na **malware za wizi**.

Lengo kuu la WhiteIntel ni kupambana na utekaji wa akaunti na mashambulio ya ransomware yanayotokana na programu hasidi za wizi wa habari.

Unaweza kutembelea tovuti yao na kujaribu injini yao **bure** hapa:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
