# Kernel na Vifurushi vya Mfumo wa macOS

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kernel ya XNU

**Msingi wa macOS ni XNU**, ambayo inasimama kwa "X is Not Unix". Kernel hii kimsingi inajumuisha **Mach microkernel** (itakayojadiliwa baadaye), **na** vipengele kutoka kwa Usambazaji wa Programu ya Berkeley (**BSD**). XNU pia hutoa jukwaa kwa **madereva ya kernel kupitia mfumo unaoitwa I/O Kit**. Kernel ya XNU ni sehemu ya mradi wa chanzo wazi wa Darwin, ambao maana yake ni kwamba **msimbo wake wa chanzo upo wazi kwa umma**.

Kutoka mtazamo wa mtafiti wa usalama au mwendelezaji wa Unix, **macOS** inaweza kuonekana kama **kama mfumo wa FreeBSD** na GUI ya kifahari na programu nyingi za desturi. Programu nyingi zilizoendelezwa kwa BSD zitakusanyika na kukimbia kwenye macOS bila kuhitaji marekebisho, kwani zana za mstari wa amri zinazofahamika kwa watumiaji wa Unix zote zinapatikana kwenye macOS. Hata hivyo, kwa sababu kernel ya XNU inajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa Unix wa kawaida na macOS, na tofauti hizi zinaweza kusababisha masuala au kutoa faida za kipekee.

Toleo la chanzo wazi la XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **inayoweza kufanya kazi kama UNIX**. Moja ya kanuni muhimu za kubuni kwake ilikuwa **kupunguza** kiasi cha **msimbo** unaofanya kazi katika **nafasi ya kernel** na badala yake kuruhusu kazi nyingi za kernel za kawaida, kama mfumo wa faili, mtandao, na I/O, kufanya kazi kama kazi za kiwango cha mtumiaji.

Katika XNU, Mach ni **mwenye jukumu la shughuli nyingi muhimu za kiwango cha chini** ambazo kernel kawaida hushughulikia, kama ratiba ya processor, multitasking, na usimamizi wa kumbukumbu ya kivutu.

### BSD

Kernel ya XNU pia **inajumuisha** kiasi kikubwa cha msimbo uliotokana na mradi wa **FreeBSD**. Msimbo huu **unafanya kazi kama sehemu ya kernel pamoja na Mach**, katika nafasi ile ile ya anwani. Hata hivyo, msimbo wa FreeBSD ndani ya XNU unaweza kutofautiana sana na msimbo wa FreeBSD wa asili kwa sababu marekebisho yalihitajika ili kuhakikisha utangamano wake na Mach. FreeBSD inachangia katika shughuli nyingi za kernel ikiwa ni pamoja na:

* Usimamizi wa mchakato
* Kukabiliana na ishara
* Mifumo ya msingi ya usalama, ikiwa ni pamoja na usimamizi wa mtumiaji na kikundi
* Miundo ya wito wa mfumo
* Mtandao wa TCP/IP na soketi
* Firewall na uchujaji wa pakiti

Kuelewa mwingiliano kati ya BSD na Mach kunaweza kuwa ngumu, kutokana na mifumo yao tofauti ya dhana. Kwa mfano, BSD hutumia michakato kama kitengo chake cha msingi cha utekelezaji, wakati Mach hufanya kazi kulingana na nyuzi. Tofauti hii inapatikana katika XNU kwa **kuhusisha kila mchakato wa BSD na kazi ya Mach** ambayo ina nyuzi moja ya Mach. Wakati wito wa mfumo wa fork() wa BSD unapotumiwa, msimbo wa BSD ndani ya kernel hutumia kazi za Mach kuunda muundo wa kazi na nyuzi.

Zaidi ya hayo, **Mach na BSD kila moja ina mifano tofauti ya usalama**: **mifano ya usalama ya Mach** inategemea **haki za bandari**, wakati mifano ya usalama ya BSD inafanya kazi kulingana na **umiliki wa mchakato**. Tofauti kati ya mifano hii mara nyingi imesababisha mapungufu ya kufikia haki za mamlaka za ndani. Mbali na wito wa mfumo wa kawaida, kuna pia **mtego wa Mach unaoruhusu programu za nafasi ya mtumiaji kuingiliana na kernel**. Vipengele tofauti hivi pamoja hufanya muundo wa mchanganyiko, wenye nyuso nyingi, wa kernel ya macOS.

### I/O Kit - Madereva

I/O Kit ni mfumo wa **dereva wa kifaa ulio na msimbo wa chanzo wazi**, unaoshughulikia **madereva ya kifaa yanayopakiwa kwa kudhamini** katika kernel ya XNU. Inaruhusu msimbo wa moduli kuongezwa kwa kernel mara moja, ikisaidia vifaa mbalimbali.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Mawasiliano kati ya Michakato

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache** ni **toleo lililopangwa mapema na kuhusishwa mapema la kernel ya XNU**, pamoja na **madereva muhimu ya kifaa** na **vifurushi vya kernel**. Huhifadhiwa katika **muundo uliopunguzwa** na hupanuliwa kumbukumbu wakati wa mchakato wa kuanza. Kernelcache inarahisisha **muda wa kuanza haraka** kwa kuwa na toleo lililopangwa tayari la kernel na madereva muhimu inapatikana, kupunguza muda na rasilimali ambazo zingetumiwa kwa kudhamini na kuunganisha sehemu hizi wakati wa kuanza.

Katika iOS inapatikana katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** katika macOS unaweza kuipata kwa kutumia **`find / -name kernelcache 2>/dev/null`** au **`mdfind kernelcache | grep kernelcache`**

Inawezekana kukimbia **`kextstat`** kuchunguza vifurushi vya kernel vilivyopakiwa.

#### IMG4

Muundo wa faili wa IMG4 ni muundo wa chombo unaotumiwa na Apple kwenye vifaa vyake vya iOS na macOS kwa **kuhifadhi na kuthibitisha kwa usalama vipengele vya firmware** (kama **kernelcache**). Muundo wa IMG4 unajumuisha kichwa na vitambulisho kadhaa ambavyo vinajumuisha vipande tofauti vya data ikiwa ni pamoja na mzigo halisi (kama kernel au bootloader), saini, na seti ya mali ya maelezo. Muundo huu unathibitisha kwa kriptografia, kuruhusu kifaa kuthibitisha uhalali na usahihi wa kipengele cha firmware kabla ya kukiendesha.

Kawaida inajumuisha vipengele vifuatavyo:

* **Mzigo (IM4P)**:
* Mara nyingi imepakwa (LZFSE4, LZSS, …)
* Kwa hiari imefichwa
* **Maelezo (IM4M)**:
* Ina Saini
* Kamusi ya Ziada ya Funguo/Thamani
* **Maelezo ya Kurejesha (IM4R)**:
* Inajulikana pia kama APNonce
* Inazuia kurudia baadhi ya sasisho
* CHAGUO: Kawaida hii haipatikani

Fungua Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Alama za Kernelcache

Wakati mwingine Apple hutoa **kernelcache** na **alama**. Unaweza kupakua baadhi ya firmwares zenye alama kwa kufuata viungo kwenye [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Hizi ni **firmwares** za Apple unazoweza kupakua kutoka [**https://ipsw.me/**](https://ipsw.me/). Miongoni mwa faili nyingine, italeta **kernelcache**.\
Kuweza **kutoa** faili hizo, unaweza tu **kuzipakua**.

Baada ya kutoa firmware utapata faili kama: **`kernelcache.release.iphone14`**. Iko katika muundo wa **IMG4**, unaweza kutoa habari muhimu kwa:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Unaweza kuangalia alama zilizochimbuliwa za kernelcache kwa: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Kwa hili sasa tunaweza **kuchimba vitu vyote vya nyongeza** au **kile unachovutiwa nacho:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Vifurushi vya Kernel vya macOS

macOS ni **muhali sana katika kupakia Vifurushi vya Kernel** (.kext) kutokana na mamlaka kubwa ambazo nambari hiyo itaendeshwa nazo. Kwa kweli, kwa chaguo-msingi ni karibu haiwezekani (isipokuwa kama njia ya kuepuka inapatikana).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Vifurushi vya Mfumo wa macOS

Badala ya kutumia Vifurushi vya Kernel, macOS iliunda Vifurushi vya Mfumo, ambavyo hutoa APIs katika kiwango cha mtumiaji kuingiliana na kernel. Kwa njia hii, wabunifu wanaweza kuepuka kutumia vifurushi vya kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Marejeo

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
