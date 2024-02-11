# Kernel na Vipengele vya Mfumo wa macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kernel ya XNU

**Kiini kikuu cha macOS ni XNU**, ambayo inasimama kwa "X is Not Unix". Kiini hiki kinaundwa msingi wa **Mach microkernel** (utajadiliwa baadaye), **na** vipengele kutoka kwa **Berkeley Software Distribution (BSD)**. XNU pia hutoa jukwaa kwa **madereva ya kiini kupitia mfumo unaoitwa I/O Kit**. Kiini cha XNU ni sehemu ya mradi wa chanzo wazi wa Darwin, ambayo inamaanisha **msimbo wake wa chanzo unapatikana bure**.

Kwa mtazamo wa mtafiti wa usalama au mtengenezaji wa Unix, **macOS** inaweza kuonekana kama **mfumo wa FreeBSD** na GUI nzuri na programu nyingi za desturi. Programu nyingi zilizoendelezwa kwa BSD zitakusanywa na kukimbia kwenye macOS bila kuhitaji marekebisho, kwani zana za mstari wa amri zinazojulikana kwa watumiaji wa Unix zote zinapatikana kwenye macOS. Walakini, kwa sababu kiini cha XNU kinajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa kawaida kama wa Unix na macOS, na tofauti hizi zinaweza kusababisha masuala yanayowezekana au kutoa faida za kipekee.

Toleo la chanzo wazi la XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **sambamba na UNIX**. Moja ya kanuni muhimu za kubuni ilikuwa **kupunguza** idadi ya **msimbo** unaofanya kazi katika nafasi ya **kiini** na badala yake kuruhusu kazi nyingi za kiini za kawaida, kama mfumo wa faili, mtandao, na I/O, kuendesha kama kazi za kiwango cha mtumiaji.

Katika XNU, Mach ni **jukumu la shughuli nyingi muhimu za kiwango cha chini** ambazo kiini kawaida hushughulikia, kama ratiba ya processor, multitasking, na usimamizi wa kumbukumbu ya kawaida.

### BSD

**Kiini** cha XNU pia **kinajumuisha** kiasi kikubwa cha msimbo uliopatikana kutoka kwa mradi wa **FreeBSD**. Msimbo huu **unaendesha kama sehemu ya kiini pamoja na Mach**, kwenye nafasi ile ile ya anwani. Walakini, msimbo wa FreeBSD ndani ya XNU unaweza kutofautiana sana na msimbo wa asili wa FreeBSD kwa sababu marekebisho yalihitajika ili kuhakikisha utangamano wake na Mach. FreeBSD inachangia katika shughuli nyingi za kiini ikiwa ni pamoja na:

* Usimamizi wa mchakato
* Kusindika ishara
* Mfumo wa msingi wa usalama, ikiwa ni pamoja na usimamizi wa mtumiaji na kikundi
* Miundombinu ya wito wa mfumo
* Stack ya TCP/IP na soketi
* Firewall na uchujaji wa pakiti

Kuelewa mwingiliano kati ya BSD na Mach kunaweza kuwa ngumu, kutokana na mfumo wao tofauti wa kufikiria. Kwa mfano, BSD hutumia michakato kama kitengo chake cha msingi cha utekelezaji, wakati Mach inafanya kazi kulingana na nyuzi. Tofauti hii inatatuliwa katika XNU kwa **kuhusisha kila mchakato wa BSD na kazi ya Mach** ambayo ina nyuzi moja tu ya Mach. Wakati wito wa mfumo wa fork() wa BSD unapotumiwa, msimbo wa BSD ndani ya kiini hutumia kazi za Mach kuunda kazi na muundo wa nyuzi.

Zaidi ya hayo, **Mach na BSD kila mmoja una mifano tofauti ya usalama**: mfano wa usalama wa Mach unategemea **haki za bandari**, wakati mfano wa usalama wa BSD unafanya kazi kulingana na **umiliki wa mchakato**. Tofauti kati ya mifano hii mbili mara kwa mara imepelekea udhaifu wa kuongeza haki za ndani. Mbali na wito wa mfumo wa kawaida, pia kuna **mtego wa Mach ambao huruhusu programu za nafasi ya mtumiaji kuingiliana na kiini**. Vipengele tofauti hivi pamoja hujenga usanifu wa kipekee na wenye tabaka nyingi wa kiini cha macOS.

### I/O Kit - Madereva

I/O Kit ni mfumo wa **madereva ya kifaa ulio na msimbo wa chanzo wazi** ndani ya kiini cha XNU, unashughulikia **madereva ya kifaa yanayopakia kwa kudumu**. Inaruhusu msimbo wa moduli kuongezwa kwenye kiini wakati wa kutekelezwa, ikisaidia vifaa mbalimbali.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Mawasiliano kati ya Mchakato

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Kernelcache ni **toleo lililopangwa mapema na limeunganishwa la kiini cha XNU**, pamoja na **madereva muhimu ya kifaa** na **nyongeza za kiini**. Inahifadhiwa katika muundo **ulioshikamana** na hupata kufutwa kwenye kumbukumbu wakati wa mchakato wa kuanza. Kernelcache inawezesha **kuanza haraka** kwa kuwa na toleo tayari la kiini na madereva muhimu, kupunguza wakati na rasilimali ambazo zingetumiwa kwa kubeba na kuunganisha sehemu hizi wakati wa kuanza.

Katika iOS, iko katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** na kwenye macOS unaweza kuipata kwa kutumia **`find / -name kernelcache 2>/dev/null`**

#### IMG4

Muundo wa faili wa IMG4 ni muundo wa chombo kinachotumiwa na Apple kwenye vifaa vyake vya iOS na macOS kwa **kuhifadhi na kuthibitisha kwa usalama** sehemu za firmware (kama vile **kernelcache**). Muundo wa IMG4 unajumuisha kichwa na vitambulisho kadhaa ambavyo hufunga vipande tofauti vya data ikiwa ni pamoja na mzigo halisi (kama kiini au bootloader), saini, na seti ya mali ya manifesto. Muundo huu unathibitisha kwa njia ya kryptografia, kuruhusu kifaa kuthibitisha uhalali na usahihi wa sehemu ya firmware kabla ya kuitekeleza.

Kawaida inajumuisha sehemu zifuatazo:

* **Mzigo (IM4P)**:
* Mara nyingi imepakwa (LZFSE4, LZSS, ...)
* Kwa hiari imefichwa
* **Manifesto (IM4M)**:
* Ina Saini
* Kamusi ya ziada ya Funguo/Thamani
* **Maelezo ya Kurejesha (IM4R)**:
* Inajulikana pia kama APNonce
* Inazuia kurudia baadhi ya sasisho
* HIARI: Kawaida hii haipatikani

Fungua Kernelcache iliyofutwa:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Alama za Kernelcache

Wakati mwingine Apple inatoa **kernelcache** na **alama**. Unaweza kupakua baadhi ya firmware na alama kwa kufuata viungo kwenye [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Hizi ni **firmwares** za Apple unazoweza kupakua kutoka [**https://ipsw.me/**](https://ipsw.me/). Kati ya faili zingine, italeta **kernelcache**.\
Kuweza **kuchambua** faili hizo, unaweza tu kuzifungua.

Baada ya kuchambua firmware, utapata faili kama: **`kernelcache.release.iphone14`**. Iko katika muundo wa **IMG4**, unaweza kuchambua habari muhimu kwa kutumia:

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
Unaweza kuangalia alama zilizochimbwa za kernelcache kwa kutumia: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Kwa hili sasa tunaweza **kuchimba nyongeza zote** au **ile unayopendezwa nayo:**
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

macOS ni **mdhibiti mkali wa kupakia Vifurushi vya Kernel** (.kext) kwa sababu ya mamlaka kubwa ambayo nambari hiyo itaendeshwa nayo. Kwa kweli, kwa chaguo-msingi ni vigumu sana (isipokuwa kama kuna njia ya kuzunguka).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Vifurushi vya Mfumo vya macOS

Badala ya kutumia Vifurushi vya Kernel, macOS iliunda Vifurushi vya Mfumo, ambavyo hutoa API za kiwango cha mtumiaji kuingiliana na kernel. Kwa njia hii, waendelezaji wanaweza kuepuka kutumia vifurushi vya kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Marejeo

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
