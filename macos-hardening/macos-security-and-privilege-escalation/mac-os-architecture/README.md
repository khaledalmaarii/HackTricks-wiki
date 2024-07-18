# Kernel & Mipangilio ya Mfumo wa macOS

{% hint style="success" %}
Jifunze & zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Kernel ya XNU

**Msingi wa macOS ni XNU**, ambayo inasimama kwa "X is Not Unix". Kernel huu kimsingi unaundwa na **Mach microkernel** (itakayojadiliwa baadaye), **na** vipengele kutoka kwa Berkeley Software Distribution (**BSD**). XNU pia hutoa jukwaa kwa **madereva ya kernel kupitia mfumo unaoitwa I/O Kit**. Kernel ya XNU ni sehemu ya mradi wa chanzo wazi wa Darwin, ambao maana yake ni kwamba **msimbo wake wa chanzo upo wazi kwa umma**.

Kutoka mtazamo wa mtafiti wa usalama au mwandishi wa programu wa Unix, **macOS** inaweza kuonekana kama **kama FreeBSD** na GUI yenye mvuto na programu nyingi za desturi. Programu nyingi zilizoendelezwa kwa BSD zitakusanywa na kufanya kazi kwenye macOS bila kuhitaji marekebisho, kwani zana za mstari wa amri zinazojulikana kwa watumiaji wa Unix zote zinapatikana kwenye macOS. Hata hivyo, kwa sababu kernel ya XNU inajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa jadi wa Unix na macOS, na tofauti hizi zinaweza kusababisha matatizo au kutoa faida za kipekee.

Toleo la chanzo wazi la XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **inayoweza kufanya kazi kama UNIX**. Moja ya kanuni muhimu za kubuni kwake ilikuwa **kupunguza** kiasi cha **msimbo** unaofanya kazi katika **nafasi ya kernel** na badala yake kuruhusu kazi nyingi za kernel za kawaida, kama mfumo wa faili, mtandao, na I/O, kufanya kazi kama kazi za kiwango cha mtumiaji.

Katika XNU, Mach **inasimamia shughuli nyingi muhimu za kiwango cha chini** ambazo kernel kawaida inashughulikia, kama ratiba ya processor, multitasking, na usimamizi wa kumbukumbu ya kielezo.

### BSD

Kernel ya XNU pia **inajumuisha** kiasi kikubwa cha msimbo uliotokana na mradi wa **FreeBSD**. Msimbo huu **unafanya kazi kama sehemu ya kernel pamoja na Mach**, katika nafasi ile ile ya anwani. Hata hivyo, msimbo wa FreeBSD ndani ya XNU unaweza kutofautiana sana na msimbo halisi wa FreeBSD kwa sababu marekebisho yalihitajika ili kuhakikisha utangamano wake na Mach. FreeBSD inachangia katika shughuli nyingi za kernel ikiwa ni pamoja na:

* Usimamizi wa mchakato
* Kukabiliana na ishara
* Mifumo ya usalama ya msingi, ikiwa ni pamoja na usimamizi wa mtumiaji na kikundi
* Miundo ya wito wa mfumo
* Mtandao wa TCP/IP na soketi
* Firewall na uchujaji wa pakiti

Kuelewa mwingiliano kati ya BSD na Mach kunaweza kuwa ngumu, kutokana na mifumo yao tofauti ya dhana. Kwa mfano, BSD hutumia michakato kama kitengo chake cha msingi cha utekelezaji, wakati Mach inafanya kazi kulingana na nyuzi. Tofauti hii inapatikana katika XNU kwa **kuhusisha kila mchakato wa BSD na kazi ya Mach** ambayo ina nyuzi moja ya Mach. Wakati wito wa mfumo wa BSD's fork() unapotumiwa, msimbo wa BSD ndani ya kernel hutumia kazi za Mach kuunda muundo wa kazi na nyuzi.

Zaidi ya hayo, **Mach na BSD kila moja ina mifano tofauti ya usalama**: **Mfano wa usalama wa Mach** unategemea **haki za bandari**, wakati mfano wa usalama wa BSD unafanya kazi kulingana na **umiliki wa mchakato**. Tofauti kati ya mifano hii mbili mara nyingi imesababisha mapungufu ya kufikia haki za mamlaka za ndani. Mbali na wito wa mfumo wa kawaida, kuna pia **mtego wa Mach unaoruhusu programu za kiwango cha mtumiaji kuingiliana na kernel**. Vipengele hivi tofauti pamoja vinajenga usanifu wa tabaka nyingi, wa kipekee wa kernel ya macOS.

### I/O Kit - Madereva

I/O Kit ni mfumo wa **dereva wa kifaa ulio na msimbo wa chanzo wazi**, unaoshughulikia **madereva ya kifaa yanayopakiwa kwa kudhamini**. Inaruhusu msimbo wa moduli kuongezwa kwa kernel mara moja, ikisaidia vifaa mbalimbali.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Mawasiliano kati ya Michakato

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache** ni **toleo lililopangwa mapema la kernel ya XNU**, pamoja na **madereva muhimu ya kifaa** na **mipanuo ya kernel**. Huhifadhiwa katika **muundo uliopunguzwa** na hupata kufunguliwa kumbukumbu wakati wa mchakato wa kuanza. Kernelcache inarahisisha **muda wa kuanza haraka** kwa kuwa na toleo tayari la kukimbia la kernel na madereva muhimu inapatikana, kupunguza muda na rasilimali ambazo zingetumiwa kwa kudhamini na kuunganisha sehemu hizi wakati wa kuanza.

Katika iOS inapatikana katika **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** kwenye macOS unaweza kuipata kwa kutumia **`find / -name kernelcache 2>/dev/null`** au **`mdfind kernelcache | grep kernelcache`**

Inawezekana kukimbia **`kextstat`** kuangalia mipanuo ya kernel iliyopakiwa.

#### IMG4

Muundo wa faili wa IMG4 ni muundo wa chombo unaotumiwa na Apple kwenye vifaa vyake vya iOS na macOS kwa **kudhibiti na kuthibitisha kwa usalama vipengele vya firmware** (kama **kernelcache**). Muundo wa IMG4 unajumuisha kichwa na vitambulisho kadhaa ambavyo vinajumuisha vipande tofauti vya data ikiwa ni pamoja na mzigo halisi (kama kernel au bootloader), saini, na seti ya mali ya maelezo. Muundo huu unathibitisha kwa kutumia kriptografia, kuruhusu kifaa kuthibitisha uhalali na usahihi wa kipengele cha firmware kabla ya kukitekeleza.

Kawaida inajumuisha vipengele vifuatavyo:

* **Mzigo (IM4P)**:
* Mara nyingi imepakwa (LZFSE4, LZSS, …)
* Kwa hiari imefichwa
* **Maelezo (IM4M)**:
* Ina Saini
* Kamusi ya ziada ya funguo/thamani
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
Kuweza **kutoa** faili hizo, unaweza tu **kuzip**.

Baada ya kutoa faili ya firmware utapata faili kama hii: **`kernelcache.release.iphone14`**. Iko katika muundo wa **IMG4**, unaweza kutoa habari muhimu kwa:

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

Kwa hili sasa tunaweza **kuchimbua vitu vyote vya nyongeza** au **kile unachovutiwa nacho:**
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

macOS ni **kali sana katika kupakia Vifurushi vya Kernel** (.kext) kutokana na mamlaka kubwa ambazo nambari hiyo itaendeshwa nazo. Kwa kweli, kwa chaguo-msingi ni karibu haiwezekani (isipokuwa kama njia ya kuepuka inapatikana).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Vifurushi vya Mfumo wa macOS

Badala ya kutumia Vifurushi vya Kernel, macOS iliunda Vifurushi vya Mfumo, ambavyo hutoa APIs kwenye kiwango cha mtumiaji kuingiliana na kernel. Kwa njia hii, wabunifu wanaweza kuepuka kutumia vifurushi vya kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Marejeo

* [**Kitabu cha Mwongozo wa Mhakiki wa Mac**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
