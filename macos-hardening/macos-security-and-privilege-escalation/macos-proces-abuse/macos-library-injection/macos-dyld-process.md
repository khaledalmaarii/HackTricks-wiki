# macOS Dyld Process

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Taarifa Msingi

Kiingilio halisi cha faili ya Mach-o ni kiungo cha kudai, kilichoelezwa katika `LC_LOAD_DYLINKER` kawaida ni `/usr/lib/dyld`.

Kiungo hiki kitahitaji kutambua maktaba zote za kutekelezeka, kuzipanga kumbukani na kuunganisha maktaba zote zisizo wavivu. Ni baada tu ya mchakato huu ndipo kiingilio cha faili kitatekelezwa.

Bila shaka, **`dyld`** haina tegemezi yoyote (inatumia syscalls na vipande vya libSystem).

{% hint style="danger" %}
Ikiwa kiungo hiki kina kasoro yoyote, kwani kinatekelezwa kabla ya kutekeleza faili yoyote (hata zile zenye mamlaka ya juu), ingewezekana **kupandisha vyeo**.
{% endhint %}

### Mchakato

Dyld itapakiwa na **`dyldboostrap::start`**, ambayo pia itapakia vitu kama **stack canary**. Hii ni kwa sababu kazi hii itapokea katika **`apple`** hoja vector hii na nyingine **thamani** **nyeti**.

**`dyls::_main()`** ndio kiingilio cha dyld na kazi yake ya kwanza ni kukimbia `configureProcessRestrictions()`, ambayo kawaida inazuia **mazingira ya DYLD_*** yanayoelezwa katika:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Kisha, inapanga cache iliyoshirikiwa ya dyld ambayo inapakia mapema maktaba muhimu za mfumo na kisha inapanga maktaba ambazo faili inategemea na kuendelea kwa njia ya kurudufu hadi maktaba zote zinazohitajika zinapakiwa. Kwa hivyo:

1. inaanza kupakia maktaba zilizoingizwa na `DYLD_INSERT_LIBRARIES` (ikiwa inaruhusiwa)
2. Kisha zile zilizoshirikiwa kutoka kwenye cache
3. Kisha zile zilizoingizwa
1. &#x20;Kisha kuendelea kuagiza maktaba kwa njia ya kurudufu

Marudio ya maktaba hizi zinapakiwa **initialisers**. Hizi zimeandikwa kwa kutumia **`__attribute__((constructor))`** iliyoelezwa katika `LC_ROUTINES[_64]` (sasa imepitwa na wakati) au kwa pointer katika sehemu iliyofungwa na bendera `S_MOD_INIT_FUNC_POINTERS` (kawaida: **`__DATA.__MOD_INIT_FUNC`**).

Waharibifu wameandikwa na **`__attribute__((destructor))`** na wako katika sehemu iliyofungwa na bendera `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Faili zote za macOS zimeunganishwa kwa njia ya kudai. Kwa hivyo, zina sehemu za stubs ambazo husaidia faili kusonga kwenye nambari sahihi kwenye mashine na muktadha tofauti. Ni dyld wakati faili inatekelezwa ndiye ubongo unahitaji kutatua anwani hizi (angalau zile zisizo wavivu).

Sehemu za stub katika faili:

* **`__TEXT.__[auth_]stubs`**: Pointi kutoka kwa sehemu za `__DATA`
* **`__TEXT.__stub_helper`**: Nambari ndogo inayoita uunganishaji wa kudai na habari juu ya kazi ya kuita
* **`__DATA.__[auth_]got`**: Jedwali la Globu la Offset (anwani za kazi zilizoingizwa, zinapofumbuliwa, (zimefungwa wakati wa kupakia kwani imeashiriwa na bendera `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Pointi za alama zisizo wavivu (zimefungwa wakati wa kupakia kwani imeashiriwa na bendera `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Pointi za alama wavivu (zimefungwa wakati wa kupakia kwani imeashiriwa na bendera `S_NON_LAZY_SYMBOL_POINTERS`)

{% hint style="warning" %}
Tafadhali kumbuka kuwa pointi zenye kipimo "auth\_" zinatumia ufunguo wa kielektroniki mchakani mmoja kulinda (PAC). Zaidi ya hayo, Inawezekana kutumia maagizo ya arm64 `BLRA[A/B]` kuthibitisha pointi kabla ya kufuata. Na RETA\[A/B] inaweza kutumika badala ya anwani ya RET.\
Kwa kweli, nambari katika **`__TEXT.__auth_stubs`** itatumia **`braa`** badala ya **`bl`** kuita kazi ili kuthibitisha pointi.

Pia kumbuka kuwa toleo la sasa la dyld linapakia **kila kitu kama sio wavivu**.
{% endhint %}

### Kupata alama wavivu
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Sehemu ya kuvunja vipande ya kuvutia:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Inawezekana kuona kwamba kuruka kuita printf inaelekea **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Katika kuchambua upya wa sehemu ya **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Unaweza kuona kwamba tun **kuruka kwa anwani ya GOT**, ambayo katika kesi hii inatanzuliwa bila uvivu na italeta anwani ya kazi ya printf.

Katika hali nyingine badala ya kuruka moja kwa moja kwa GOT, inaweza kuruka kwa **`__DATA.__la_symbol_ptr`** ambayo itapakia thamani inayowakilisha kazi ambayo inajaribu kupakia, kisha kuruka kwa **`__TEXT.__stub_helper`** ambayo inaruka **`__DATA.__nl_symbol_ptr`** ambayo ina anwani ya **`dyld_stub_binder`** ambayo inachukua kama vigezo idadi ya kazi na anwani.\
Kazi ya mwisho, baada ya kupata anwani ya kazi inayotafutwa, huandika katika eneo husika katika **`__TEXT.__stub_helper`** ili kuepuka kufanya utafutaji baadaye.

{% hint style="success" %}
Hata hivyo, kumbuka kwamba toleo la sasa la dyld linapakia kila kitu bila uvivu.
{% endhint %}

#### Dyld opcodes

Hatimaye, **`dyld_stub_binder`** inahitaji kupata kazi iliyoelekezwa na kuandika katika anwani sahihi ili isitafute tena. Ili kufanya hivyo, inatumia kanuni (kifaa cha hali ya mwisho) ndani ya dyld.

## apple\[] argument vector

Katika macOS, kazi kuu hupokea kimsingi vigezo 4 badala ya 3. Ya nne inaitwa apple na kila kuingia ni katika mfumo `key=value`. Kwa mfano:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
### Matokeo:

Faili ya dyld inaweza kutumika kuingiza maktaba katika mchakato wa macOS. Hii inaweza kusababisha mchakato kutekeleza nambari iliyoharibika na kusababisha ukiukaji wa usalama au ongezeko la mamlaka. Kwa kufanya hivyo, mshambuliaji anaweza kuchukua udhibiti wa mchakato au hata mfumo mzima.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Kufikia wakati hizi thamani zinapofika kwenye kazi kuu, habari nyeti tayari imeondolewa kutoka kwao au ingekuwa uvujaji wa data.
{% endhint %}

ni rahisi kuona thamani zote za kuvutia zikibugia kabla ya kuingia kwenye kazi kuu na:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Hii ni muundo unaozalishwa na dyld na habari kuhusu hali ya dyld ambayo inaweza kupatikana katika [**msimbo wa chanzo**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) na habari kama toleo, pointer kwa safu ya dyld\_image\_info, kwa dyld\_image\_notifier, ikiwa proc imejitenga kutoka kwa cache iliyoshirikiwa, ikiwa mwanzilishi wa libSystem alipigiwa simu, pointer kwa kichwa cha Mach cha dyld yenyewe, pointer kwa herufi ya toleo la dyld...

## dyld env variables

### debug dyld

Mazingira ya env yenye thamani ambayo husaidia kuelewa ni nini dyld inafanya:

* **DYLD\_PRINT\_LIBRARIES**

Angalia kila maktaba inayopakiwa:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Angalia jinsi kila maktaba inavyopakiwa:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Chapisha wakati kila mwanzilishi wa maktaba anapoendeshwa:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Wengine

* `DYLD_BIND_AT_LAUNCH`: Uunganishaji wa uvivu unatatuliwa na wale wasio wavivu
* `DYLD_DISABLE_PREFETCH`: Lemaza upakiaji wa maudhui ya \_\_DATA na \_\_LINKEDIT mapema
* `DYLD_FORCE_FLAT_NAMESPACE`: Uunganishaji wa ngazi moja
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Njia za ufumbuzi
* `DYLD_INSERT_LIBRARIES`: Pakia maktaba maalum
* `DYLD_PRINT_TO_FILE`: Andika upelelezi wa dyld kwenye faili
* `DYLD_PRINT_APIS`: Chapisha simu za API za libdyld
* `DYLD_PRINT_APIS_APP`: Chapisha simu za API za libdyld zilizofanywa na main
* `DYLD_PRINT_BINDINGS`: Chapisha alama wakati zinapounganishwa
* `DYLD_WEAK_BINDINGS`: Chapisha alama dhaifu tu wakati zinapounganishwa
* `DYLD_PRINT_CODE_SIGNATURES`: Chapisha operesheni za usajili wa saini ya nambari
* `DYLD_PRINT_DOFS`: Chapisha sehemu za muundo wa D-Trace zilizopakiwa
* `DYLD_PRINT_ENV`: Chapisha mazingira yanayoonekana na dyld
* `DYLD_PRINT_INTERPOSTING`: Chapisha operesheni za kuingilia
* `DYLD_PRINT_LIBRARIES`: Chapisha maktaba zilizopakiwa
* `DYLD_PRINT_OPTS`: Chapisha chaguo za upakiaji
* `DYLD_REBASING`: Chapisha operesheni za kubadilisha alama
* `DYLD_RPATHS`: Chapisha upanuzi wa @rpath
* `DYLD_PRINT_SEGMENTS`: Chapisha ramani za sehemu za Mach-O
* `DYLD_PRINT_STATISTICS`: Chapisha takwimu za wakati
* `DYLD_PRINT_STATISTICS_DETAILS`: Chapisha takwimu za wakati kwa undani
* `DYLD_PRINT_WARNINGS`: Chapisha ujumbe wa onyo
* `DYLD_SHARED_CACHE_DIR`: Njia ya kutumia kwa hifadhi ya maktaba iliyoshirikiwa
* `DYLD_SHARED_REGION`: "tumia", "binafsi", "epuka"
* `DYLD_USE_CLOSURES`: Wezesha kufungwa

Inawezekana kupata zaidi na kitu kama:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Au pakua mradi wa dyld kutoka [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) na uendeshe kwenye folda:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Marejeo

* [**\*OS Internals, Kijitabu cha I: Mode ya Mtumiaji. Na Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
