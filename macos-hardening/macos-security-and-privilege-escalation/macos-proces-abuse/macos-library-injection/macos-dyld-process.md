# macOS Dyld Prosedure

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

Die werklike **ingangspunt** van 'n Mach-o binêre lêer is die dinamies gekoppelde, gedefinieer in `LC_LOAD_DYLINKER` is gewoonlik `/usr/lib/dyld`.

Hierdie koppelaar sal al die uitvoerbare biblioteke moet vind, hulle in geheue in kaart bring en al die nie-luie biblioteke koppel. Eers na hierdie proses sal die ingangspunt van die binêre lêer uitgevoer word.

Natuurlik het **`dyld`** geen afhanklikhede nie (dit gebruik stelseloproepe en libSystem-uitreksels).

{% hint style="danger" %}
As hierdie koppelaar enige kwesbaarheid bevat, aangesien dit uitgevoer word voordat enige binêre (selfs hoogs bevoorregte) uitgevoer word, sou dit moontlik wees om **bevoorregting te eskaleer**.
{% endhint %}

### Vloei

Dyld sal deur **`dyldboostrap::start`** gelaai word, wat ook dinge soos die **stapel kanarie** sal laai. Dit is omdat hierdie funksie in sy **`apple`**-argumentvektor hierdie en ander **sensitiewe waardes** sal ontvang.

**`dyls::_main()`** is die ingangspunt van dyld en sy eerste taak is om `configureProcessRestrictions()` uit te voer, wat gewoonlik **`DYLD_*`**-omgewingsveranderlikes beperk soos verduidelik in:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Daarna kaart dit die dyld gedeelde kas wat al die belangrike stelselbiblioteke vooraf koppel en dan kaart dit die biblioteke waarvan die binêre afhanklik is en gaan dan voort op 'n rekursiewe wyse totdat al die benodigde biblioteke gelaai is. Dus:

1. dit begin met die laai van ingevoegde biblioteke met `DYLD_INSERT_LIBRARIES` (indien toegelaat)
2. Dan die gedeelde gekašte een
3. Dan die ingevoerde een
4. Dan gaan dit voort om biblioteke rekursief in te voer

Sodra almal gelaai is, word die **inisialiseerders** van hierdie biblioteke uitgevoer. Hierdie is gekodeer met **`__attribute__((constructor))`** gedefinieer in die `LC_ROUTINES[_64]` (nou verouderd) of deur 'n wyser in 'n afdeling met die vlag `S_MOD_INIT_FUNC_POINTERS` (gewoonlik: **`__DATA.__MOD_INIT_FUNC`**).

Terminators is gekodeer met **`__attribute__((destructor))`** en is geleë in 'n afdeling met die vlag `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Alle binêre lêers in macOS is dinamies gekoppel. Daarom bevat hulle sekere stubs-afdelings wat die binêre help om na die korrekte kode in verskillende rekenaars en kontekste te spring. Dit is dyld wanneer die binêre lêer uitgevoer word, die brein wat hierdie adresse moet oplos (ten minste die nie-luie eenhede).

Sekere stubs-afdelings in die binêre:

* **`__TEXT.__[auth_]stubs`**: Wysers vanaf `__DATA`-afdelings
* **`__TEXT.__stub_helper`**: Klein kode wat dinamiese koppeling aanroep met inligting oor die funksie om te roep
* **`__DATA.__[auth_]got`**: Globale Verskuiwingstabel (adresse na ingevoerde funksies, wanneer opgelos, (gebond gedurende laai-tyd aangesien dit gemerk is met die vlag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Nie-luie simboolwysers (gebond gedurende laai-tyd aangesien dit gemerk is met die vlag `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Luie simboolwysers (gebond met eerste toegang)

{% hint style="warning" %}
Let daarop dat die wysers met die voorvoegsel "auth\_" een in-proses-enkripsiesleutel gebruik om dit te beskerm (PAC). Daarbenewens is dit moontlik om die arm64-instruksie `BLRA[A/B]` te gebruik om die wyser te verifieer voordat dit gevolg word. En die RETA\[A/B\] kan in plaas van 'n RET-adres gebruik word.\
Eintlik sal die kode in **`__TEXT.__auth_stubs`** **`braa`** in plaas van **`bl`** gebruik om die versoekfunksie te roep vir verifikasie van die wyser.

Let ook daarop dat huidige dyld-weergawes **alles as nie-luie** laai.
{% endhint %}

### Vind luie simbole
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interessante disassemblage gedeelte:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Dit is moontlik om te sien dat die sprong na die aanroep van printf na **`__TEXT.__stubs`** gaan:
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
In die ontleed van die **`__stubs`** afdeling:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Jy kan sien dat ons **spring na die adres van die GOT**, wat in hierdie geval nie-lui opgelos word en die adres van die printf funksie sal bevat.

In ander situasies, in plaas van direk na die GOT te spring, kan dit spring na **`__DATA.__la_symbol_ptr`** wat 'n waarde laai wat die funksie verteenwoordig wat dit probeer laai, dan spring na **`__TEXT.__stub_helper`** wat spring na die **`__DATA.__nl_symbol_ptr`** wat die adres van **`dyld_stub_binder`** bevat wat as parameters die nommer van die funksie en 'n adres neem.\
Hierdie laaste funksie, nadat dit die adres van die gesogte funksie gevind het, skryf dit na die ooreenstemmende plek in **`__TEXT.__stub_helper`** om te verhoed dat soekopdragte in die toekoms gedoen moet word.

{% hint style="success" %}
Let egter daarop dat huidige dyld weergawes alles as nie-lui laai.
{% endhint %}

#### Dyld opcodes

Laastens, **`dyld_stub_binder`** moet die aangeduide funksie vind en dit in die regte adres skryf sodat dit nie weer daarna hoef te soek nie. Om dit te doen, gebruik dit opcodes (‘n eindige toestandmasjien) binne dyld.

## apple\[] argument vektor

In macOS ontvang die hooffunksie eintlik 4 argumente in plaas van 3. Die vierde word apple genoem en elke inskrywing is in die vorm `key=value`. Byvoorbeeld:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
### macOS Dyld Process

#### macOS Dyld Proses

The dynamic linker (dyld) is responsible for loading dynamic libraries into a process's address space. Attackers can abuse this process by injecting malicious code into legitimate libraries or by loading malicious libraries into a process. This can lead to privilege escalation and other security issues.

Die dinamiese skakelaar (dyld) is verantwoordelik vir die laai van dinamiese biblioteke in 'n proses se adresruimte. Aanvallers kan hierdie proses misbruik deur kwaadwillige kode in legitieme biblioteke in te spuit of deur kwaadwillige biblioteke in 'n proses te laai. Dit kan lei tot voorreg-escalasie en ander sekuriteitskwessies.
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
Teen die tyd dat hierdie waardes die hooffunksie bereik, is sensitiewe inligting reeds daaruit verwyder of dit sou 'n datalek gewees het.
{% endhint %}

Dit is moontlik om al hierdie interessante waardes te sien tydens die foutopsporing voordat dit in die hooffunksie beland met:

<pre><code>lldb ./apple

<strong>(lldb) teiken skep "./a"
</strong>Huidige uitvoerbare stel in op '/tmp/a' (arm64).
(lldb) proses begin -s
[..]

<strong>(lldb) mem lees $sp
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

Dit is 'n struktuur wat deur dyld uitgevoer word met inligting oor die dyld-toestand wat gevind kan word in die [**bronkode**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) met inligting soos die weergawe, wyser na dyld\_image\_info-reeks, na dyld\_image\_notifier, as die pros van die gedeelde kas afgesonder is, as libSystem-initialiseerder geroep is, wyser na dyld se eie Mach-kop, wyser na dyld-weergawe-string...

## dyld-omgewingsveranderlikes

### foutopsporing dyld

Interessante omgewingsveranderlikes wat help om te verstaan wat dyld doen:

* **DYLD\_PRINT\_LIBRARIES**

Kyk na elke biblioteek wat gelaai is:
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

Kontroleer hoe elke biblioteek gelaai word:
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

Druk af wanneer elke biblioteek-initialiseerder hardloop:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Ander

* `DYLD_BIND_AT_LAUNCH`: Luie bindings word opgelos met nie-luie een
* `DYLD_DISABLE_PREFETCH`: Deaktiveer vooraf ophaling van \_\_DATA en \_\_LINKEDIT inhoud
* `DYLD_FORCE_FLAT_NAMESPACE`: Enkelvlak bindings
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Oplossingspaaie
* `DYLD_INSERT_LIBRARIES`: Laai 'n spesifieke biblioteek
* `DYLD_PRINT_TO_FILE`: Skryf dyld foutopsporing na 'n lêer
* `DYLD_PRINT_APIS`: Druk libdyld API-oproepe
* `DYLD_PRINT_APIS_APP`: Druk libdyld API-oproepe gemaak deur hoof
* `DYLD_PRINT_BINDINGS`: Druk simbole wanneer gebind
* `DYLD_WEAK_BINDINGS`: Druk slegs swak simbole wanneer gebind
* `DYLD_PRINT_CODE_SIGNATURES`: Druk kodesignatuur registrasie-operasies
* `DYLD_PRINT_DOFS`: Druk D-Trace objekformaatseksies soos gelaai
* `DYLD_PRINT_ENV`: Druk omgewing gesien deur dyld
* `DYLD_PRINT_INTERPOSTING`: Druk interpostoperasies
* `DYLD_PRINT_LIBRARIES`: Druk biblioteke wat gelaai is
* `DYLD_PRINT_OPTS`: Druk laaiopties
* `DYLD_REBASING`: Druk simbool herbasering-operasies
* `DYLD_RPATHS`: Druk uitbreidings van @rpath
* `DYLD_PRINT_SEGMENTS`: Druk karterings van Mach-O segmente
* `DYLD_PRINT_STATISTICS`: Druk tydstatistieke
* `DYLD_PRINT_STATISTICS_DETAILS`: Druk gedetailleerde tydstatistieke
* `DYLD_PRINT_WARNINGS`: Druk waarskuwingsboodskappe
* `DYLD_SHARED_CACHE_DIR`: Pad om vir gedeelde biblioteekkas te gebruik
* `DYLD_SHARED_REGION`: "gebruik", "privaat", "vermy"
* `DYLD_USE_CLOSURES`: Aktiveer sluitings

Dit is moontlik om meer te vind met iets soos:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Of laai die dyld projek af van [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) en hardloop binne die vouer:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Verwysings

* [**\*OS Internals, Volume I: User Mode. Deur Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslaan. 

</details>
