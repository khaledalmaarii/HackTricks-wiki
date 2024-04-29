# macOS Dyld Proces

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodiču PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

Pravi **ulaz** binarnog Mach-o fajla je dinamički linkovan, definisan u `LC_LOAD_DYLINKER`, obično je `/usr/lib/dyld`.

Ovaj linker će morati da locira sve izvršne biblioteke, mapira ih u memoriju i poveže sve ne-lenje biblioteke. Tek nakon ovog procesa, izvršiće se ulazna tačka binarnog fajla.

Naravno, **`dyld`** nema nikakve zavisnosti (koristi sistemske pozive i delove libSystem-a).

{% hint style="opasnost" %}
Ako ovaj linker sadrži bilo kakvu ranjivost, budući da se izvršava pre izvršavanja bilo kog binarnog fajla (čak i visoko privilegovanih), bilo bi moguće **eskalirati privilegije**.
{% endhint %}

### Tok

Dyld će biti učitan preko **`dyldboostrap::start`**, koji će takođe učitati stvari poput **stack canary**-ja. To je zato što će ova funkcija primiti u svom **`apple`** argumentu ovu i druge **osetljive** **vrednosti**.

**`dyls::_main()`** je ulazna tačka dyld-a i njegov prvi zadatak je da pokrene `configureProcessRestrictions()`, što obično ograničava **`DYLD_*`** okružne promenljive objašnjene u:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Zatim mapira dyld deljeni keš koji unapred povezuje sve važne sistem biblioteke, a zatim mapira biblioteke od kojih binarni fajl zavisi i nastavlja rekurzivno dok se ne učitaju sve potrebne biblioteke. Stoga:

1. počinje sa učitavanjem ubačenih biblioteka sa `DYLD_INSERT_LIBRARIES` (ako je dozvoljeno)
2. Zatim deljeni keširani
3. Zatim uvežene
1. &#x20;Zatim nastavlja rekurzivno uvoziti biblioteke

Kada su sve učitane, pokreću se **inicijalizatori** ovih biblioteka. Oni su kodirani koristeći **`__attribute__((constructor))`** definisane u `LC_ROUTINES[_64]` (sada zastarelo) ili preko pokazivača u odeljku označenom sa `S_MOD_INIT_FUNC_POINTERS` (obično: **`__DATA.__MOD_INIT_FUNC`**).

Terminatori su kodirani sa **`__attribute__((destructor))`** i nalaze se u odeljku označenom sa `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubovi

Svi binarni fajlovi na macOS-u su dinamički linkovani. Stoga, sadrže neke odeljke stubova koji pomažu binarnom fajlu da skoči na odgovarajući kod u različitim mašinama i kontekstima. Dyld je taj koji mora da reši ove adrese kada se binarni fajl izvrši (barem one koje nisu lenje).

Neki odeljci stubova u binarnom fajlu:

* **`__TEXT.__[auth_]stubs`**: Pokazivači iz `__DATA` odeljaka
* **`__TEXT.__stub_helper`**: Mali kod koji poziva dinamičko linkovanje sa informacijama o funkciji koju treba pozvati
* **`__DATA.__[auth_]got`**: Globalna tabela offseta (adrese uvezenih funkcija, kada se reše, (vezuju se tokom vremena učitavanja jer je označena zastavicom `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Pokazivači na ne-lenje simbole (vezuju se tokom vremena učitavanja jer je označena zastavicom `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Pokazivači na lenje simbole (vezuju se prilikom prvog pristupa)

{% hint style="upozorenje" %}
Imajte na umu da pokazivači sa prefiksom "auth\_" koriste jedan ključ za enkripciju u procesu kako bi ih zaštitili (PAC). Takođe, moguće je koristiti arm64 instrukciju `BLRA[A/B]` da proveri pokazivač pre nego što ga prati. I RETA\[A/B\] se može koristiti umesto adrese RET.\
Zapravo, kod u **`__TEXT.__auth_stubs`** će koristiti **`braa`** umesto **`bl`** da pozove traženu funkciju kako bi autentifikovao pokazivač.

Takođe imajte na umu da trenutne verzije dyld-a učitavaju **sve kao ne-lenje**.
{% endhint %}

### Pronalaženje lenjih simbola
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interesantan deo disasemblera:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Moguće je videti da skok ka pozivu printf ide ka **`__TEXT.__stubs`**:
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
Prilikom rastavljanja **`__stubs`** odeljka:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Možete videti da **skočimo na adresu GOT-a**, koja u ovom slučaju nije lenja i sadržaće adresu funkcije printf.

U drugim situacijama umesto direktnog skakanja na GOT, može se skočiti na **`__DATA.__la_symbol_ptr`** koji će učitati vrednost koja predstavlja funkciju koju pokušava da učita, zatim skočiti na **`__TEXT.__stub_helper`** koji skače na **`__DATA.__nl_symbol_ptr`** koji sadrži adresu **`dyld_stub_binder`** koji kao parametre uzima broj funkcije i adresu.\
Ova poslednja funkcija, nakon što pronađe adresu tražene funkcije, upisuje je na odgovarajuće mesto u **`__TEXT.__stub_helper`** kako bi izbegla pretragu u budućnosti.

{% hint style="success" %}
Međutim, primetite da trenutne verzije dyld-a sve učitavaju kao ne-lenje.
{% endhint %}

#### Dyld opcode

Konačno, **`dyld_stub_binder`** mora pronaći naznačenu funkciju i upisati je na odgovarajuću adresu kako je ne bi ponovo tražio. Da bi to postigao, koristi opcode-ove (konačni automat) unutar dyld-a.

## apple\[] argument vektor

U macOS-u, glavna funkcija zapravo prima 4 argumenta umesto 3. Četvrti se zove apple i svaki unos je u obliku `ključ=vrednost`. Na primer:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
## macOS Dyld Process

### macOS Biblioteka ubrizgavanje

Biblioteka ubrizgavanje je tehnika koja omogućava napadaču da ubaci zlonamernu biblioteku u proces kako bi dobio kontrolu nad izvršavanjem. Ova tehnika se često koristi za postizanje privilegija eskalacije ili za skrivanje zlonamernih aktivnosti. Dyld (dinamički linker) je odgovoran za učitavanje i povezivanje dinamičkih biblioteka u macOS operativnom sistemu. Napadač može iskoristiti ranjivosti u dyld procesu kako bi ubacio zlonamernu biblioteku i preuzeo kontrolu nad sistemom.
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
Kada ove vrednosti stignu do glavne funkcije, osetljive informacije već su uklonjene iz njih ili bi došlo do curenja podataka.
{% endhint %}

Moguće je videti sve ove interesantne vrednosti prilikom debagovanja pre ulaska u glavnu funkciju sa:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Trenutni izvršni fajl postavljen je na '/tmp/a' (arm64).
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

Ovo je struktura izvezena od strane dyld-a sa informacijama o stanju dyld-a koje se može pronaći u [**izvornom kodu**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) sa informacijama poput verzije, pokazivača na niz dyld\_image\_info, na dyld\_image\_notifier, da li je proces odvojen od deljenog keša, da li je inicijalizator libSystem-a pozvan, pokazivač na Mach zaglavlje dyld-a, pokazivač na verziju dyld-a...

## dyld env promenljive

### debug dyld

Interesantne env promenljive koje pomažu u razumevanju šta dyld radi:

* **DYLD\_PRINT\_LIBRARIES**

Proverite svaku biblioteku koja je učitana:
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

Proverite kako je svaka biblioteka učitana:
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

Štampajte kada se pokreće svaki inicijalizator biblioteke:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Ostali

* `DYLD_BIND_AT_LAUNCH`: Lenje veze se rešavaju sa ne-lenjim vezama
* `DYLD_DISABLE_PREFETCH`: Onemogućava preuzimanje \_\_DATA i \_\_LINKEDIT sadržaja
* `DYLD_FORCE_FLAT_NAMESPACE`: Veze na jednom nivou
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Putanje za rešavanje
* `DYLD_INSERT_LIBRARIES`: Učitava određenu biblioteku
* `DYLD_PRINT_TO_FILE`: Piše dyld debug u fajl
* `DYLD_PRINT_APIS`: Ispisuje pozive libdyld API-ja
* `DYLD_PRINT_APIS_APP`: Ispisuje pozive libdyld API-ja napravljene od strane glavne aplikacije
* `DYLD_PRINT_BINDINGS`: Ispisuje simbole kada su vezani
* `DYLD_WEAK_BINDINGS`: Ispisuje samo slabe simbole kada su vezani
* `DYLD_PRINT_CODE_SIGNATURES`: Ispisuje operacije registracije potpisa koda
* `DYLD_PRINT_DOFS`: Ispisuje sekcije formata objekta D-Trace-a koje su učitane
* `DYLD_PRINT_ENV`: Ispisuje okruženje viđeno od strane dyld-a
* `DYLD_PRINT_INTERPOSTING`: Ispisuje operacije interpostovanja
* `DYLD_PRINT_LIBRARIES`: Ispisuje učitane biblioteke
* `DYLD_PRINT_OPTS`: Ispisuje opcije učitavanja
* `DYLD_REBASING`: Ispisuje operacije relokacije simbola
* `DYLD_RPATHS`: Ispisuje proširenja @rpath
* `DYLD_PRINT_SEGMENTS`: Ispisuje mapiranja Mach-O segmenata
* `DYLD_PRINT_STATISTICS`: Ispisuje statistiku vremena
* `DYLD_PRINT_STATISTICS_DETAILS`: Ispisuje detaljnu statistiku vremena
* `DYLD_PRINT_WARNINGS`: Ispisuje upozorenja
* `DYLD_SHARED_CACHE_DIR`: Putanja za korišćenje keša deljenih biblioteka
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Omogućava zatvaranja

Moguće je pronaći više sa nečim poput:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ili preuzimanje dyld projekta sa [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) i pokretanje unutar foldera:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Reference

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA ČLANSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
