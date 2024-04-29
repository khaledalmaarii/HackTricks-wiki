# Proces Dyld w macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Podstawowe informacje

Rzeczywistym **punktem wejścia** binarnej Mach-o jest dynamiczny linker, zdefiniowany w `LC_LOAD_DYLINKER`, zazwyczaj znajduje się w `/usr/lib/dyld`.

Ten linker będzie musiał zlokalizować wszystkie biblioteki wykonywalne, zmapować je w pamięci i połączyć wszystkie biblioteki nie-leniwie. Dopiero po tym procesie zostanie wykonany punkt wejścia binarny.

Oczywiście **`dyld`** nie ma żadnych zależności (korzysta z wywołań systemowych i fragmentów libSystem).

{% hint style="danger" %}
Jeśli ten linker zawiera jakąkolwiek podatność, ponieważ jest wykonywany przed wykonaniem jakiegokolwiek binarnego (nawet tych o wysokich uprawnieniach), byłoby możliwe **eskalowanie uprawnień**.
{% endhint %}

### Przepływ

Dyld zostanie załadowany przez **`dyldboostrap::start`**, który również załaduje rzeczy takie jak **canary stosu**. Dzieje się tak, ponieważ ta funkcja otrzyma w swoim argumencie **`apple`** ten i inne **wrażliwe** **wartości**.

**`dyls::_main()`** jest punktem wejścia dyld i jego pierwszym zadaniem jest uruchomienie `configureProcessRestrictions()`, która zazwyczaj ogranicza zmienne środowiskowe **`DYLD_*`** wyjaśnione w:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Następnie mapuje współdzieloną pamięć podręczną dyld, która prelinkuje wszystkie ważne biblioteki systemowe, a następnie mapuje biblioteki, od których zależy binarny, i kontynuuje rekurencyjnie, aż wszystkie potrzebne biblioteki zostaną załadowane. Dlatego:

1. zaczyna ładować wstawione biblioteki za pomocą `DYLD_INSERT_LIBRARIES` (jeśli jest to dozwolone)
2. Następnie te współdzielone podręczne
3. Następnie importowane
1. &#x20;Następnie kontynuuje importowanie bibliotek rekurencyjnie

Gdy wszystkie są załadowane, uruchamiane są **inicjatory** tych bibliotek. Są one kodowane za pomocą **`__attribute__((constructor))`** zdefiniowane w `LC_ROUTINES[_64]` (obecnie przestarzałe) lub za pomocą wskaźnika w sekcji oznaczonej flagą `S_MOD_INIT_FUNC_POINTERS` (zazwyczaj: **`__DATA.__MOD_INIT_FUNC`**).

Terminatory są kodowane za pomocą **`__attribute__((destructor))`** i znajdują się w sekcji oznaczonej flagą `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Wskaźniki

Wszystkie binarne pliki w macOS są dynamicznie łączone. Dlatego zawierają pewne sekcje stubs, które pomagają binarnemu skoczyć do poprawnego kodu w różnych maszynach i kontekstach. To dyld, gdy binarny jest wykonywany, musi rozwiązać te adresy (przynajmniej te nie-leniwie).

Niektóre sekcje stubs w binarnym:

* **`__TEXT.__[auth_]stubs`**: Wskaźniki z sekcji `__DATA`
* **`__TEXT.__stub_helper`**: Mały kod wywołujący dynamiczne łączenie z informacją o funkcji do wywołania
* **`__DATA.__[auth_]got`**: Globalna tabela przesunięć (adresy do importowanych funkcji, rozwiązane podczas czasu ładowania, ponieważ jest oznaczone flagą `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Wskaźniki symboli nie-leniwych (rozwiązane podczas czasu ładowania, ponieważ jest oznaczone flagą `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Wskaźniki symboli leniwych (rozwiązane przy pierwszym dostępie)

{% hint style="warning" %}
Zauważ, że wskaźniki z prefiksem "auth\_" używają jednego klucza szyfrowania w procesie do ochrony (PAC). Ponadto możliwe jest użycie instrukcji arm64 `BLRA[A/B]` do weryfikacji wskaźnika przed jego śledzeniem. A zamiast adresu RET można użyć RETA\[A/B\].\
Faktycznie kod w **`__TEXT.__auth_stubs`** będzie używał **`braa`** zamiast **`bl`** do wywołania żądanej funkcji w celu uwierzytelnienia wskaźnika.

Zauważ również, że obecne wersje dyld ładują **wszystko jako nie-lenwe**.
{% endhint %}

### Wyszukiwanie symboli leniwych
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interesujący fragment rozkładu:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Możliwe jest zauważenie, że skok do wywołania printf przechodzi do **`__TEXT.__stubs`**:
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
Podczas analizy sekcji **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Możesz zauważyć, że **skaczemy do adresu GOT**, który w tym przypadku jest rozwiązany natychmiastowo i będzie zawierał adres funkcji printf.

W innych sytuacjach zamiast bezpośrednio skakać do GOT, można skoczyć do **`__DATA.__la_symbol_ptr`**, który załaduje wartość reprezentującą funkcję, którą próbuje załadować, a następnie skoczyć do **`__TEXT.__stub_helper`**, który skacze do **`__DATA.__nl_symbol_ptr`**, który zawiera adres **`dyld_stub_binder`**, który jako parametry przyjmuje numer funkcji i adres.\
Ta ostatnia funkcja, po znalezieniu adresu poszukiwanej funkcji, zapisuje go w odpowiednim miejscu w **`__TEXT.__stub_helper`**, aby uniknąć przeszukiwania w przyszłości.

{% hint style="success" %}
Zauważ jednak, że obecne wersje dyld ładują wszystko jako natychmiastowe.
{% endhint %}

#### Opcodes Dyld

W końcu, **`dyld_stub_binder`** musi znaleźć wskazaną funkcję i zapisać ją pod odpowiednim adresem, aby nie szukać jej ponownie. Aby to zrobić, używa operacji (maszyny stanów skończonych) wewnątrz dyld.

## apple\[] argument vector

W macOS funkcja główna faktycznie otrzymuje 4 argumenty zamiast 3. Czwarty nazywa się apple, a każdy wpis ma formę `klucz=wartość`. Na przykład:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
## macOS Dynamic Linker (dyld) Process

### macOS Biblioteka Wstrzykiwania

Biblioteka dynamiczna (dyld) w systemie macOS jest odpowiedzialna za ładowanie plików wykonywalnych i bibliotek do pamięci procesu. Atakujący może wykorzystać proces ładowania bibliotek przez dyld do wstrzyknięcia złośliwego kodu do procesu lub do nadpisania istniejących funkcji bibliotecznych. To może prowadzić do eskalacji uprawnień lub innych ataków na system. Aby zabezpieczyć system macOS przed tego typu atakami, należy podjąć odpowiednie środki ostrożności, takie jak monitorowanie procesów, ograniczanie uprawnień procesów oraz regularne aktualizacje systemu.
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
Do czasu dotarcia tych wartości do funkcji głównej, wrażliwe informacje zostały już z nich usunięte lub doszłoby do wycieku danych.
{% endhint %}

można zobaczyć wszystkie te interesujące wartości debugując przed wejściem do funkcji głównej za pomocą:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Aktualny plik wykonywalny ustawiony na '/tmp/a' (arm64).
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

Jest to struktura eksportowana przez dyld z informacjami o stanie dyld, które można znaleźć w [**kodzie źródłowym**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) z informacjami takimi jak wersja, wskaźnik do tablicy dyld\_image\_info, do dyld\_image\_notifier, czy proces jest odłączony od pamięci podręcznej współdzielonej, czy został wywołany inicjalizator libSystem, wskaźnik do własnego nagłówka Mach dyld, wskaźnik do ciągu wersji dyld...

## Zmienne środowiskowe dyld

### debug dyld

Interesujące zmienne środowiskowe pomagające zrozumieć, co robi dyld:

* **DYLD\_PRINT\_LIBRARIES**

Sprawdź każdą bibliotekę, która jest ładowana:
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

Sprawdź, jak jest ładowana każda biblioteka:
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

Drukuj, kiedy uruchamiany jest każdy inicjalizator biblioteki:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Inne

* `DYLD_BIND_AT_LAUNCH`: Leniwe wiązania są rozwiązywane z wiązaniami natychmiastowymi
* `DYLD_DISABLE_PREFETCH`: Wyłącza wczytywanie wstępne zawartości \_\_DATA i \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Wiązania jednopoziomowe
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Ścieżki rozwiązania
* `DYLD_INSERT_LIBRARIES`: Ładuje określoną bibliotekę
* `DYLD_PRINT_TO_FILE`: Zapisuje debugowanie dyld do pliku
* `DYLD_PRINT_APIS`: Wyświetla wywołania API libdyld
* `DYLD_PRINT_APIS_APP`: Wyświetla wywołania API libdyld dokonane przez główny program
* `DYLD_PRINT_BINDINGS`: Wyświetla symbole podczas wiązania
* `DYLD_WEAK_BINDINGS`: Wyświetla tylko słabe symbole podczas wiązania
* `DYLD_PRINT_CODE_SIGNATURES`: Wyświetla operacje rejestracji sygnatur kodu
* `DYLD_PRINT_DOFS`: Wyświetla sekcje formatu obiektu D-Trace jako załadowane
* `DYLD_PRINT_ENV`: Wyświetla środowisko widziane przez dyld
* `DYLD_PRINT_INTERPOSTING`: Wyświetla operacje interpostowania
* `DYLD_PRINT_LIBRARIES`: Wyświetla załadowane biblioteki
* `DYLD_PRINT_OPTS`: Wyświetla opcje ładowania
* `DYLD_REBASING`: Wyświetla operacje przesunięcia symboli
* `DYLD_RPATHS`: Wyświetla rozwinięcia @rpath
* `DYLD_PRINT_SEGMENTS`: Wyświetla odwzorowania segmentów Mach-O
* `DYLD_PRINT_STATISTICS`: Wyświetla statystyki czasowe
* `DYLD_PRINT_STATISTICS_DETAILS`: Wyświetla szczegółowe statystyki czasowe
* `DYLD_PRINT_WARNINGS`: Wyświetla komunikaty ostrzegawcze
* `DYLD_SHARED_CACHE_DIR`: Ścieżka do użycia dla pamięci podręcznej współdzielonych bibliotek
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Włącza zamknięcia

Możliwe jest znalezienie więcej za pomocą:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Lub pobierając projekt dyld z [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) i uruchamiając go wewnątrz folderu:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Odnośniki

* [**\*OS Internals, Tom I: Tryb Użytkownika. Autor: Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Zacznij od zera i zostań mistrzem hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
