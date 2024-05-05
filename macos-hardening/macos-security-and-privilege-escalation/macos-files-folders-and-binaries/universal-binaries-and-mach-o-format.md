# macOS Uniwersalne pliki binarne i format Mach-O

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>

## Podstawowe informacje

Binarki systemu Mac OS zazwyczaj są kompilowane jako **uniwersalne pliki binarne**. **Uniwersalny plik binarny** może **obsługiwać wiele architektur w tym samym pliku**.

Te binarki podążają za **strukturą Mach-O**, która składa się z:

* Nagłówka
* Komend ładowania
* Danych

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Nagłówek Fat

Wyszukaj plik za pomocą: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* liczba struktur, które następują */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* określacz CPU (int) */
cpu_subtype_t	cpusubtype;	/* określacz maszyny (int) */
uint32_t	offset;		/* przesunięcie pliku do tego pliku obiektu */
uint32_t	size;		/* rozmiar tego pliku obiektu */
uint32_t	align;		/* wyrównanie jako potęga liczby 2 */
};
</code></pre>

Nagłówek zawiera **magiczne** bajty, a następnie **liczbę** **architektur**, które plik **zawiera** (`nfat_arch`), a każda architektura będzie miała strukturę `fat_arch`.

Sprawdź to za pomocą:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O uniwersalny plik binarny z 2 architekturami: [x86_64:Mach-O 64-bitowy plik wykonywalny x86_64] [arm64e:Mach-O 64-bitowy plik wykonywalny arm64e]
/bin/ls (dla architektury x86_64):	Mach-O 64-bitowy plik wykonywalny x86_64
/bin/ls (dla architektury arm64e):	Mach-O 64-bitowy plik wykonywalny arm64e

% otool -f -v /bin/ls
Nagłówki Fat
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architektura x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    przesunięcie 16384
</strong><strong>    rozmiar 72896
</strong>    wyrównanie 2^14 (16384)
<strong>architektura arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    przesunięcie 98304
</strong><strong>    rozmiar 88816
</strong>    wyrównanie 2^14 (16384)
</code></pre>

lub używając narzędzia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Jak możesz sobie wyobrazić, zazwyczaj uniwersalny plik binarny skompilowany dla 2 architektur **podwaja rozmiar** w porównaniu z tym skompilowanym tylko dla 1 architektury.

## **Nagłówek Mach-O**

Nagłówek zawiera podstawowe informacje o pliku, takie jak magiczne bajty identyfikujące go jako plik Mach-O oraz informacje o architekturze docelowej. Możesz go znaleźć w: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Typy plików Mach-O

Istnieją różne typy plików, można je znaleźć zdefiniowane w [**źródłowym kodzie na przykład tutaj**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Najważniejsze z nich to:

* `MH_OBJECT`: Plik obiektowy do przenoszenia (produkty pośrednie kompilacji, jeszcze nie wykonywalne).
* `MH_EXECUTE`: Pliki wykonywalne.
* `MH_FVMLIB`: Plik biblioteki VM o stałym rozmiarze.
* `MH_CORE`: Zrzuty kodu.
* `MH_PRELOAD`: Plik wykonywalny wczytany z góry (już nieobsługiwany w XNU).
* `MH_DYLIB`: Biblioteki dynamiczne.
* `MH_DYLINKER`: Łącznik dynamiczny.
* `MH_BUNDLE`: "Pliki wtyczek". Generowane za pomocą -bundle w gcc i ładowane jawnie przez `NSBundle` lub `dlopen`.
* `MH_DYSM`: Plik towarzyszący `.dSym` (plik ze symbolami do debugowania).
* `MH_KEXT_BUNDLE`: Rozszerzenia jądra.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Lub używając [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flagi Mach-O**

Kod źródłowy definiuje również kilka przydatnych flag do ładowania bibliotek:

* `MH_NOUNDEFS`: Brak niesprecyzowanych odwołań (w pełni połączony)
* `MH_DYLDLINK`: Łączenie Dyld
* `MH_PREBOUND`: Dynamiczne odwołania są wcześniej związane.
* `MH_SPLIT_SEGS`: Plik dzieli segmenty tylko do odczytu i do zapisu.
* `MH_WEAK_DEFINES`: Binarne symbole zdefiniowane jako słabe
* `MH_BINDS_TO_WEAK`: Binarne używa słabych symboli
* `MH_ALLOW_STACK_EXECUTION`: Umożliwia wykonanie stosu
* `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nie zawiera poleceń LC\_REEXPORT
* `MH_PIE`: Wykonywalny o niezależnej pozycji
* `MH_HAS_TLV_DESCRIPTORS`: Istnieje sekcja z zmiennymi lokalnymi wątku
* `MH_NO_HEAP_EXECUTION`: Brak wykonania dla stron sterty/danych
* `MH_HAS_OBJC`: Binarne sekcje oBject-C
* `MH_SIM_SUPPORT`: Wsparcie dla symulatora
* `MH_DYLIB_IN_CACHE`: Używane w dylibs/frameworks w udostępnionej pamięci biblioteki.

## **Polecenia ładowania Mach-O**

**Układ pliku w pamięci** jest tutaj określony, szczegółowo opisując **lokalizację tabeli symboli**, kontekst głównego wątku na początku wykonania oraz wymagane **biblioteki współdzielone**. Instrukcje są dostarczane do dynamicznego ładowacza **(dyld)** dotyczące procesu ładowania binarnego do pamięci.

Używa struktury **load\_command**, zdefiniowanej w wspomnianym pliku **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Istnieje około **50 różnych rodzajów poleceń ładowania**, które system obsługuje w inny sposób. Najczęstsze z nich to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
W zasadzie ten rodzaj polecenia ładowania definiuje **sposób wczytywania segmentów \_\_TEXT** (kod wykonywalny) **i \_\_DATA** (dane procesu) **zgodnie z przesunięciami wskazanymi w sekcji danych** podczas wykonywania binariatu.
{% endhint %}

Te polecenia **definiują segmenty**, które są **mapowane** do **przestrzeni pamięci wirtualnej** procesu podczas jego wykonywania.

Istnieją **różne rodzaje** segmentów, takie jak segment **\_\_TEXT**, który przechowuje kod wykonywalny programu, oraz segment **\_\_DATA**, który zawiera dane używane przez proces. Te **segmenty znajdują się w sekcji danych** pliku Mach-O.

**Każdy segment** może być dodatkowo **podzielony** na wiele **sekcji**. Struktura **polecenia ładowania** zawiera **informacje** o **tych sekcjach** w odpowiednim segmencie.

W nagłówku znajduje się najpierw **nagłówek segmentu**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* dla architektur 64-bitowych */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* zawiera rozmiar struktur section_64 */
char		segname[16];	/* nazwa segmentu */
uint64_t	vmaddr;		/* adres pamięci tego segmentu */
uint64_t	vmsize;		/* rozmiar pamięci tego segmentu */
uint64_t	fileoff;	/* przesunięcie pliku tego segmentu */
uint64_t	filesize;	/* ilość do zmapowania z pliku */
int32_t		maxprot;	/* maksymalna ochrona VM */
int32_t		initprot;	/* początkowa ochrona VM */
<strong>	uint32_t	nsects;		/* liczba sekcji w segmencie */
</strong>	uint32_t	flags;		/* flagi */
};
</code></pre>

Przykład nagłówka segmentu:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Ten nagłówek definiuje **liczbę sekcji, których nagłówki pojawiają się po** nim:
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
Przykład **nagłówka sekcji**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Jeśli **dodasz** **przesunięcie sekcji** (0x37DC) + **przesunięcie**, gdzie **arch zaczyna się**, w tym przypadku `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Można również uzyskać informacje o **nagłówkach** z **wiersza poleceń** za pomocą:
```bash
otool -lv /bin/ls
```
```markdown
Wspólne segmenty ładowane przez tę komendę:

* **`__PAGEZERO`:** Wskazuje jądrze, aby **mapowało** **adres zero**, dzięki czemu **nie można go odczytać, zapisać ani wykonać**. Zmienne maxprot i minprot w strukturze są ustawione na zero, aby wskazać, że na tej stronie **nie ma praw do odczytu-zapisu-wykonania**.
* Ta alokacja jest ważna dla **zmniejszenia podatności na odwołania do wskaźników NULL**. Wynika to z faktu, że XNU narzuca twardą stronę zero, która zapewnia, że pierwsza strona (tylko pierwsza) pamięci jest nieosiągalna (oprócz w i386). Binarny może spełnić te wymagania, tworząc małe \_\_PAGEZERO (używając `-pagezero_size`) obejmujące pierwsze 4k i pozwalając na dostęp do reszty pamięci 32-bitowej zarówno w trybie użytkownika, jak i jądra.
* **`__TEXT`**: Zawiera **wykonywalny** **kod** z uprawnieniami **do odczytu** i **wykonania** (bez możliwości zapisu)**.** Wspólne sekcje tego segmentu:
* `__text`: Skompilowany kod binarny
* `__const`: Dane stałe (tylko do odczytu)
* `__[c/u/os_log]string`: Stałe łańcuchy znaków C, Unicode lub os logs
* `__stubs` i `__stubs_helper`: Zaangażowane podczas procesu dynamicznego ładowania bibliotek
* `__unwind_info`: Dane rozluźniania stosu.
* Należy zauważyć, że cała ta zawartość jest podpisana, ale również oznaczona jako wykonywalna (tworząc więcej opcji do eksploatacji sekcji, które niekoniecznie potrzebują tego uprawnienia, jak sekcje dedykowane łańcuchom znaków).
* **`__DATA`**: Zawiera dane, które są **do odczytu** i **zapisu** (bez możliwości wykonania)**.**
* `__got:` Globalna tabela przesunięć
* `__nl_symbol_ptr`: Wskaźnik symbolu nie leniwego (wiąż przy ładowaniu)
* `__la_symbol_ptr`: Wskaźnik symbolu leniwego (wiąż przy użyciu)
* `__const`: Powinny być to dane tylko do odczytu (w rzeczywistości nie)
* `__cfstring`: Łańcuchy CoreFoundation
* `__data`: Zmienne globalne (które zostały zainicjowane)
* `__bss`: Zmienne statyczne (które nie zostały zainicjowane)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, itp.): Informacje używane przez środowisko uruchomieniowe Objective-C
* **`__DATA_CONST`**: \_\_DATA.\_\_const nie jest gwarantowane jako stałe (uprawnienia do zapisu), podobnie jak inne wskaźniki i tabela GOT. Ta sekcja sprawia, że `__const`, niektóre inicjalizatory i tabela GOT (po rozwiązaniu) są **tylko do odczytu** za pomocą `mprotect`.
* **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak wpisy do tabel symboli, łańcuchów i relokacji. Jest to ogólny kontener na treści, które nie znajdują się w `__TEXT` ani `__DATA`, a jego zawartość jest opisana w innych poleceniach ładowania.
* Informacje dyld: Rebase, operacje wiązania nie leniwego/leniwego/słabego i informacje o eksporcie
* Początki funkcji: Tabela adresów początkowych funkcji
* Dane w kodzie: Wyspy danych w \_\_text
* Tabela symboli: Symbole w binarnym pliku
* Tabela symboli pośrednich: Symbole wskaźników/stubów
* Tabela łańcuchów znaków
* Sygnatura kodu
* **`__OBJC`**: Zawiera informacje używane przez środowisko uruchomieniowe Objective-C. Chociaż te informacje mogą być również znalezione w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.
* **`__RESTRICT`**: Segment bez zawartości z pojedynczą sekcją o nazwie **`__restrict`** (również pustą), która zapewnia, że podczas uruchamiania binarnego zostaną zignorowane zmienne środowiskowe DYLD.

Jak można było zauważyć w kodzie, **segmenty również obsługują flagi** (choć nie są one zbyt często używane):

* `SG_HIGHVM`: Tylko rdzeń (nieużywane)
* `SG_FVMLIB`: Nie używane
* `SG_NORELOC`: Segment nie ma relokacji
* `SG_PROTECTED_VERSION_1`: Szyfrowanie. Używane na przykład przez Finder do szyfrowania tekstu w segmencie `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** zawiera punkt wejścia w atrybucie **entryoff**. Podczas ładowania, **dyld** po prostu **dodaje** tę wartość do (w pamięci) **bazowego adresu binarnego**, a następnie **przechodzi** do tej instrukcji, aby rozpocząć wykonywanie kodu binarnego.

**`LC_UNIXTHREAD`** zawiera wartości rejestrów, które muszą być ustawione podczas rozpoczynania głównego wątku. Jest to już przestarzałe, ale **`dyld`** wciąż tego używa. Można zobaczyć wartości rejestrów ustawione przez to polecenie za pomocą:
```
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

Zawiera informacje na temat **podpisu kodu pliku Mach-O**. Zawiera tylko **przesunięcie**, które **wskazuje** na **blok podpisu**. Zazwyczaj znajduje się na samym końcu pliku.\
Można jednak znaleźć pewne informacje na temat tej sekcji w [**tym wpisie na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) oraz w tym [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Obsługuje szyfrowanie binarne. Jednak oczywiście, jeśli atakujący zdoła skompromitować proces, będzie mógł zrzucić pamięć bez szyfrowania.

### **`LC_LOAD_DYLINKER`**

Zawiera **ścieżkę do wykonywalnego dynamicznego łącznika**, który mapuje biblioteki współdzielone do przestrzeni adresowej procesu. **Wartość zawsze jest ustawiona na `/usr/lib/dyld`**. Ważne jest zauważenie, że w macOS mapowanie dylibów odbywa się w **trybie użytkownika**, a nie w trybie jądra.

### **`LC_IDENT`**

Przestarzałe, ale gdy skonfigurowane do generowania zrzutów w przypadku paniki, tworzony jest zrzut rdzenia Mach-O, a wersja jądra jest ustawiana w poleceniu `LC_IDENT`.

### **`LC_UUID`**

Losowy UUID. Jest przydatny do niczego bezpośrednio, ale XNU przechowuje go wraz z resztą informacji o procesie. Może być używany w raportach o awariach.

### **`LC_DYLD_ENVIRONMENT`**

Pozwala wskazać zmienne środowiskowe dla dyld przed wykonaniem procesu. Może to być bardzo niebezpieczne, ponieważ pozwala to na wykonanie arbitralnego kodu wewnątrz procesu, dlatego to polecenie ładowania jest używane tylko w dyld zbudowanym z `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatkowo ogranicza przetwarzanie tylko do zmiennych o formie `DYLD_..._PATH` określających ścieżki ładowania.

### **`LC_LOAD_DYLIB`**

To polecenie ładowania opisuje zależność **dynamicznej biblioteki**, które **nakazuje** **ładowaczowi** (dyld) **załadowanie i połączenie tej biblioteki**. Istnieje polecenie ładowania `LC_LOAD_DYLIB` **dla każdej biblioteki**, którą wymaga plik Mach-O.

* To polecenie ładowania jest strukturą typu **`dylib_command`** (która zawiera strukturę dylib, opisującą rzeczywistą zależną dynamiczną bibliotekę):
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![](<../../../.gitbook/assets/image (486).png>)

Możesz również uzyskać te informacje za pomocą wiersza poleceń:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Potencjalne biblioteki związane z złośliwym oprogramowaniem to:

* **DiskArbitration**: Monitorowanie dysków USB
* **AVFoundation:** Przechwytywanie dźwięku i obrazu
* **CoreWLAN**: Skanowanie sieci Wifi.

{% hint style="info" %}
Plik Mach-O może zawierać jeden lub **więcej konstruktorów**, które zostaną **wykonane przed** adresem określonym w **LC\_MAIN**.\
Przesunięcia dowolnych konstruktorów są przechowywane w sekcji **\_\_mod\_init\_func** segmentu **\_\_DATA\_CONST**.
{% endhint %}

## **Dane Mach-O**

W centrum pliku znajduje się obszar danych, który składa się z kilku segmentów zdefiniowanych w obszarze poleceń ładowania. **W każdym segmencie może być umieszczonych wiele sekcji danych**, z każdą sekcją **zawierającą kod lub dane** specyficzne dla danego typu.

{% hint style="success" %}
Dane to w zasadzie część zawierająca wszystkie **informacje**, które są ładowane przez polecenia ładowania **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Obejmuje to:

* **Tabela funkcji:** Która zawiera informacje o funkcjach programu.
* **Tabela symboli**: Która zawiera informacje o zewnętrznych funkcjach używanych przez plik binarny
* Może również zawierać wewnętrzne funkcje, nazwy zmiennych i inne.

Aby sprawdzić to, można skorzystać z narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Lub z wiersza poleceń:
```bash
size -m /bin/ls
```
## Sekcje wspólne Objective-C

W segmencie `__TEXT` (r-x):

- `__objc_classname`: Nazwy klas (ciągi znaków)
- `__objc_methname`: Nazwy metod (ciągi znaków)
- `__objc_methtype`: Typy metod (ciągi znaków)

W segmencie `__DATA` (rw-):

- `__objc_classlist`: Wskaźniki do wszystkich klas Objective-C
- `__objc_nlclslist`: Wskaźniki do klas Objective-C Non-Lazy
- `__objc_catlist`: Wskaźnik do kategorii
- `__objc_nlcatlist`: Wskaźnik do kategorii Non-Lazy
- `__objc_protolist`: Lista protokołów
- `__objc_const`: Dane stałe
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
