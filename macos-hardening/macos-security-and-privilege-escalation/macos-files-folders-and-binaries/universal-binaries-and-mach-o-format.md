# Uniwersalne pliki wykonywalne w macOS i format Mach-O

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Podstawowe informacje

Binaria w systemie macOS zazwyczaj są kompilowane jako **uniwersalne pliki wykonywalne**. **Uniwersalny plik wykonywalny** może **obsługiwać wiele architektur w tym samym pliku**.

Te pliki wykonywalne stosują **strukturę Mach-O**, która składa się z:

* Nagłówek
* Polecenia ładowania
* Dane

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

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
/bin/ls: Mach-O uniwersalny plik wykonywalny z 2 architekturami: [x86_64:Mach-O 64-bitowy plik wykonywalny x86_64] [arm64e:Mach-O 64-bitowy plik wykonywalny arm64e]
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

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jak możesz sobie wyobrazić, zazwyczaj uniwersalny plik skompilowany dla 2 architektur **podwaja rozmiar** w porównaniu z plikiem skompilowanym tylko dla 1 architektury.

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
**Typy plików**:

* MH\_EXECUTE (0x2): Standardowy plik wykonywalny Mach-O
* MH\_DYLIB (0x6): Biblioteka dynamiczna Mach-O (np. .dylib)
* MH\_BUNDLE (0x8): Pakiet Mach-O (np. .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Lub używając [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Polecenia ładowania Mach-O**

**Układ pliku w pamięci** jest tutaj określony, szczegółowo opisując **lokalizację tabeli symboli**, kontekst głównego wątku na początku wykonania oraz wymagane **biblioteki współdzielone**. Instrukcje są dostarczane do dynamicznego ładowacza **(dyld)** dotyczące procesu ładowania binarnego do pamięci.

Używa struktury **load\_command**, zdefiniowanej w wspomnianym **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Istnieje około **50 różnych rodzajów poleceń ładowania**, które system obsługuje w inny sposób. Najczęstsze z nich to: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
W zasadzie ten rodzaj polecenia ładowania definiuje **sposób ładowania segmentów \_\_TEXT** (kod wykonywalny) **i \_\_DATA** (dane procesu) **zgodnie z przesunięciami wskazanymi w sekcji danych** podczas wykonywania binariatu.
{% endhint %}

Te polecenia **definiują segmenty**, które są **mapowane** do **przestrzeni pamięci wirtualnej** procesu podczas jego wykonywania.

Istnieją **różne rodzaje** segmentów, takie jak segment **\_\_TEXT**, który przechowuje kod wykonywalny programu, oraz segment **\_\_DATA**, który zawiera dane używane przez proces. Te **segmenty znajdują się w sekcji danych** pliku Mach-O.

**Każdy segment** może być dalej **podzielony** na wiele **sekcji**. Struktura **polecenia ładowania** zawiera **informacje** o **tych sekcjach** w odpowiednim segmencie.

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

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ten nagłówek definiuje **liczbę sekcji, których nagłówki po nim występują**:
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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Jeśli **dodasz** **przesunięcie sekcji** (0x37DC) + **przesunięcie**, gdzie **arch zaczyna się**, w tym przypadku `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Możliwe jest również uzyskanie informacji o **nagłówkach** z **wiersza poleceń** za pomocą:
```bash
otool -lv /bin/ls
```
```markdown
Wspólne segmenty ładowane przez tę komendę:

* **`__PAGEZERO`:** Instruuje jądro, aby **mapowało** **adres zero**, więc **nie można go odczytać, zapisać ani wykonać**. Zmienne maxprot i minprot w strukturze są ustawione na zero, aby wskazać, że na tej stronie **nie ma praw do odczytu-zapisu-wykonania**.
* Ta alokacja jest ważna do **zmniejszenia podatności na odwołania do wskaźników NULL**.
* **`__TEXT`**: Zawiera **wykonywalny** **kod** z uprawnieniami **do odczytu** i **wykonania** (bez możliwości zapisu)**.** Wspólne sekcje tego segmentu:
* `__text`: Skompilowany kod binarny
* `__const`: Dane stałe
* `__cstring`: Stałe ciągi znaków
* `__stubs` i `__stubs_helper`: Zaangażowane podczas procesu dynamicznego ładowania bibliotek
* **`__DATA`**: Zawiera dane, które są **do odczytu** i **zapisu** (bez możliwości wykonania)**.**
* `__data`: Zmienne globalne (które zostały zainicjowane)
* `__bss`: Zmienne statyczne (które nie zostały zainicjowane)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, itp.): Informacje używane przez środowisko uruchomieniowe Objective-C
* **`__LINKEDIT`**: Zawiera informacje dla linkera (dyld), takie jak "wpisy do tabeli symboli, ciągów i relokacji."
* **`__OBJC`**: Zawiera informacje używane przez środowisko uruchomieniowe Objective-C. Chociaż te informacje mogą być również znalezione w segmencie \_\_DATA, w różnych sekcjach \_\_objc\_\*.

### **`LC_MAIN`**

Zawiera punkt wejścia w atrybucie **entryoff**. Podczas ładowania, **dyld** po prostu **dodaje** tę wartość do (w pamięci) **bazowego adresu binarnego**, a następnie **przechodzi** do tej instrukcji, aby rozpocząć wykonywanie kodu binarnego.

### **LC\_CODE\_SIGNATURE**

Zawiera informacje o **podpisie kodu pliku Mach-O**. Zawiera tylko **przesunięcie**, które **wskazuje** na **blok podpisu**. Zazwyczaj znajduje się to na samym końcu pliku.\
Jednak informacje o tej sekcji można znaleźć w [**tym wpisie na blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) oraz w tym [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Zawiera **ścieżkę do dynamicznego łącznika wykonywalnego**, który mapuje współdzielone biblioteki do przestrzeni adresowej procesu. **Wartość zawsze jest ustawiona na `/usr/lib/dyld`**. Warto zauważyć, że w macOS mapowanie dylibów odbywa się w **trybie użytkownika**, a nie w trybie jądra.

### **`LC_LOAD_DYLIB`**

Ta komenda ładowania opisuje zależność od **dynamicznej** **biblioteki**, która **instruuje** **ładowacz** (dyld) do **załadowania i połączenia tej biblioteki**. Istnieje komenda ładowania LC\_LOAD\_DYLIB **dla każdej biblioteki**, którą wymaga plik Mach-O.

* Ta komenda ładowania jest strukturą typu **`dylib_command`** (która zawiera strukturę dylib, opisującą rzeczywistą zależną dynamiczną bibliotekę):
```
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
Możesz również uzyskać te informacje za pomocą wiersza poleceń:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Potencjalne biblioteki związane z złośliwym oprogramowaniem to:

- **DiskArbitration**: Monitorowanie dysków USB
- **AVFoundation:** Przechwytywanie dźwięku i obrazu
- **CoreWLAN**: Skanowanie sieci Wifi.

{% hint style="info" %}
Binarny Mach-O może zawierać jeden lub **więcej konstruktorów**, które zostaną **wykonane przed** adresem określonym w **LC\_MAIN**.\
Przesunięcia dowolnych konstruktorów są przechowywane w sekcji **\_\_mod\_init\_func** segmentu **\_\_DATA\_CONST**.
{% endhint %}

## **Dane Mach-O**

W centrum pliku znajduje się region danych, który składa się z kilku segmentów zdefiniowanych w regionie poleceń ładowania. **W każdym segmencie może być umieszczonych wiele sekcji danych**, z każdą sekcją **zawierającą kod lub dane** specyficzne dla danego typu.

{% hint style="success" %}
Dane to w zasadzie część zawierająca **wszystkie informacje**, które są ładowane przez polecenia ładowania **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Obejmuje to:

- **Tabela funkcji:** Która zawiera informacje o funkcjach programu.
- **Tabela symboli**: Która zawiera informacje o zewnętrznych funkcjach używanych przez binarny plik
- Może również zawierać wewnętrzne funkcje, nazwy zmiennych i inne.

Aby to sprawdzić, można skorzystać z narzędzia [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Lub z wiersza poleceń:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
