# macOS Universele bineêre & Mach-O-formaat

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Basiese Inligting

Mac OS-bineêre lêers is gewoonlik saamgestel as **universele bineêre lêers**. 'n **Universele bineêre lêer** kan **verskeie argitekture in dieselfde lêer ondersteun**.

Hierdie bineêre lêers volg die **Mach-O-struktuur** wat basies bestaan uit:

* Kop
* Laai-opdragte
* Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Vet Kop

Soek na die lêer met: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* aantal strukture wat volg */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu spesifiseerder (int) */
cpu_subtype_t	cpusubtype;	/* masjien spesifiseerder (int) */
uint32_t	offset;		/* lêer-offset na hierdie objeklêer */
uint32_t	size;		/* grootte van hierdie objeklêer */
uint32_t	align;		/* uitlyn as 'n mag van 2 */
};
</code></pre>

Die kop het die **magic**-byte gevolg deur die **aantal** **argitekture** wat die lêer **bevat** (`nfat_arch`) en elke argitektuur sal 'n `fat_arch` struktuur hê.

Kontroleer dit met:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universele bineêre met 2 argitekture: [x86_64:Mach-O 64-bietjie uitvoerbare x86_64] [arm64e:Mach-O 64-bietjie uitvoerbare arm64e]
/bin/ls (vir argitektuur x86_64):	Mach-O 64-bietjie uitvoerbare x86_64
/bin/ls (vir argitektuur arm64e):	Mach-O 64-bietjie uitvoerbare arm64e

% otool -f -v /bin/ls
Vet koppe
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>argitektuur x86_64
</strong>    cputipe CPU_TYPE_X86_64
cpusubtipe CPU_SUBTYPE_X86_64_ALL
vermoëns 0x0
<strong>    offset 16384
</strong><strong>    grootte 72896
</strong>    uitlyn 2^14 (16384)
<strong>argitektuur arm64e
</strong>    cputipe CPU_TYPE_ARM64
cpusubtipe CPU_SUBTYPE_ARM64E
vermoëns PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    grootte 88816
</strong>    uitlyn 2^14 (16384)
</code></pre>

of deur die [Mach-O View](https://sourceforge.net/projects/machoview/) gereedskap te gebruik:

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk dink, verdubbel 'n universele bineêre wat vir 2 argitekture saamgestel is die grootte van een wat net vir 1 argitektuur saamgestel is.

## **Mach-O Kop**

Die kop bevat basiese inligting oor die lêer, soos die magiese byte om dit as 'n Mach-O-lêer te identifiseer en inligting oor die teikenargitektuur. Jy kan dit vind in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O Lêertipes

Daar is verskillende lêertipes, jy kan hulle gedefinieer vind in die [**bronkode byvoorbeeld hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Die belangrikste is:

- `MH_OBJECT`: Herplaasbare objeklêer (tussenproduk van samestelling, nog nie uitvoerbare lêers nie).
- `MH_EXECUTE`: Uitvoerbare lêers.
- `MH_FVMLIB`: Vasgehegte VM-biblioteeklêer.
- `MH_CORE`: Kode-afsettings
- `MH_PRELOAD`: Voorafgelaai uitvoerbare lêer (nie meer ondersteun in XNU nie)
- `MH_DYLIB`: Dinamiese Biblioteke
- `MH_DYLINKER`: Dinamiese Skakelaar
- `MH_BUNDLE`: "Inprop-lêers". Opgestel deur -bundle in gcc en eksplisiet gelaai deur `NSBundle` of `dlopen`.
- `MH_DYSM`: Metgesel `.dSym` lêer (lêer met simbole vir foutopsporing).
- `MH_KEXT_BUNDLE`: Kernel-uitbreidings.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Of deur [Mach-O View](https://sourceforge.net/projects/machoview/) te gebruik:

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Vlae**

Die bronkode definieer ook verskeie vlae wat nuttig is vir die laai van biblioteke:

* `MH_NOUNDEFS`: Geen ongedefinieerde verwysings (volledig gekoppel)
* `MH_DYLDLINK`: Dyld koppeling
* `MH_PREBOUND`: Dinamiese verwysings vooraf gebind.
* `MH_SPLIT_SEGS`: Lêer verdeel r/o en r/w segmente.
* `MH_WEAK_DEFINES`: Binêre het swak gedefinieerde simbole
* `MH_BINDS_TO_WEAK`: Binêre gebruik swak simbole
* `MH_ALLOW_STACK_EXECUTION`: Maak die stapel uitvoerbaar
* `MH_NO_REEXPORTED_DYLIBS`: Biblioteek nie LC\_REEXPORT-opdragte nie
* `MH_PIE`: Posisioneel Onafhanklike Uitvoerbare lêer
* `MH_HAS_TLV_DESCRIPTORS`: Daar is 'n afdeling met draadlokale veranderlikes
* `MH_NO_HEAP_EXECUTION`: Geen uitvoering vir heap/data-bladsye
* `MH_HAS_OBJC`: Binêre het oBject-C afdelings
* `MH_SIM_SUPPORT`: Simulator-ondersteuning
* `MH_DYLIB_IN_CACHE`: Gebruik op dylibs/frameworks in gedeelde biblioteekkas.

## **Mach-O Laai-opdragte**

Die **lêer se uitleg in geheue** word hier gespesifiseer, met inligting oor die **simbooltabel se ligging**, die konteks van die hoofdraad by uitvoerbegin, en die vereiste **gedeelde biblioteke**. Instruksies word aan die dinamiese laaier **(dyld)** verskaf oor die binêre se laaiproses in geheue.

Dit maak gebruik van die **load\_command** struktuur, gedefinieer in die genoemde **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Daar is ongeveer **50 verskillende tipes laai-opdragte** wat die stelsel anders hanteer. Die mees algemene is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, en `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Basies definieer hierdie tipe Laai-opdrag **hoe om die \_\_TEXT** (uitvoerbare kode) **en \_\_DATA** (data vir die proses) **segmente te laai** volgens die **offsets aangedui in die Data-seksie** wanneer die binêre lêer uitgevoer word.
{% endhint %}

Hierdie opdragte **definieer segmente** wat in die **virtuele geheue-ruimte** van 'n proses ingevoeg word wanneer dit uitgevoer word.

Daar is **verskillende tipes** segmente, soos die **\_\_TEXT** segment, wat die uitvoerbare kode van 'n program bevat, en die **\_\_DATA** segment, wat data bevat wat deur die proses gebruik word. Hierdie **segmente is geleë in die data-seksie** van die Mach-O lêer.

**Elke segment** kan verder verdeel word in verskeie **seksies**. Die **laai-opdragstruktuur** bevat **inligting** oor **hierdie seksies** binne die betrokke segment.

In die kop vind jy die **segmentkop**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* vir 64-bis-argitekture */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* sluit die grootte van section_64 strukture in */
char		segname[16];	/* segmentnaam */
uint64_t	vmaddr;		/* geheue-adres van hierdie segment */
uint64_t	vmsize;		/* geheuegrootte van hierdie segment */
uint64_t	fileoff;	/* lêer-offset van hierdie segment */
uint64_t	filesize;	/* hoeveelheid om van die lêer af te beeld */
int32_t		maxprot;	/* maksimum VM-beskerming */
int32_t		initprot;	/* aanvanklike VM-beskerming */
<strong>	uint32_t	nsects;		/* aantal seksies in segment */
</strong>	uint32_t	flags;		/* vlae */
};
</code></pre>

Voorbeeld van segmentkop:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Hierdie kop definieer die **aantal seksies waarvan die koppe daarna verskyn**:
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
Voorbeeld van **seksie-kop**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

As jy die **seksie-offset** (0x37DC) + die **offset** waar die **arg begin**, in hierdie geval `0x18000` byvoeg --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **koppe-inligting** van die **opdraglyn** te kry met:
```bash
otool -lv /bin/ls
```
Gemeenskaplike segmente wat deur hierdie cmd gelaai word:

* **`__PAGEZERO`:** Dit instrueer die kernel om die **adres nul** te **kaart** sodat dit **nie gelees, geskryf of uitgevoer kan word nie**. Die maxprot en minprot veranderlikes in die struktuur word na nul ingestel om aan te dui dat daar **geen lees-skuif-uitvoer regte op hierdie bladsy** is nie.
* Hierdie toewysing is belangrik om **NULL-aanwyservulnerabiliteite te verminder**. Dit is omdat XNU 'n harde bladsy nul afdwing wat verseker dat die eerste bladsy (slegs die eerste) van geheue onbereikbaar is (behalwe in i386). 'n Binêre kan aan hierdie vereistes voldoen deur 'n klein \_\_PAGEZERO (met die `-pagezero_size`) te skep om die eerste 4k te dek en die res van die 32-bis geheue toeganklik te hê in beide gebruiker- en kernelmodus.
* **`__TEXT`**: Bevat **uitvoerbare** **kode** met **lees** en **uitvoer** regte (nie skryfbare)**.** Gewone afdelings van hierdie segment:
* `__text`: Opgestelde binêre kode
* `__const`: Konstante data (slegs leesbaar)
* `__[c/u/os_log]string`: C, Unicode of os-logstring konstantes
* `__stubs` en `__stubs_helper`: Betrokke tydens die dinamiese biblioteeklaaiproses
* `__unwind_info`: Stok ontwar data.
* Let daarop dat al hierdie inhoud onderteken is maar ook as uitvoerbaar gemerk is (skep meer opsies vir uitbuiting van afdelings wat nie noodwendig hierdie voorreg nodig het nie, soos string-toegewyde afdelings).
* **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (nie uitvoerbaar)**.**
* `__got:` Globale Verskuiwingstabel
* `__nl_symbol_ptr`: Nie lui (bind by laai) simboolaanduider
* `__la_symbol_ptr`: Lui (bind by gebruik) simboolaanduider
* `__const`: Behoort lees-slegs data te wees (nie regtig)
* `__cfstring`: CoreFoundation strings
* `__data`: Globale veranderlikes (wat geïnisialiseer is)
* `__bss`: Statiese veranderlikes (wat nie geïnisialiseer is nie)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, ens.): Inligting wat deur die Objective-C-uitvoertyd gebruik word
* **`__DATA_CONST`**: \_\_DATA.\_\_const is nie gewaarborg om konstant te wees (skryfregte nie), en ook nie ander aanwysers en die GOT nie. Hierdie afdeling maak `__const`, sommige inisialiseerders en die GOT-tabel (eenmaal opgelos) **leesbaar slegs** deur `mprotect` te gebruik.
* **`__LINKEDIT`**: Bevat inligting vir die koppelaar (dyld) soos simbool-, string- en herlokasie-tabelinskrywings. Dit is 'n generiese houer vir inhoud wat nie in `__TEXT` of `__DATA` is nie en sy inhoud word in ander laaibefehle beskryf.
* dyld-inligting: Herbasis, Nie-luie/lui/swak bindopkode en uitvoer inligting
* Funksies begin: Tabel van beginadresse van funksies
* Data In Kode: Data-eilande in \_\_text
* Simbooltabel: Simbole in binêr
* Indirekte Simbooltabel: Aanduider/stub simbole
* Stringtabel
* Kodehandtekening
* **`__OBJC`**: Bevat inligting wat deur die Objective-C-uitvoertyd gebruik word. Alhoewel hierdie inligting ook in die \_\_DATA-segment gevind kan word, binne verskeie in \_\_objc\_\* afdelings.
* **`__RESTRICT`**: 'n Segment sonder inhoud met 'n enkele afdeling genaamd **`__restrict`** (ook leeg) wat verseker dat wanneer die binêre lopende is, dit DYLD-omgewingsveranderlikes ignoreer.

Soos in die kode gesien kon word, **ondersteun segmente ook vlae** (al word hulle nie baie gebruik nie):

* `SG_HIGHVM`: Slegs kern (nie gebruik nie)
* `SG_FVMLIB`: Nie gebruik nie
* `SG_NORELOC`: Segment het geen herlokasie
* `SG_PROTECTED_VERSION_1`: Versleuteling. Gebruik byvoorbeeld deur Finder om teks in `__TEXT`-segment te versleutel.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** bevat die ingangspunt in die **entryoff-eienskap.** Met laai-tyd voeg **dyld** eenvoudig hierdie waarde by die (in-geheue) **basis van die binêre**, spring dan na hierdie instruksie om die uitvoering van die binêre se kode te begin.

**`LC_UNIXTHREAD`** bevat die waardes wat die register moet hê wanneer die hoofdraad begin. Dit is reeds verouderd maar **`dyld`** gebruik dit nog steeds. Dit is moontlik om die waardes van die register wat deur hierdie ingestel is, te sien met:
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

Bevat inligting oor die **kodesignatuur van die Macho-O-lêer**. Dit bevat slegs 'n **offset** wat na die **handtekeningblob** wys. Dit is tipies aan die einde van die lêer.\
Jy kan egter inligting oor hierdie afdeling vind in [**hierdie blogpos**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en hierdie [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Ondersteuning vir binêre versleuteling. Indien 'n aanvaller egter die proses kan kompromiteer, sal hy die geheue onversleuteld kan aflaai.

### **`LC_LOAD_DYLINKER`**

Bevat die **pad na die dinamiese skakeluitvoerbare lêer** wat gedeelde biblioteke in die proses-adresruimte in kaart bring. Die **waarde is altyd ingestel op `/usr/lib/dyld`**. Dit is belangrik om daarop te let dat in macOS, dylib-afbeelding in **gebruikermodus** plaasvind, nie in kernelmodus nie.

### **`LC_IDENT`**

Verouderd, maar wanneer dit ingestel is om damps by paniek te genereer, word 'n Mach-O-kern-damp geskep en die kernweergawe word in die `LC_IDENT`-bevel ingestel.

### **`LC_UUID`**

Willekeurige UUID. Dit is nie direk nuttig vir enigiets nie, maar XNU stoor dit saam met die res van die prosesinligting. Dit kan in botsingsverslae gebruik word.

### **`LC_DYLD_ENVIRONMENT`**

Laat toe om omgewingsveranderlikes aan die dyld aan te dui voordat die proses uitgevoer word. Dit kan baie gevaarlik wees omdat dit kan toelaat om arbitrêre kode binne die proses uit te voer, dus word hierdie laai-bevel slegs gebruik in dyld-geboue met `#define SUPPORT_LC_DYLD_ENVIRONMENT` en beperk verdere verwerking slegs tot veranderlikes van die vorm `DYLD_..._PATH` wat laaipaaie spesifiseer.

### **`LC_LOAD_DYLIB`**

Hierdie laaibevolking beskryf 'n **dinamiese biblioteekafhanklikheid** wat die **laaier** (dyld) **instrueer om genoemde biblioteek te laai en te skakel**. Daar is 'n `LC_LOAD_DYLIB`-laaibevolking **vir elke biblioteek** wat die Mach-O-binêre lêer benodig.

* Hierdie laaibevolking is 'n struktuur van die tipe **`dylib_command`** (wat 'n struktuur dylib bevat wat die werklike afhanklike dinamiese biblioteek beskryf):
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

Jy kan ook hierdie inligting kry van die opdraggelynpunt met:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potensiële kwaadwillige biblioteke is:

* **DiskArbitration**: Monitering van USB-aandrywings
* **AVFoundation:** Vang klank en video
* **CoreWLAN**: Wifi-skanderings.

{% hint style="info" %}
'n Mach-O binêre lêer kan een of **meer konstrukteurs** bevat, wat **uitgevoer sal word voor** die adres gespesifiseer in **LC\_MAIN**.\
Die offsette van enige konstrukteurs word gehou in die **\_\_mod\_init\_func** afdeling van die **\_\_DATA\_CONST** segment.
{% endhint %}

## **Mach-O Data**

In die kern van die lêer lê die data-gebied, wat bestaan uit verskeie segmente soos gedefinieer in die laai-opdragte-gebied. **'n Verskeidenheid data-afdelings kan binne elke segment gehuisves word**, met elke afdeling wat kode of data bevat wat spesifiek is vir 'n tipe.

{% hint style="success" %}
Die data is basies die gedeelte wat al die **inligting** bevat wat deur die laai-opdragte **LC\_SEGMENTS\_64** gelaai word.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Dit sluit in:

* **Funksie-tabel:** Wat inligting oor die programfunksies bevat.
* **Simbooltabel**: Wat inligting oor die eksterne funksie bevat wat deur die binêre gebruik word
* Dit kan ook interne funksie, veranderlike name en meer bevat.

Om dit te kontroleer, kan jy die [**Mach-O View**](https://sourceforge.net/projects/machoview/) gereedskap gebruik:

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Of vanaf die opdraglyn:
```bash
size -m /bin/ls
```
## Objective-C Algemene Afdelings

In die `__TEXT` segment (r-x):

- `__objc_classname`: Klasname (strings)
- `__objc_methname`: Metode name (strings)
- `__objc_methtype`: Metode tipes (strings)

In die `__DATA` segment (rw-):

- `__objc_classlist`: Aanwysers na alle Objective-C klasse
- `__objc_nlclslist`: Aanwysers na Nie-Luie Objective-C klasse
- `__objc_catlist`: Aanwyser na Kategorieë
- `__objc_nlcatlist`: Aanwyser na Nie-Luie Kategorieë
- `__objc_protolist`: Protokolle lys
- `__objc_const`: Konstante data
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
