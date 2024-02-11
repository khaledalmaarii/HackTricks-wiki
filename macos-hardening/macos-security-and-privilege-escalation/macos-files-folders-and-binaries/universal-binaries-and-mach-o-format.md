# macOS Universele bineêre en Mach-O-formaat

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

Mac OS-bineêre lêers word gewoonlik saamgestel as **universele bineêre lêers**. 'n **Universele bineêre lêer** kan **ondersteuning bied vir verskeie argitekture in dieselfde lêer**.

Hierdie bineêre lêers volg die **Mach-O-struktuur**, wat basies bestaan uit:

* Kop
* Laai-opdragte
* Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

## Vetkop

Soek na die lêer met: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* aantal structs wat volg */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu-spesifiseerder (int) */
cpu_subtype_t	cpusubtype;	/* masjien-spesifiseerder (int) */
uint32_t	offset;		/* lêeroffset na hierdie objeklêer */
uint32_t	size;		/* grootte van hierdie objeklêer */
uint32_t	align;		/* uitlyning as 'n mag van 2 */
};
</code></pre>

Die kop het die **magic**-byte gevolg deur die **aantal** **argitekture** wat die lêer **bevat** (`nfat_arch`) en elke argitektuur sal 'n `fat_arch`-struktuur hê.

Kyk daarna met:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universele bineêre lêer met 2 argitekture: [x86_64:Mach-O 64-bit uitvoerbare x86_64] [arm64e:Mach-O 64-bit uitvoerbare arm64e]
/bin/ls (vir argitektuur x86_64):	Mach-O 64-bit uitvoerbare x86_64
/bin/ls (vir argitektuur arm64e):	Mach-O 64-bit uitvoerbare arm64e

% otool -f -v /bin/ls
Fat-koppe
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>argitektuur x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
vermoëns 0x0
<strong>    offset 16384
</strong><strong>    grootte 72896
</strong>    uitlyning 2^14 (16384)
<strong>argitektuur arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
vermoëns PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    grootte 88816
</strong>    uitlyning 2^14 (16384)
</code></pre>

of deur die [Mach-O View](https://sourceforge.net/projects/machoview/) hulpmiddel te gebruik:

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Soos jy dalk dink, verdubbel 'n universele bineêre lêer wat vir 2 argitekture saamgestel is, gewoonlik die grootte van een wat slegs vir 1 argitektuur saamgestel is.

## **Mach-O Kop**

Die kop bevat basiese inligting oor die lêer, soos magiese byte om dit as 'n Mach-O-lêer te identifiseer en inligting oor die teikenargitektuur. Jy kan dit vind in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Lêertipes**:

* MH\_EXECUTE (0x2): Standaard Mach-O uitvoerbare lêer
* MH\_DYLIB (0x6): 'n Mach-O dinamiese gekoppelde biblioteek (d.w.s. .dylib)
* MH\_BUNDLE (0x8): 'n Mach-O bundel (d.w.s. .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Of deur [Mach-O View](https://sourceforge.net/projects/machoview/) te gebruik:

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Laai-opdragte**

Die **lêer se uitleg in geheue** word hier gespesifiseer, waar die **simbooltabel se ligging**, die konteks van die hoofdraad by uitvoering begin, en die vereiste **gedeelde biblioteke** beskryf word. Instruksies word aan die dinamiese laaier **(dyld)** verskaf oor die proses van die binêre lading in geheue.

Dit maak gebruik van die **load\_command** struktuur, wat gedefinieer is in die genoemde **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Daar is ongeveer **50 verskillende tipes laai-opdragte** wat die stelsel verskillend hanteer. Die mees algemene is: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, en `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Basies definieer hierdie tipe Laai-opdrag hoe om die \_\_TEXT (uitvoerbare kode) en \_\_DATA (data vir die proses) segmente te laai volgens die verskuiwings wat in die Data-afdeling aangedui word wanneer die binêre lêer uitgevoer word.
{% endhint %}

Hierdie opdragte definieer segmente wat in die virtuele geheue-ruimte van 'n proses gekaart word wanneer dit uitgevoer word.

Daar is verskillende tipes segmente, soos die \_\_TEXT-segment wat die uitvoerbare kode van 'n program bevat, en die \_\_DATA-segment wat data bevat wat deur die proses gebruik word. Hierdie segmente is geleë in die data-afdeling van die Mach-O-lêer.

**Elke segment** kan verder verdeel word in verskeie **seksies**. Die laai-opdragstruktuur bevat inligting oor hierdie seksies binne die betrokke segment.

In die kop vind jy eers die **segmentkop**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* vir 64-bis-argitekture */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* sluit sizeof section_64-strukture in */
char		segname[16];	/* segmentnaam */
uint64_t	vmaddr;		/* geheue-adres van hierdie segment */
uint64_t	vmsize;		/* geheuegrootte van hierdie segment */
uint64_t	fileoff;	/* lêer-verskuiwing van hierdie segment */
uint64_t	filesize;	/* hoeveelheid om van die lêer af te kaart */
int32_t		maxprot;	/* maksimum VM-beskerming */
int32_t		initprot;	/* aanvanklike VM-beskerming */
<strong>	uint32_t	nsects;		/* aantal seksies in segment */
</strong>	uint32_t	flags;		/* vlae */
};
</code></pre>

Voorbeeld van 'n segmentkop:

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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
Voorbeeld van **seksie kop**:

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

As jy die **seksie offset** (0x37DC) byvoeg by die **offset** waar die **argitektuur begin**, in hierdie geval `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Dit is ook moontlik om **koppe-inligting** vanaf die **opdraglyn** te kry met:
```bash
otool -lv /bin/ls
```
Gemeenskaplike segmente gelaai deur hierdie opdrag:

* **`__PAGEZERO`:** Dit instrueer die kernel om die **adres nul** te **kaart** sodat dit **nie gelees, geskryf of uitgevoer kan word nie**. Die maxprot en minprot veranderlikes in die struktuur word op nul gestel om aan te dui dat daar **geen lees-skryf-uitvoerregte op hierdie bladsy is nie**.
* Hierdie toewysing is belangrik om **NULL-aanwyservolgordekwesbaarhede te verminder**.
* **`__TEXT`**: Bevat **uitvoerbare** **kode** met **lees** en **uitvoer** regte (nie skryfbaar)**.** Gemeenskaplike afdelings van hierdie segment:
* `__text`: Opgestelde binêre kode
* `__const`: Konstante data
* `__cstring`: String konstante
* `__stubs` en `__stubs_helper`: Betrokke tydens die dinamiese biblioteeklaaiproses
* **`__DATA`**: Bevat data wat **leesbaar** en **skryfbaar** is (nie uitvoerbaar)**.**
* `__data`: Globale veranderlikes (wat geïnisialiseer is)
* `__bss`: Statische veranderlikes (wat nie geïnisialiseer is nie)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, ens.): Inligting wat deur die Objective-C runtime gebruik word
* **`__LINKEDIT`**: Bevat inligting vir die linker (dyld) soos "simbool-, string- en herlokasietabelinskrywings".
* **`__OBJC`**: Bevat inligting wat deur die Objective-C runtime gebruik word. Hierdie inligting kan egter ook in die \_\_DATA-segment gevind word, binne verskillende \_\_objc\_\*-afdelings.

### **`LC_MAIN`**

Bevat die ingangspunt in die **entryoff-eienskap**. By laai-tyd **voeg dyld** eenvoudig hierdie waarde by die (in-memory) **basis van die binêre**, en **spring** dan na hierdie instruksie om die uitvoering van die binêre se kode te begin.

### **LC\_CODE\_SIGNATURE**

Bevat inligting oor die **kodesignatuur van die Macho-O-lêer**. Dit bevat slegs 'n **verskuiwing** wat na die **handtekeningblob** wys. Dit is tipies aan die einde van die lêer.\
U kan egter enkele inligting oor hierdie afdeling vind in [**hierdie blogpos**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) en hierdie [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Bevat die **pad na die dinamiese skakeluitvoerder** wat gedeelde biblioteke in die prosesadresruimte in kaart bring. Die **waarde is altyd ingestel op `/usr/lib/dyld`**. Dit is belangrik om daarop te let dat in macOS, dylib-kartering in **gebruikersmodus** plaasvind, nie in kernelmodus nie.

### **`LC_LOAD_DYLIB`**

Hierdie laaibedeling beskryf 'n **dinamiese** **biblioteek-afhanklikheid** wat die **laaier** (dyld) instrueer om genoemde biblioteek te **laai en te skakel**. Daar is 'n LC\_LOAD\_DYLIB laaibedeling **vir elke biblioteek** wat die Mach-O-binêre vereis.

* Hierdie laaibedeling is 'n struktuur van die tipe **`dylib_command`** (wat 'n struct dylib bevat wat die werklike afhanklike dinamiese biblioteek beskryf):
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
![](<../../../.gitbook/assets/image (558).png>)

Jy kan ook hierdie inligting kry vanaf die opdraglyn met:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Sommige potensiële kwaadwillige biblioteke is:

* **DiskArbitration**: Monitor USB-aandrywers
* **AVFoundation:** Neem klank en video op
* **CoreWLAN**: Wifi-skanderings.

{% hint style="info" %}
'n Mach-O binêre lêer kan een of **meer** **konstrukteurs** bevat wat **uitgevoer** sal word **voor** die adres wat in **LC\_MAIN** gespesifiseer is.\
Die verskuiwings van enige konstrukteurs word in die **\_\_mod\_init\_func**-afdeling van die **\_\_DATA\_CONST**-segment gehou.
{% endhint %}

## **Mach-O Data**

In die kern van die lêer lê die data-afdeling, wat bestaan uit verskeie segmente soos gedefinieer in die laai-opdragte-afdeling. **Verskeie data-afdelings kan binne elke segment gehuisves word**, met elke afdeling wat kode of data bevat wat spesifiek is vir 'n tipe.

{% hint style="success" %}
Die data is basies die gedeelte wat al die **inligting** bevat wat deur die laai-opdragte **LC\_SEGMENTS\_64** gelaai word.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Dit sluit in:

* **Funksietabel:** Wat inligting oor die programfunksies bevat.
* **Simbooltabel**: Wat inligting bevat oor die eksterne funksie wat deur die binêre gebruik word
* Dit kan ook interne funksie, veranderlike name en meer bevat.

Om dit te kontroleer, kan jy die [**Mach-O View**](https://sourceforge.net/projects/machoview/) hulpmiddel gebruik:

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Of vanaf die opdraglyn:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
