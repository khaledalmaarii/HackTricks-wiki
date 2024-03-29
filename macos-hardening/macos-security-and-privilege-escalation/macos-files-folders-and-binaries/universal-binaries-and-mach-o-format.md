# macOS Universal binaries & Mach-O Format

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Binaries za Mac OS kawaida hukusanywa kama **universal binaries**. **Universal binary** inaweza **kusaidia miundo mingi ya kompyuta ndani ya faili moja**.

Binaries hizi zinafuata **muundo wa Mach-O** ambao kimsingi una:

* Kichwa (Header)
* Amri za Upakiaji (Load Commands)
* Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

## Kichwa cha Mafuta (Fat Header)

Tafuta faili kwa: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* idadi ya miundo inayofuata */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* maelezo ya kompyuta (int) */
cpu_subtype_t	cpusubtype;	/* maelezo ya mashine (int) */
uint32_t	offset;		/* ofseti ya faili hadi faili hii ya kitu */
uint32_t	size;		/* ukubwa wa faili hii ya kitu */
uint32_t	align;		/* mlinganisho kama nishati ya 2 */
};
</code></pre>

Kichwa kina **herufi za uchawi** zifuatiwazo na **idadi** ya **miundo** ambayo faili **ina** (`nfat_arch`) na kila muundo utakuwa na muundo wa `fat_arch`.

Angalia na:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (kwa muundo wa x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (kwa muundo wa arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Vichwa vya Mafuta
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>muundo wa x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
uwezo 0x0
<strong>    ofseti 16384
</strong><strong>    ukubwa 72896
</strong>    mlinganisho 2^14 (16384)
<strong>muundo wa arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
uwezo PTR_AUTH_VERSION USERSPACE 0
<strong>    ofseti 98304
</strong><strong>    ukubwa 88816
</strong>    mlinganisho 2^14 (16384)
</code></pre>

au kutumia zana ya [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Kama unavyoweza kufikiria kawaida binary ya universal iliyokusanywa kwa miundo 2 **inazidisha ukubwa** wa ile iliyokusanywa kwa muundo mmoja tu.

## **Kichwa cha Mach-O**

Kichwa kina taarifa msingi kuhusu faili, kama herufi za uchawi kutambua kama faili ni ya Mach-O na taarifa kuhusu muundo wa kompyuta lengwa. Unaweza kuipata kwa: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Aina za Faili**:

* MH\_EXECUTE (0x2): Mchakato wa kawaida wa Mach-O
* MH\_DYLIB (0x6): Maktaba ya Mach-O inayoweza kuhusishwa kwa njia ya moja kwa moja (yaani .dylib)
* MH\_BUNDLE (0x8): Pakiti ya Mach-O (yaani .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Au kutumia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Amri za Kupakia Mach-O**

**Muundo wa faili akilini** umeelezwa hapa, ukielezea **eneo la jedwali la alama**, muktadha wa mnyororo mkuu wakati wa kuanza utekelezaji, na **maktaba zinazoshirikiwa** zinazohitajika. Maelekezo hutolewa kwa mzigo wa kudumu **(dyld)** kuhusu mchakato wa kupakia wa binary akilini.

Inatumia muundo wa **load\_command**, ulioainishwa katika **`loader.h`** iliyotajwa:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Kuna aina karibu **50 tofauti za amri za mzigo** ambazo mfumo unashughulikia tofauti. Zile za kawaida zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Kimsingi, aina hii ya Amri ya Mzigo inaainisha **jinsi ya kupakia \_\_TEXT** (msimbo wa kutekelezeka) **na \_\_DATA** (data kwa ajili ya mchakato) **vipande** kulingana na **makadirio yaliyoonyeshwa katika sehemu ya Data** wakati faili inatekelezwa.
{% endhint %}

Amri hizi **inaainisha vipande** ambavyo **vinahaririwa** katika **nafasi ya kumbukumbu ya kumbukumbu** ya mchakato unapotekelezwa.

Kuna **aina tofauti** za vipande, kama vile vipande vya **\_\_TEXT**, ambavyo vinashikilia msimbo wa kutekelezeka wa programu, na vipande vya **\_\_DATA**, ambavyo vinajumuisha data inayotumiwa na mchakato. Vipande hivi **vipo katika sehemu ya data** ya faili ya Mach-O.

**Kila kipande** kinaweza kugawanywa zaidi katika **sehemu nyingi**. Muundo wa **amri ya mzigo** una **maelezo** kuhusu **sehemu hizi** ndani ya kipande husika.

Kichwa kinaanza na **kichwa cha kipande**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* kwa usanifu wa 64-bit */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* inajumuisha ukubwa wa miundo ya section_64 */
char		segname[16];	/* jina la kipande */
uint64_t	vmaddr;		/* anwani ya kumbukumbu ya kipande hiki */
uint64_t	vmsize;		/* ukubwa wa kumbukumbu ya kipande hiki */
uint64_t	fileoff;	/* ofseti ya faili ya kipande hiki */
uint64_t	filesize;	/* kiasi cha ramani kutoka faili */
int32_t		maxprot;	/* ulinzi mkubwa wa VM */
int32_t		initprot;	/* ulinzi wa awali wa VM */
<strong>	uint32_t	nsects;		/* idadi ya sehemu katika kipande */
</strong>	uint32_t	flags;		/* bendera */
};
</code></pre>

Mfano wa kichwa cha kipande:

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Kichwa hiki kinaainisha **idadi ya sehemu ambazo vichwa vyake vinatokea baada ya** hiyo:
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
Mfano wa **kichwa cha sehemu**:

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Ikiwa un **ongeza** **sehemu ya kichwa** (0x37DC) + **sehemu ya kichwa** ambapo **arch inaanza**, katika kesi hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Pia niwezekanavyo kupata **habari za vichwa** kutoka kwa **mstari wa amri** na:
```bash
otool -lv /bin/ls
```
Vidirisha vya kawaida vinavyopakiwa na hii cmd:

* **`__PAGEZERO`:** Inaagiza kernel **kufanya ramani** **anwani sifuri** ili isome, andikwe, au kutekelezwa. maxprot na minprot katika muundo huu hupewa thamani sifuri kuonyesha **hakuna haki za kusoma-andika-tekeleza kwenye ukurasa huu**.
* Ugawaji huu ni muhimu kwa kuzuia **udhaifu wa dereference wa pointa za NULL**.
* **`__TEXT`**: Ina **mimbo inayoweza kutekelezwa** na **ruhusa za kusoma** na **kutekeleza** (siyo andikwa)**.** Sehemu za kawaida za kipande hiki:
* `__text`: Msimbo wa binary uliokompiliwa
* `__const`: Data ya kudumu
* `__cstring`: Vigezo vya herufi
* `__stubs` na `__stubs_helper`: Husika wakati wa mchakato wa kupakia maktaba za kudumu
* **`__DATA`**: Ina data inayoweza **kusomwa** na **kuandikwa** (siyo kutekelezwa)**.**
* `__data`: Vigezo vya kimataifa (ambavyo vimeanzishwa)
* `__bss`: Vigezo vya statiki (ambavyo havijaanzishwa)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, nk): Taarifa zinazotumiwa na runtime ya Objective-C
* **`__LINKEDIT`**: Ina taarifa kwa linker (dyld) kama vile, "alama, herufi, na meza za uhamishaji."
* **`__OBJC`**: Ina taarifa zinazotumiwa na runtime ya Objective-C. Ingawa taarifa hii inaweza kupatikana pia kwenye kipande cha \_\_DATA, ndani ya sehemu mbalimbali za \_\_objc\_\*.

### **`LC_MAIN`**

Inaingiza sehemu ya kuingia katika **sifa ya kuingia.** Wakati wa kupakia, **dyld** tu **inaongeza** thamani hii kwenye (kumbukumbu) **msingi wa binary**, kisha **inaruka** kwenye maagizo haya kuanza utekelezaji wa msimbo wa binary.

### **LC\_CODE\_SIGNATURE**

Ina taarifa kuhusu **sahihi ya msimbo wa faili ya Macho-O**. Ina **kielekezi** kinachopata **bloki ya sahihi**. Kawaida hii iko mwishoni mwa faili.\
Hata hivyo, unaweza kupata baadhi ya taarifa kuhusu sehemu hii katika [**chapisho hili la blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na hii [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Ina **njia ya kielekezi ya kutekelezwa kwa kudhibiti** ambayo inarami maktaba za kudumu kwenye nafasi ya anwani ya mchakato. **Thamani daima inawekwa kwa `/usr/lib/dyld`**. Ni muhimu kutambua kwamba katika macOS, ramani ya dylib hufanyika katika **hali ya mtumiaji**, siyo katika hali ya kernel.

### **`LC_LOAD_DYLIB`**

Agizo hili la kupakia linataja **tegemezi la maktaba ya kudumu** ambayo **inaagiza** **mpakiaji** (dyld) **kupakia na kuunganisha maktaba hiyo**. Kuna agizo la kupakia LC\_LOAD\_DYLIB **kwa kila maktaba** ambayo binary ya Mach-O inahitaji.

* Agizo hili la kupakia ni muundo wa aina ya **`dylib_command`** (ambayo ina muundo wa dylib, ukielezea maktaba ya kudumu inayotegemea):
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

Ungepata habari hii pia kutoka kwa cli kwa:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Baadhi ya maktaba zinazoweza kuwa na uhusiano na programu hasidi ni:

- **DiskArbitration**: Kufuatilia diski za USB
- **AVFoundation**: Kukamata sauti na video
- **CoreWLAN**: Uchunguzi wa Wifi.

{% hint style="info" %}
Binary ya Mach-O inaweza kuwa na moja au **zaidi** ya **wajenzi**, ambao watakuwa **wakitekelezwa** **kabla** ya anwani iliyotajwa katika **LC\_MAIN**.\
Vidokezo vya wajenzi wowote vinashikiliwa katika sehemu ya **\_\_mod\_init\_func** ya segimenti ya **\_\_DATA\_CONST**.
{% endhint %}

## **Data ya Mach-O**

Katikati ya faili kuna eneo la data, ambalo linaundwa na sehemu kadhaa kama ilivyoelezwa katika eneo la amri za kupakia. **Aina mbalimbali za sehemu za data zinaweza kuhifadhiwa ndani ya kila segimenti**, na kila sehemu **ikishikilia kanuni au data** maalum kwa aina fulani.

{% hint style="success" %}
Data ni sehemu inayoshikilia **habari zote** ambazo zinapakiwa na amri za kupakia **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Hii ni pamoja na:

- **Jedwali la Kazi:** Ambalo linashikilia habari kuhusu kazi za programu.
- **Jedwali la Alama**: Linaloleta habari kuhusu kazi za nje zinazotumiwa na binary
- Pia inaweza kuwa na kazi za ndani, majina ya vitu, na zaidi.

Kuichunguza unaweza kutumia zana ya [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Au kutoka kwa cli:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
