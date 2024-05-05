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

Faili za Mac OS kawaida hukusanywa kama **faili za kawaida**. **Faili ya kawaida** inaweza **kusaidia miundo mingi katika faili moja**.

Faili hizi zinafuata muundo wa **Mach-O** ambao kimsingi una:

* Kichwa
* Amri za Upakiaji
* Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Kichwa cha Mafuta

Tafuta faili na: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* idadi ya miundo inayofuata */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* maelezo ya cpu (int) */
cpu_subtype_t	cpusubtype;	/* maelezo ya mashine (int) */
uint32_t	offset;		/* ofisi ya faili hadi faili hii ya kitu */
uint32_t	size;		/* ukubwa wa faili hii ya kitu */
uint32_t	align;		/* mlinganisho kama nguvu ya 2 */
};
</code></pre>

Kichwa kina **baye za uchawi** zifuatazo na **idadi** ya **miundo** faili **ina** (`nfat_arch`) na kila muundo utakuwa na muundo wa `fat_arch`.

Angalia na:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O faili ya kawaida na miundo 2: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (kwa muundo x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (kwa muundo arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Vichwa vya mafuta
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>muundo x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
uwezo 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>muundo arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
uwezo PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

au kutumia zana ya [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Kama unavyoweza kufikiria kawaida faili ya kawaida iliyokusanywa kwa miundo 2 **inadouble ukubwa** wa ile iliyokusanywa kwa muundo 1 tu.

## **Kichwa cha Mach-O**

Kichwa kina taarifa msingi kuhusu faili, kama baye za uchawi kutambua kama faili ya Mach-O na taarifa kuhusu muundo wa lengo. Unaweza kuipata kwa: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Aina za Faili za Mach-O

Kuna aina tofauti za faili, unaweza kuzipata zimefafanuliwa katika [**mifano ya msimbo hapa kwa mfano**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Zile muhimu zaidi ni:

- `MH_OBJECT`: Faili ya kitu inayoweza kuhama (bidhaa za kati za uundaji, sio utekelezaji bado).
- `MH_EXECUTE`: Faili za utekelezaji.
- `MH_FVMLIB`: Faili ya maktaba ya VM iliyofungwa.
- `MH_CORE`: Dump za Msimbo
- `MH_PRELOAD`: Faili ya utekelezaji iliyopakiwa mapema (haisaidiwi tena katika XNU)
- `MH_DYLIB`: Maktaba za Kisasa
- `MH_DYLINKER`: Kiungo cha Kisasa
- `MH_BUNDLE`: "Faili za programu-jalizi". Zinazozalishwa kwa kutumia -bundle katika gcc na kupakiwa wazi na `NSBundle` au `dlopen`.
- `MH_DYSM`: Faili ya `.dSym` ya rafiki (faili na alama za kutatua mizozo).
- `MH_KEXT_BUNDLE`: Vifurushi vya Kerneli.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Au kutumia [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Alama**

Msimbo wa chanzo pia unatambua alama kadhaa zinazofaa kwa kupakia maktaba:

* `MH_NOUNDEFS`: Hakuna marejeo yasiyojulikana (imeunganishwa kabisa)
* `MH_DYLDLINK`: Uunganishaji wa Dyld
* `MH_PREBOUND`: Marejeo ya kudumu ya kudumu.
* `MH_SPLIT_SEGS`: Faili inagawanya segimenti za r/o na r/w.
* `MH_WEAK_DEFINES`: Baina ina alama zilizofafanuliwa kwa udhaifu
* `MH_BINDS_TO_WEAK`: Baina inatumia alama za udhaifu
* `MH_ALLOW_STACK_EXECUTION`: Fanya steki iweze kutekelezwa
* `MH_NO_REEXPORTED_DYLIBS`: Maktaba bila amri za LC\_REEXPORT
* `MH_PIE`: Kitekelezaji Kinachoweza Kuhamishika
* `MH_HAS_TLV_DESCRIPTORS`: Kuna sehemu na pembejeo za mnyororo wa watumiaji wa mada
* `MH_NO_HEAP_EXECUTION`: Hakuna utekelezaji kwa kurasa za kitalu/data
* `MH_HAS_OBJC`: Baina ina sehemu za oBject-C
* `MH_SIM_SUPPORT`: Msaada wa Simulator
* `MH_DYLIB_IN_CACHE`: Kutumika kwenye dylibs/frameworks katika hifadhi ya maktaba iliyoshirikiwa.

## **Amri za Upakiaji wa Mach-O**

**Mpangilio wa faili kwenye kumbukumbu** unatajwa hapa, ukielezea **eneo la jedwali la alama**, muktadha wa mnyororo mkuu mwanzoni mwa utekelezaji, na **maktaba zinazoshirikiwa** zinazohitajika. Maelekezo yanatolewa kwa mzigo wa kudumu **(dyld)** kuhusu mchakato wa kupakia wa binary kwenye kumbukumbu.

Inatumia muundo wa **load\_command**, uliotajwa katika **`loader.h`** iliyotajwa:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Kuna karibu **aina 50 tofauti za amri za mzigo** ambazo mfumo unashughulikia tofauti. Zile za kawaida zaidi ni: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, na `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Kimsingi, aina hii ya Amri ya Mzigo inaainisha **jinsi ya kupakia \_\_TEXT** (msimbo wa kutekelezeka) **na \_\_DATA** (data kwa ajili ya mchakato) **sehemu** kulingana na **makadirio yaliyoonyeshwa katika sehemu ya Data** wakati binary inatekelezwa.
{% endhint %}

Amri hizi **inaainisha sehemu** ambazo **zimepangwa** katika **nafasi ya kumbukumbu ya kielezo** ya mchakato unapotekelezwa.

Kuna **aina tofauti** za sehemu, kama vile sehemu ya **\_\_TEXT**, ambayo inashikilia msimbo wa kutekelezeka wa programu, na sehemu ya **\_\_DATA**, ambayo ina data inayotumiwa na mchakato. Hizi **sehemu zinapatikana katika sehemu ya data** ya faili ya Mach-O.

**Kila sehemu** inaweza kugawanywa zaidi katika **sehemu nyingi**. Muundo wa **amri ya mzigo** una **habari** kuhusu **sehemu hizi** ndani ya sehemu husika.

Kichwa kinaanza na **kichwa cha sehemu**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* kwa usanifu wa 64-bit */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* inajumuisha ukubwa wa miundo ya section_64 */
char		segname[16];	/* jina la sehemu */
uint64_t	vmaddr;		/* anwani ya kumbukumbu ya sehemu hii */
uint64_t	vmsize;		/* ukubwa wa kumbukumbu ya sehemu hii */
uint64_t	fileoff;	/* ofseti ya faili ya sehemu hii */
uint64_t	filesize;	/* kiasi cha ramani kutoka faili */
int32_t		maxprot;	/* ulinzi mkubwa wa VM */
int32_t		initprot;	/* ulinzi wa awali wa VM */
<strong>	uint32_t	nsects;		/* idadi ya sehemu katika sehemu */
</strong>	uint32_t	flags;		/* bendera */
};
</code></pre>

Mfano wa kichwa cha sehemu:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Ikiwa un **ongeza** **kielekezi cha sehemu** (0x37DC) + **kielekezi** ambapo **arch inaanza**, katika kesi hii `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Pia niwezekana kupata **habari za vichwa** kutoka kwa **mstari wa amri** na:
```bash
otool -lv /bin/ls
```
```html
<p>Sekjimenti za kawaida zilizopakiwa na hii cmd:</p>

<ul>
<li><strong>__PAGEZERO:</strong> Inaagiza kernel kufanya ramani ya <strong>anwani sifuri</strong> ili <strong>isomeki, iandikwe, au kutekelezwa</strong>. Mipangilio ya maxprot na minprot katika muundo huo hupangwa kuwa sifuri kuashiria kwamba hakuna <strong>ruhusa za kusoma-andika-tekeleza kwenye ukurasa huu</strong>.</li>
<li>Ugawaji huu ni muhimu kwa kudhibiti **udhaifu wa dereference wa pointa za NULL**. Hii ni kwa sababu XNU inatekeleza ukurasa sifuri wa ngumu ambao unahakikisha ukurasa wa kwanza (ukurasa wa kwanza tu) wa kumbukumbu hauwezi kufikiwa (isipokuwa kwa i386). Binary inaweza kukidhi mahitaji haya kwa kutengeneza __PAGEZERO ndogo (kwa kutumia `-pagezero_size`) kufunika kwanza 4k na kuwa na kumbukumbu ya 32bit iliyobaki inayopatikana katika hali ya mtumiaji na hali ya kernel.</li>
<li><strong>__TEXT</strong>: Ina <strong>msimbo wa kutekelezeka</strong> unaoruhusu <strong>kusoma</strong> na <strong>kutekeleza</strong> (siyo andikika)**.** Sehemu za kawaida za sehemu hii:</li>
<ul>
<li>__text: Msimbo wa binary uliokompiliwa</li>
<li>__const: Data ya kudumu (isomeke tu)</li>
<li>__[c/u/os_log]string</li>
<li>__stubs na __stubs_helper: Husika wakati wa mchakato wa kupakia maktaba za kudumu</li>
<li>__unwind_info: Data ya kufungua steki.</li>
</ul>
<li>Taarifa zote hizi zimesainiwa lakini pia zimeainishwa kama kutekelezeka (kutengeneza chaguzi zaidi za kutumia sehemu ambazo hazihitaji lazima haki hii, kama sehemu zilizotengwa kwa vitambulisho).</li>
<li><strong>__DATA</strong>: Ina data ambayo inaweza <strong>kusomwa</strong> na <strong>kuandikwa</strong> (siyo kutekelezeka)**.</li>
<li>__got: Jedwali la Kielekezi cha Kijumla</li>
<li>__nl_symbol_ptr: Alama ya ishara isiyo wavivu (inayobana wakati wa kupakia)</li>
<li>__la_symbol_ptr: Alama ya ishara wavivu (inayobana wakati wa matumizi)</li>
<li>__const: Inapaswa kuwa data isiyoweza kusomwa (sio kweli)</li>
<li>__cfstring: Maneno ya CoreFoundation</li>
<li>__data: Vigezo vya kawaida (ambavyo vimeanzishwa)</li>
<li>__bss: Vigezo vya tuli (ambavyo havijaanzishwa)</li>
<li>__objc_* (__objc_classlist, __objc_protolist, nk): Taarifa zinazotumiwa na runtime ya Objective-C</li>
<li><strong>__DATA_CONST</strong>: __DATA.__const haihakikishiwi kuwa ya kudumu (ruhusa za kuandika), wala viashiria vingine na jedwali la GOT. Sehemu hii inafanya `__const`, baadhi ya waanzilishi na jedwali la GOT (baada ya kutatuliwa) kuwa **ya kusomwa tu** kwa kutumia `mprotect`.</li>
<li><strong>__LINKEDIT</strong>: Ina taarifa kwa linker (dyld) kama vile, alama, herufi, na makala ya jedwali la uhamishaji. Ni chombo cha jumla cha maudhui ambayo hayamo katika `__TEXT` au `__DATA` na maudhui yake yameelezwa katika amri zingine za kupakia.</li>
<li>Taarifa ya dyld: Rebase, Opcodes za kubana zisizo wavivu/wavivu/dhaifu na habari ya kuuza</li>
<li>Mwanzo wa kazi: Jedwali la anwani za mwanzo za kazi</li>
<li>Data Ndani ya Msimbo: Visiwa vya data katika __text</li>
<li>Jedwali la Alama: Alama katika binary</li>
<li>Jedwali la Alama za Kiashiria: Alama za Kiashiria/kiti</li>
<li>Jedwali la Maneno</li>
<li>Sahihi ya Msimbo</li>
<li><strong>__OBJC</strong>: Ina taarifa inayotumiwa na runtime ya Objective-C. Ingawa taarifa hii inaweza kupatikana pia katika sehemu ya __DATA, ndani ya sehemu mbalimbali za __objc_*.</li>
<li><strong>__RESTRICT</strong>: Sehemu bila maudhui yenye sehemu moja tu inayoitwa **`__restrict`** (pia tupu) ambayo inahakikisha kwamba wakati wa kukimbia binary, itapuuza mazingira ya DYLD.</li>
</ul>

<p>Kama ilivyowezekana kuona katika msimbo, **sejimenti pia zinaunga mkono bendera** (ingawa hazitumiwi sana):</p>

<ul>
<li>SG_HIGHVM: Msingi pekee (haikutumiwa)</li>
<li>SG_FVMLIB: Haikutumiwa</li>
<li>SG_NORELOC: Sejimenti haina uhamishaji</li>
<li>SG_PROTECTED_VERSION_1: Ufichaji. Hutumiwa kwa mfano na Finder kuficha maandishi ya __TEXT.</li>
</ul>

<h3><strong>LC_UNIXTHREAD/LC_MAIN</strong></h3>

<p><strong>LC_MAIN</strong> inaingiza kipengele cha kuingia katika sifa ya **entryoff.** Wakati wa kupakia, **dyld** tu **huongeza** thamani hii kwa (kumbukumbu) **msingi wa binary**, kisha **inaruka** kwenye maagizo haya kuanza utekelezaji wa msimbo wa binary.</p>

<p><strong>LC_UNIXTHREAD</strong> ina thamani ambazo kisajili kinapaswa kuwa nacho wakati wa kuanza mnyuzi mkuu. Hii tayari imepitwa na wakati lakini **`dyld`** bado inaitumia. Inawezekana kuona thamani za visajili vilivyowekwa na hii kwa:</p>
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

Ina taarifa kuhusu **sahihi ya nambari ya faili ya Macho-O**. Ina **offset** tu ambayo **inaelekeza** kwa **blob ya sahihi**. Kawaida iko mwishoni mwa faili.\
Hata hivyo, unaweza kupata baadhi ya taarifa kuhusu sehemu hii katika [**chapisho hili la blogu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) na hii [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Inasaidia kwa kificho cha kuficha faili. Hata hivyo, bila shaka, ikiwa mshambuliaji anafanikiwa kuhatarisha mchakato, ataweza kudump kumbukumbu bila kufichwa.

### **`LC_LOAD_DYLINKER`**

Ina **njia ya kwa kielekezi cha utekelezaji wa kiungo cha kudumu** ambacho hupanga maktaba zinazoshirikiwa katika nafasi ya anwani ya mchakato. **Thamani daima inawekwa kwa `/usr/lib/dyld`**. Ni muhimu kutambua kwamba katika macOS, uanishaji wa dylib hufanyika katika **mode ya mtumiaji**, sio katika mode ya kernel.

### **`LC_IDENT`**

Imepitwa na wakati lakini wakati inapowekwa kuzalisha dumps wakati wa mshtuko, kudump ya msingi ya Mach-O inaundwa na toleo la kernel linawekwa katika amri ya `LC_IDENT`.

### **`LC_UUID`**

UUID Isiyotabirika. Ni muhimu kwa chochote moja kwa moja lakini XNU inahifadhi na habari nyingine ya mchakato. Inaweza kutumika katika ripoti za ajali.

### **`LC_DYLD_ENVIRONMENT`**

Inaruhusu kuonyesha mazingira ya mazingira kwa dyld kabla ya mchakato kutekelezwa. Hii inaweza kuwa hatari sana kwani inaweza kuruhusu kutekeleza nambari ya kupindukia ndani ya mchakato hivyo amri ya kupakia hii inatumika tu katika dyld iliyoundwa na `#define SUPPORT_LC_DYLD_ENVIRONMENT` na inazuia usindikaji zaidi tu kwa mazingira ya aina `DYLD_..._PATH` inayoeleza njia za kupakia.

### **`LC_LOAD_DYLIB`**

Amri hii ya kupakia inaelezea **tegemezi la maktaba ya kudumu** ambayo **inawaagiza** **mzigo** (dyld) kwa **kupakia na kuunganisha maktaba hiyo**. Kuna amri ya kupakia `LC_LOAD_DYLIB` **kwa kila maktaba** ambayo faili ya Mach-O inahitaji.

* Amri hii ya kupakia ni muundo wa aina **`dylib_command`** (ambao una struct dylib, ukiainisha maktaba ya kudumu inayotegemea):
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

Ungepata habari hii pia kutoka kwa cli kwa:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Baadhi ya maktaba zinazohusiana na zisizo za zisizo za programu hasidi ni:

- **DiskArbitration**: Kufuatilia diski za USB
- **AVFoundation:** Kuchukua sauti na video
- **CoreWLAN**: Uchunguzi wa Wifi.

{% hint style="info" %}
Mach-O binary inaweza kuwa na moja au **zaidi** ya **wajenzi**, ambao watakuwa **wakitekelezwa** **kabla** ya anwani iliyoainishwa katika **LC\_MAIN**.\
Vidokezo vya wajenzi wowote vinashikiliwa katika sehemu ya **\_\_mod\_init\_func** ya segimenti ya **\_\_DATA\_CONST**.
{% endhint %}

## **Data ya Mach-O**

Katikati ya faili kuna eneo la data, ambalo linaundwa na sehemu kadhaa kama ilivyoelezwa katika eneo la amri za kupakia. **Aina mbalimbali za sehemu za data zinaweza kuhifadhiwa ndani ya kila segimenti**, na kila sehemu **inashikilia kanuni au data** maalum kwa aina fulani.

{% hint style="success" %}
Data ni sehemu inayohusisha **habari zote** ambazo zinapakiwa na amri za kupakia **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Hii ni pamoja na:

- **Jedwali la kazi:** Ambalo linashikilia habari kuhusu kazi za programu.
- **Jedwali la alama**: Linaloleta habari kuhusu kazi za nje zinazotumiwa na binary
- Pia inaweza kuwa na kazi za ndani, majina ya pembejeo, na zaidi.

Ili kuangalia unaweza kutumia chombo cha [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Au kutoka kwa cli:
```bash
size -m /bin/ls
```
## Sehemu za Kawaida za Objective-C

Katika segimenti ya `__TEXT` (r-x):

- `__objc_classname`: Majina ya darasa (herufi)
- `__objc_methname`: Majina ya mbinu (herufi)
- `__objc_methtype`: Aina za mbinu (herufi)

Katika segimenti ya `__DATA` (rw-):

- `__objc_classlist`: Pointa kwa darasa zote za Objective-C
- `__objc_nlclslist`: Pointa kwa Darasa za Objective-C zisizo za uvivu
- `__objc_catlist`: Pointa kwa Jamii
- `__objc_nlcatlist`: Pointa kwa Jamii zisizo za uvivu
- `__objc_protolist`: Orodha ya Itifaki
- `__objc_const`: Data ya kudumu
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
