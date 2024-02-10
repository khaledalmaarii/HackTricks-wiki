# macOS Evrensel ikili dosyaları ve Mach-O Formatı

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

Mac OS ikili dosyaları genellikle **evrensel ikili dosyalar** olarak derlenir. Bir **evrensel ikili dosya**, aynı dosyada **çoklu mimarileri destekleyebilir**.

Bu ikili dosyalar, temel olarak şu şekilde oluşan **Mach-O yapısını** takip eder:

* Başlık
* Yükleme Komutları
* Veri

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

## Yağ Başlık

Dosyayı şu komutla arayın: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* takip eden yapıların sayısı */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu belirleyici (int) */
cpu_subtype_t	cpusubtype;	/* makine belirleyici (int) */
uint32_t	offset;		/* bu nesne dosyasına göre dosya ofseti */
uint32_t	size;		/* bu nesne dosyasının boyutu */
uint32_t	align;		/* 2'nin üssü olarak hizalama */
};
</code></pre>

Başlık, **sihirli** baytları ve dosyanın içerdiği **mimari sayısını** (`nfat_arch`) takip eden her bir mimarinin bir `fat_arch` yapısına sahip olduğu bilgileri içerir.

Bunu şu şekilde kontrol edin:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: 2 mimariye sahip Mach-O evrensel ikili dosya: [x86_64:Mach-O 64-bit çalıştırılabilir x86_64] [arm64e:Mach-O 64-bit çalıştırılabilir arm64e]
/bin/ls (mimari x86_64 için):	Mach-O 64-bit çalıştırılabilir x86_64
/bin/ls (mimari arm64e için):	Mach-O 64-bit çalıştırılabilir arm64e

% otool -f -v /bin/ls
Yağ başlıklar
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>mimari x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>mimari arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

veya [Mach-O View](https://sourceforge.net/projects/machoview/) aracını kullanarak:

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Genellikle 2 mimari için derlenen evrensel bir ikili dosya, yalnızca 1 mimari için derlenene göre **boyutunu ikiye katlar**.

## **Mach-O Başlık**

Başlık, dosyanın sihirli baytlarını ve hedef mimari hakkında bilgiler gibi dosya hakkında temel bilgiler içerir. Başlığı şurada bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Dosya türleri**:

* MH\_EXECUTE (0x2): Standart Mach-O yürütülebilir dosyası
* MH\_DYLIB (0x6): Bir Mach-O dinamik bağlantılı kütüphane (yani .dylib)
* MH\_BUNDLE (0x8): Bir Mach-O paketi (yani .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Veya [Mach-O View](https://sourceforge.net/projects/machoview/) kullanarak:

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Yükleme komutları**

Bellekteki **dosyanın düzeni** burada belirtilir, **sembol tablosunun konumu**, yürütme başlangıcında ana iş parçacığının bağlamı ve gereken **paylaşılan kütüphaneler** ayrıntılı olarak açıklanır. Talimatlar, binary'nin belleğe yükleme süreci hakkında dinamik yükleyici **(dyld)**'ye sağlanır.

Kullanılan yapı, bahsedilen **`loader.h`** içinde tanımlanan **load\_command** yapısıdır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Sistem farklı şekillerde işlenen yaklaşık **50 farklı yükleme komutu** bulunmaktadır. En yaygın olanlar şunlardır: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Temel olarak, bu tür Yükleme Komutu, ikili dosya çalıştırıldığında **Veri bölümünde belirtilen ofsetlere göre \_\_TEXT** (yürütülebilir kod) **ve \_\_DATA** (işlem için veri) **segmentlerinin nasıl yükleneceğini** tanımlar.
{% endhint %}

Bu komutlar, bir işlem çalıştırıldığında **sanal bellek alanına eşlenen segmentleri** tanımlar.

\_\_TEXT segmenti, bir programın yürütülebilir kodunu içeren ve işlem tarafından kullanılan verileri içeren \_\_DATA segmenti gibi **farklı türlerde segmentler** bulunmaktadır. Bu segmentler, Mach-O dosyasının veri bölümünde bulunur.

**Her segment**, daha fazla **bölüme** ayrılabilir. **Yükleme komutu yapısı**, ilgili segment içindeki **bu bölümlerle ilgili bilgileri** içerir.

Başlıkta önce **segment başlığı** bulunur:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* 64 bit mimariler için */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* section_64 yapılarının sizeof'ını içerir */
char		segname[16];	/* segment adı */
uint64_t	vmaddr;		/* bu segmentin bellek adresi */
uint64_t	vmsize;		/* bu segmentin bellek boyutu */
uint64_t	fileoff;	/* bu segmentin dosya ofseti */
uint64_t	filesize;	/* dosyadan eşlenecek miktar */
int32_t		maxprot;	/* maksimum VM koruması */
int32_t		initprot;	/* başlangıç VM koruması */
<strong>	uint32_t	nsects;		/* segmentteki bölüm sayısı */
</strong>	uint32_t	flags;		/* bayraklar */
};
</code></pre>

Segment başlığı örneği:

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Bu başlık, **ardından görünen bölüm başlıklarının sayısını** tanımlar:
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
**Bölüm başlığı** örneği:

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Eğer **bölüm ofsetini** (0x37DC) + **mimarinin başladığı ofseti** (bu durumda `0x18000`) **eklerseniz**, `0x37DC + 0x18000 = 0x1B7DC` olur.

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ayrıca **komut satırından** **başlık bilgilerini** almak da mümkündür:
```bash
otool -lv /bin/ls
```
Bu komut tarafından yüklenen yaygın bölümler:

* **`__PAGEZERO`:** Bu, çekirdeğe **adres sıfırı**nı **okunamaz, yazılamaz veya yürütülemez** olarak **haritalamak** için talimat verir. Yapıdaki maxprot ve minprot değişkenleri sıfıra ayarlanır, bu da bu sayfada **okuma-yazma-yürütme haklarının olmadığını** gösterir.
* Bu tahsis, **NULL işaretçi başvurusu açıklarını hafifletmek** için önemlidir.
* **`__TEXT`**: **Okunabilir** ve **yürütülebilir** (yazılabilir değil) **yürütülebilir** **kod** içerir. Bu segmentin yaygın bölümleri:
* `__text`: Derlenmiş ikili kod
* `__const`: Sabit veriler
* `__cstring`: Dize sabitleri
* `__stubs` ve `__stubs_helper`: Dinamik kitaplık yükleme sürecinde yer alır
* **`__DATA`**: **Okunabilir** ve **yazılabilir** (yürütülemez) veriler içerir.
* `__data`: Başlatılmış global değişkenler
* `__bss`: Başlatılmamış statik değişkenler
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, vb.): Objective-C çalışma zamanı tarafından kullanılan bilgiler
* **`__LINKEDIT`**: "sembol, dize ve yerleştirme tablosu girişleri" gibi, bağlayıcı (dyld) için bilgiler içerir.
* **`__OBJC`**: Objective-C çalışma zamanı tarafından kullanılan bilgiler içerir. Bu bilgiler aynı zamanda \_\_DATA segmentinde de bulunabilir, çeşitli \_\_objc\_\* bölümlerinde bulunur.

### **`LC_MAIN`**

**entryoff** özniteliğinde giriş noktasını içerir. Yükleme zamanında, **dyld** bu değeri (hafızada) **ikilinin tabanına ekler**, ardından bu talimata atlayarak ikilinin kodunun yürütmesini başlatır.

### **LC\_CODE\_SIGNATURE**

Macho-O dosyasının **kod imzası hakkında bilgi** içerir. Yalnızca **imza bloğuna işaret eden bir ofset** içerir. Bu genellikle dosyanın sonunda bulunur.\
Ancak, bu bölüm hakkında bazı bilgilere [**bu blog yazısında**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve bu [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) ulaşabilirsiniz.

### **LC\_LOAD\_DYLINKER**

Paylaşılan kitaplıkları işlem adres alanına eşleyen dinamik bağlayıcı yürütülebilirinin **yolunu içerir**. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. Önemli bir nokta olarak, macOS'ta dylib eşlemesi **çekirdek modunda değil, kullanıcı modunda** gerçekleşir.

### **`LC_LOAD_DYLIB`**

Bu yükleme komutu, Mach-O ikilisinin gerektirdiği **dinamik kitaplık bağımlılığını tanımlar** ve **yükleyiciyi** (dyld) **bu kitaplığı yüklemesi ve bağlaması için yönlendirir**. Mach-O ikilisinin gerektirdiği her kitaplık için bir LC\_LOAD\_DYLIB yükleme komutu vardır.

* Bu yükleme komutu, gerçek bağımlı dinamik kitaplığı tanımlayan bir struct dylib içeren **`dylib_command`** türünde bir yapıdır:
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

Bu bilgiyi ayrıca komut satırından da alabilirsiniz:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Potansiyel kötü amaçlı yazılım ile ilişkili bazı kütüphaneler şunlardır:

* **DiskArbitration**: USB sürücülerini izleme
* **AVFoundation:** Ses ve video yakalama
* **CoreWLAN**: Wifi taramaları.

{% hint style="info" %}
Bir Mach-O ikili dosyası, **LC\_MAIN**'de belirtilen adresten **önce** **çalıştırılacak** bir veya **daha fazla yapıcı** içerebilir.\
Herhangi bir yapıcının ofsetleri, **\_\_DATA\_CONST** segmentinin **\_\_mod\_init\_func** bölümünde tutulur.
{% endhint %}

## **Mach-O Verileri**

Dosyanın çekirdeğinde, yük komutları bölgesinde tanımlandığı gibi birkaç segmentten oluşan veri bölgesi bulunur. **Her segmentte birçok veri bölümü barındırılabilir**, her bölüm ise bir türe özgü kod veya veri içerir.

{% hint style="success" %}
Veri, temel olarak yük komutları **LC\_SEGMENTS\_64** tarafından yüklenen tüm **bilgileri** içeren kısımdır.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Bu şunları içerir:

* **Fonksiyon tablosu:** Program fonksiyonları hakkında bilgi içerir.
* **Sembol tablosu**: İkili tarafından kullanılan harici fonksiyonlar hakkında bilgi içerir
* Ayrıca dahili fonksiyon, değişken adları ve daha fazlasını içerebilir.

Bunu kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Veya komut satırından:
```bash
size -m /bin/ls
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
