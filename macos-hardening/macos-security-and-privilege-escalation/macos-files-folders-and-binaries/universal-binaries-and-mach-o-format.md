# macOS Evrensel ikili dosyaları ve Mach-O Formatı

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı) ile sıfırdan kahramana AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud github depolarına PR'lar gönderin** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Temel Bilgiler

Mac OS ikili dosyaları genellikle **evrensel ikili dosyalar** olarak derlenir. Bir **evrensel ikili dosya**, **aynı dosyada birden fazla mimariyi destekleyebilir**.

Bu ikili dosyalar genellikle **Mach-O yapısını** takip eder, bu yapının temel olarak şunlardan oluşur:

* Başlık
* Yükleme Komutları
* Veri

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (467).png>)

## Yağlı Başlık

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
uint32_t	offset;		/* bu nesne dosyasına dosya ofseti */
uint32_t	size;		/* bu nesne dosyasının boyutu */
uint32_t	align;		/* 2'nin üssü olarak hizalama */
};
</code></pre>

Başlık, **sihirli** baytları ve dosyanın içerdiği **mimari sayısını** (`nfat_arch`) takip eden her mimarinin bir `fat_arch` yapısına sahip olacağı baytları içerir.

Şununla kontrol edin:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: 2 mimariye sahip Mach-O evrensel ikili dosya: [x86_64:Mach-O 64-bit yürütülebilir x86_64] [arm64e:Mach-O 64-bit yürütülebilir arm64e]
/bin/ls (mimari x86_64 için):	Mach-O 64-bit yürütülebilir x86_64
/bin/ls (mimari arm64e için):	Mach-O 64-bit yürütülebilir arm64e

% otool -f -v /bin/ls
Yağlı başlıklar
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>mimari x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
yetenekler 0x0
<strong>    ofset 16384
</strong><strong>    boyut 72896
</strong>    hizalama 2^14 (16384)
<strong>mimari arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
yetenekler PTR_AUTH_VERSION USERSPACE 0
<strong>    ofset 98304
</strong><strong>    boyut 88816
</strong>    hizalama 2^14 (16384)
</code></pre>

veya [Mach-O View](https://sourceforge.net/projects/machoview/) aracını kullanarak:

<figure><img src="../../../.gitbook/assets/image (1091).png" alt=""><figcaption></figcaption></figure>

Genellikle 2 mimari için derlenen evrensel bir ikili dosya, yalnızca 1 mimari için derlenen bir dosyanın boyutunu **iki katına çıkarır**.

## **Mach-O Başlık**

Başlık, dosya hakkında temel bilgiler içerir, örneğin sihirli baytları dosyayı Mach-O dosyası olarak tanımlamak ve hedef mimari hakkında bilgiler içerir. Şurada bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Dosya Türleri**:

* MH\_EXECUTE (0x2): Standart Mach-O yürütülebilir dosyası
* MH\_DYLIB (0x6): Bir Mach-O dinamik bağlantılı kütüphane (.dylib)
* MH\_BUNDLE (0x8): Bir Mach-O paketi (.bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Veya [Mach-O View](https://sourceforge.net/projects/machoview/) kullanarak:

<figure><img src="../../../.gitbook/assets/image (1130).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Yükleme komutları**

**Dosyanın bellekteki düzeni** burada belirtilir, **sembol tablosunun konumu**, yürütme başlangıcında ana iş parçacığının bağlamı ve gerekli **paylaşılan kütüphaneler** detaylandırılır. Talimatlar, ikincil yükleyici **(dyld)** tarafından belleğe yükleme işlemine ilişkin olarak sağlanır.

Kullanılan yapı, belirtilen **`loader.h`** içinde tanımlanan **load\_command** yapısıdır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Sistem farklı şekillerde işleyen yaklaşık **50 farklı yükleme komutu türü** bulunmaktadır. En yaygın olanlar şunlardır: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Temelde, bu tür Yükleme Komutları, ikili dosya yürütüldüğünde **\_\_TEXT** (yürütülebilir kod) ve **\_\_DATA** (işlem için veri) **segmentlerini** **veri bölümünde belirtilen ofsetlere göre nasıl yükleyeceğini** tanımlar.
{% endhint %}

Bu komutlar, bir işlem yürütüldüğünde **sanal bellek alanına eşlenen segmentleri tanımlar**.

**Farklı türlerde** segmentler bulunmaktadır, örneğin bir programın yürütülebilir kodunu içeren **\_\_TEXT** segmenti ve işlem tarafından kullanılan verileri içeren **\_\_DATA** segmenti. Bu **segmentler**, Mach-O dosyasının veri bölümünde bulunmaktadır.

**Her segment**, daha fazla **bölünebilen birden fazla bölüme** ayrılabilir. **Yükleme komutu yapısı**, ilgili segment içindeki **bu bölümler hakkında bilgi** içerir.

Başlıkta önce **segment başlığını** bulursunuz:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* 64-bit mimariler için */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* section_64 yapılarının boyutunu içerir */
char		segname[16];	/* segment adı */
uint64_t	vmaddr;		/* bu segmentin bellek adresi */
uint64_t	vmsize;		/* bu segmentin bellek boyutu */
uint64_t	fileoff;	/* bu segmentin dosya ofseti */
uint64_t	filesize;	/* dosyadan eşlenmesi gereken miktar */
int32_t		maxprot;	/* maksimum VM koruması */
int32_t		initprot;	/* başlangıç VM koruması */
<strong>	uint32_t	nsects;		/* segmentteki bölüm sayısı */
</strong>	uint32_t	flags;		/* bayraklar */
};
</code></pre>

Segment başlığının örneği:

<figure><img src="../../../.gitbook/assets/image (1123).png" alt=""><figcaption></figcaption></figure>

Bu başlık, **ardından görünen başlıkları olan bölümlerin sayısını** tanımlar:
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
Örnek **bölüm başlığı**:

<figure><img src="../../../.gitbook/assets/image (1105).png" alt=""><figcaption></figcaption></figure>

Eğer **bölüm ofseti**ni (0x37DC) **eklerseniz** ve **mimarinin başladığı ofseti** (bu durumda `0x18000`) **ofsete eklerseniz** --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Ayrıca **başlık bilgilerini** **komut satırından** da almak mümkündür:
```bash
otool -lv /bin/ls
```
```markdown
Bu cmd tarafından yüklenen yaygın bölümler:

* **`__PAGEZERO`:** Çekirdeğe **adres sıfırı**nı **haritalamaması** için talimat verir, böylece bu sayfada **okunamaz, yazılamaz veya yürütülemez**. Yapıdaki maxprot ve minprot değişkenleri sıfıra ayarlanır, bu sayfada **okuma-yazma-yürütme hakları olmadığını** belirtir.
* Bu tahsis, **NULL işaretçi sıfırlama zafiyetlerini hafifletmek** için önemlidir.
* **`__TEXT`**: **Okunabilir** ve **yürütülebilir** **kod** içerir (yazılabilir değil)**.** Bu segmentin yaygın bölümleri:
* `__text`: Derlenmiş ikili kod
* `__const`: Sabit veri
* `__cstring`: Dize sabitleri
* `__stubs` ve `__stubs_helper`: Dinamik kitaplık yükleme sürecinde rol oynar
* **`__DATA`**: **Okunabilir** ve **yazılabilir** verileri içerir (yürütülebilir değil)**.**
* `__data`: Başlatılmış küresel değişkenler
* `__bss`: Başlatılmamış statik değişkenler
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, vb.): Objective-C çalışma zamanı tarafından kullanılan bilgiler
* **`__LINKEDIT`**: Bağlayıcı için (dyld) "sembol, dize ve yer değiştirme tablosu girişleri" gibi bilgileri içerir.
* **`__OBJC`**: Objective-C çalışma zamanı tarafından kullanılan bilgileri içerir. Bu bilgiler ayrıca \_\_DATA segmentinde, çeşitli \_\_objc\_\* bölümlerinde de bulunabilir.

### **`LC_MAIN`**

**entryoff özniteliğindeki** giriş noktasını içerir. Yükleme zamanında, **dyld** sadece bu değeri (bellekteki) **ikili dosyanın tabanına ekler**, ardından yürütmenin başlaması için bu talimata **atlar**.

### **LC\_CODE\_SIGNATURE**

Macho-O dosyasının **kod imzası hakkında bilgileri** içerir. Yalnızca bir **imza bloguna işaret eden** bir **ofset** içerir. Bu genellikle dosyanın sonunda bulunur.\
Ancak, bu bölümle ilgili bazı bilgileri [**bu blog yazısında**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve bu [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) bulabilirsiniz.

### **LC\_LOAD\_DYLINKER**

Paylaşılan kitaplıkları işlem adres alanına haritalayan dinamik bağlayıcı yürütülebilir dosyanın **yolunu içerir**. **Değer her zaman `/usr/lib/dyld` olarak ayarlanır**. macOS'ta dylib eşlemesi **çekirdek modunda değil, kullanıcı modunda** gerçekleşir.

### **`LC_LOAD_DYLIB`**

Bu yükleme komutu, **yükleme ve bağlama talimatı veren** **dinamik** **kitaplık** bağımlılığını açıklar. Mach-O ikili dosyanın gerektirdiği her kitaplık için bir LC\_LOAD\_DYLIB yükleme komutu vardır.

* Bu yükleme komutu, **gerçek bağımlı dinamik kitaplığı tanımlayan** bir yapı türüdür: **`dylib_command`** (struct dylib içeren, asıl bağımlı dinamik kitaplığı tanımlayan bir yapı): 
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
Ayrıca bu bilgiyi şu komutla da alabilirsiniz:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Potansiyel kötü amaçlı yazılım ile ilişkili kütüphaneler şunlardır:

- **DiskArbitration**: USB sürücülerini izleme
- **AVFoundation:** Ses ve video yakalama
- **CoreWLAN**: Wifi taramaları.

{% hint style="info" %}
Bir Mach-O ikili dosyası, **LC\_MAIN**'de belirtilen adresten **önce** **çalıştırılacak** bir veya **daha fazla** **yapıcıyı** içerebilir.\
Herhangi bir yapıcının ofsetleri, **\_\_DATA\_CONST** segmentinin **\_\_mod\_init\_func** bölümünde tutulur.
{% endhint %}

## **Mach-O Verileri**

Dosyanın çekirdeğinde, yükleme komutları bölgesinde tanımlanan birkaç segmentten oluşan veri bölgesi bulunmaktadır. **Her segmentte çeşitli veri bölümleri barındırılabilir**, her bölüm de bir türe özgü kod veya veri içerir.

{% hint style="success" %}
Veri, temelde yükleme komutları **LC\_SEGMENTS\_64** tarafından yüklenen tüm **bilgileri** içeren kısımdır.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Bu şunları içerir:

- **Fonksiyon tablosu:** Program fonksiyonları hakkında bilgileri tutar.
- **Sembol tablosu**: İkili dosya tarafından kullanılan harici fonksiyonlar hakkındaki bilgileri içerir
- Ayrıca iç fonksiyonları, değişken adlarını ve daha fazlasını içerebilir.

Bunu kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Veya komut satırından:
```bash
size -m /bin/ls
```
<detaylar>

<özet>

<strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na bakın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni alın (https://peass.creator-spring.com)
* [**The PEASS Ailesi**]'ni keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**] koleksiyonumuz (https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**] (https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] veya **bizi takip edin** **Twitter** 🐦 [**@carlospolopm**] (https://twitter.com/hacktricks\_live)**.**
* **Hacking püf noktalarınızı göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</detaylar>
