# macOS Evrensel ikili dosyaları ve Mach-O Formatı

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Temel Bilgiler

Mac OS ikili dosyaları genellikle **evrensel ikili dosyalar** olarak derlenir. Bir **evrensel ikili dosya**, **aynı dosyada birden fazla mimariyi destekleyebilir**.

Bu ikili dosyalar genellikle **Mach-O yapısını** takip eder, bu yapının temel olarak şunlardan oluşur:

* Başlık
* Yükleme Komutları
* Veri

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Fat Başlık

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

Başlık, **sihirli** baytları ve dosyanın içerdiği **mimari sayısını** (`nfat_arch`) takip eden her mimarinin bir `fat_arch` yapısına sahip olduğu **sayıyı** içerir.

Şununla kontrol edin:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: 2 mimariye sahip Mach-O evrensel ikili dosya: [x86_64:Mach-O 64-bit yürütülebilir x86_64] [arm64e:Mach-O 64-bit yürütülebilir arm64e]
/bin/ls (mimari x86_64 için):	Mach-O 64-bit yürütülebilir x86_64
/bin/ls (mimari arm64e için):	Mach-O 64-bit yürütülebilir arm64e

% otool -f -v /bin/ls
Fat başlıklar
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

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Genellikle 2 mimari için derlenen bir evrensel ikili dosya, yalnızca 1 mimari için derlenen bir dosyanın boyutunu **iki katına çıkarır**.

## **Mach-O Başlık**

Başlık, dosya hakkında temel bilgiler içerir, örneğin dosyayı Mach-O dosyası olarak tanımlamak için sihirli baytları ve hedef mimari hakkında bilgiler içerir. Şurada bulabilirsiniz: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O Dosya Türleri

Farklı dosya türleri bulunmaktadır, bunlar [**örneğin burada tanımlanmıştır**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). En önemlileri şunlardır:

* `MH_OBJECT`: Taşınabilir nesne dosyası (derlemenin ara ürünleri, henüz yürütülebilir değil).
* `MH_EXECUTE`: Yürütülebilir dosyalar.
* `MH_FVMLIB`: Sabit VM kütüphane dosyası.
* `MH_CORE`: Kod Dökümleri
* `MH_PRELOAD`: Önceden yüklenmiş yürütülebilir dosya (artık XNU'da desteklenmiyor)
* `MH_DYLIB`: Dinamik Kütüphaneler
* `MH_DYLINKER`: Dinamik Bağlayıcı
* `MH_BUNDLE`: "Eklenti dosyaları". GCC'de -bundle kullanılarak oluşturulur ve `NSBundle` veya `dlopen` tarafından açıkça yüklenir.
* `MH_DYSM`: Eş `.dSym` dosyası (hata ayıklama sembolleri içeren dosya).
* `MH_KEXT_BUNDLE`: Çekirdek Uzantıları.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Veya [Mach-O View](https://sourceforge.net/projects/machoview/) kullanarak:

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Bayrakları**

Kaynak kod ayrıca kütüphaneleri yükleme için kullanışlı birkaç bayrak tanımlar:

* `MH_NOUNDEFS`: Tanımsız referans yok (tam bağlantılı)
* `MH_DYLDLINK`: Dyld bağlantısı
* `MH_PREBOUND`: Dinamik referanslar önceden bağlanmış.
* `MH_SPLIT_SEGS`: Dosya r/o ve r/w segmentlere bölünmüştür.
* `MH_WEAK_DEFINES`: Binanın zayıf tanımlı sembolleri vardır
* `MH_BINDS_TO_WEAK`: Bina zayıf sembolleri kullanır
* `MH_ALLOW_STACK_EXECUTION`: Yığını yürütülebilir yap
* `MH_NO_REEXPORTED_DYLIBS`: Kütüphane LC\_REEXPORT komutları içermez
* `MH_PIE`: Konum Bağımsız Yürütülebilir
* `MH_HAS_TLV_DESCRIPTORS`: İplik yerel değişkenlere sahip bir bölüm var
* `MH_NO_HEAP_EXECUTION`: Yığın/veri sayfaları için yürütme yok
* `MH_HAS_OBJC`: Bina Objective-C bölümlerine sahip
* `MH_SIM_SUPPORT`: Simülatör desteği
* `MH_DYLIB_IN_CACHE`: Paylaşılan kütüphane önbelleğindeki dylib/framework'lerde kullanılır.

## **Mach-O Yükleme Komutları**

**Dosyanın bellekteki düzeni** burada belirtilir, **sembol tablosunun konumu**, yürütme başlangıcında ana iş parçacığının bağlamı ve gerekli **paylaşılan kütüphaneler** ayrıntılandırılır. Talimatlar, ikincil yükleyici **(dyld)** üzerine, binanın belleğe yüklenme süreci hakkında bilgi sağlar.

Kullanılan yapı **load\_command** yapısıdır, belirtilen **`loader.h`** içinde tanımlanmıştır:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Sistem farklı şekillerde işlediği yaklaşık **50 farklı yükleme komutu türü** bulunmaktadır. En yaygın olanlar şunlardır: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` ve `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Temelde, bu tür Yükleme Komutları, ikili dosya yürütüldüğünde **\_\_TEXT** (yürütülebilir kod) ve **\_\_DATA** (işlem için veri) **segmentlerini** yüklemenin **Veri bölümünde belirtilen ofsetlere göre** nasıl yapılacağını tanımlar.
{% endhint %}

Bu komutlar, bir işlem yürütüldüğünde **sanal bellek alanına eşlenen segmentleri tanımlar**.

**Farklı türlerde** segmentler bulunmaktadır, örneğin bir programın yürütülebilir kodunu içeren **\_\_TEXT** segmenti ve işlem tarafından kullanılan verileri içeren **\_\_DATA** segmenti gibi. Bu **segmentler**, Mach-O dosyasının veri bölümünde bulunmaktadır.

**Her segment**, daha fazla **bölünebilen birden fazla bölüme** ayrılabilir. **Yükleme komutu yapısı**, ilgili segment içindeki **bu bölümlerle ilgili bilgileri** içerir.

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

Segment başlığının bir örneği:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Bu başlık, **ardından görünen başlıkların sayısını** tanımlar:
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

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Eğer **bölüm ofseti** (0x37DC) + **mimarinin başladığı ofset** eklenirse, bu durumda `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Ayrıca **komut satırından** **başlık bilgilerini** almak da mümkündür:
```bash
otool -lv /bin/ls
```
Bu komut tarafından yüklenen yaygın bölümler:

* **`__PAGEZERO`:** Çekirdeğe **adres sıfırı**nı **haritalamayı** emreder, böylece bu sayfadan **okunamaz, yazılamaz veya yürütülemez**. Yapıdaki maxprot ve minprot değişkenleri sıfıra ayarlanır, bu da bu sayfada **okuma-yazma-yürütme haklarının olmadığını** gösterir.
* Bu tahsis, **NULL işaretçi sıfırlama açıklarını hafifletmek için önemlidir**. Bu, XNU'nun yalnızca ilk bellek sayfasının (yalnızca ilk) erişilemez olduğunu sağlayan sert bir sayfa sıfırını zorunlu kılmasından kaynaklanmaktadır (yalnızca i386'da). Bir ikili dosya, ilk 4k'yi kapsayan küçük bir \_\_PAGEZERO oluşturarak ve geri kalan 32 bit belleğin hem kullanıcı hem de çekirdek modunda erişilebilir olmasını sağlayarak bu gereksinimleri karşılayabilir.
* **`__TEXT`**: **Okunabilir** ve **yürütülebilir** izinlere sahip **yürütülebilir** **kod** içerir (yazılabilir değil)**.** Bu segmentin yaygın bölümleri:
* `__text`: Derlenmiş ikili kod
* `__const`: Sabit veri (yalnızca okunabilir)
* `__[c/u/os_log]string`: C, Unicode veya işletim sistemi günlüğü dizesi sabitleri
* `__stubs` ve `__stubs_helper`: Dinamik kitaplık yükleme sürecinde rol oynar
* `__unwind_info`: Yığın açma verileri.
* Tüm bu içeriğin imzalandığını ancak aynı zamanda yürütülebilir olarak işaretlendiğini unutmayın (bu ayrıcalığa ihtiyaç duymayan bölümlerin söz konusu ayrıcalığı kullanarak istismar seçenekleri oluşturulması).
* **`__DATA`**: **Okunabilir** ve **yazılabilir** verileri içerir (yürütülemez)**.**
* `__got:` Global Offset Table
* `__nl_symbol_ptr`: Tembel olmayan (yükleme sırasında bağlanan) sembol işaretçisi
* `__la_symbol_ptr`: Tembel (kullanımda bağlanan) sembol işaretçisi
* `__const`: Gerçekte yalnızca okunabilir veri olmalıdır (değil)
* `__cfstring`: CoreFoundation dizeleri
* `__data`: Başlatılmış global değişkenler
* `__bss`: Başlatılmamış statik değişkenler
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, vb.): Objective-C çalışma zamanı tarafından kullanılan bilgiler
* **`__DATA_CONST`**: \_\_DATA.\_\_const sabit olması garanti edilmez (yazma izinleri), diğer işaretçiler ve GOT de değil. Bu bölüm, `__const`, bazı başlatıcılar ve GOT tablosunu (çözümlendikten sonra) `mprotect` kullanarak **yalnızca okunabilir** yapar.
* **`__LINKEDIT`**: Bağlayıcı için (dyld gibi) sembol, dize ve yer değiştirme tablosu girişleri gibi bilgileri içerir. `__TEXT` veya `__DATA` içinde olmayan içerikler için genel bir konteynerdir ve içeriği diğer yükleme komutlarında açıklanmıştır.
* dyld bilgileri: Yeniden konumlandırma, Tembel olmayan/tembel/zayıf bağlama işlemleri ve ihraç bilgileri
* Fonksiyon başlangıçları: Fonksiyonların başlangıç adresleri tablosu
* Kod İçindeki Veri: \_\_text içindeki veri adaları
* Sembol Tablosu: İkili dosyadaki semboller
* Dolaylı Sembol Tablosu: İşaretçi/stub sembolleri
* Dize Tablosu
* Kod İmzası
* **`__OBJC`**: Objective-C çalışma zamanı tarafından kullanılan bilgileri içerir. Bu bilgiler, \_\_DATA segmentinde de bulunabilir, çeşitli \_\_objc\_\* bölümlerinde.
* **`__RESTRICT`**: İçeriği olmayan bir bölüm olan **`__restrict`** adında tek bir bölüm içerir (ayrıca boştur) ve ikili dosya çalıştırıldığında DYLD çevresel değişkenlerini yoksayar.

Kodda görülebileceği gibi, **bölümler ayrıca bayrakları destekler** (ancak çok fazla kullanılmazlar):

* `SG_HIGHVM`: Yalnızca çekirdek (kullanılmaz)
* `SG_FVMLIB`: Kullanılmaz
* `SG_NORELOC`: Bölümde yeniden konumlandırma yok
* `SG_PROTECTED_VERSION_1`: Şifreleme. Örneğin Finder tarafından metni şifrelemek için `__TEXT` segmentini kullanır.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`**, **entryoff özniteliğindeki** giriş noktasını içerir. Yükleme zamanında, **dyld** bu değeri (bellekteki) **ikili dosyanın tabanına ekler**, ardından bu talimata atlayarak ikili dosyanın kodunun yürütmesini başlatır.

**`LC_UNIXTHREAD`**, ana iş parçacığını başlatırken kayıtların sahip olması gereken değerleri içerir. Bu zaten kullanımdan kaldırılmış olsa da **`dyld`** hala bunu kullanır. Bu ile ayarlanan kayıtların değerlerini görmek mümkündür:
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

Macho-O dosyasının **kod imzası** hakkında bilgi içerir. Yalnızca **imza bloğuna işaret eden bir ofset** içerir. Genellikle dosyanın sonunda bulunur.\
Ancak, bu bölüm hakkında bazı bilgileri [**bu blog yazısında**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) ve bu [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) bulabilirsiniz.

### **`LC_ENCRYPTION_INFO[_64]`**

Binary şifrelemesini destekler. Ancak, tabii ki, bir saldırgan süreci ele geçirmeyi başarırsa, belleği şifrelenmemiş olarak dökme yeteneğine sahip olacaktır.

### **`LC_LOAD_DYLINKER`**

Paylaşılan kütüphaneleri işlem adres alanına eşleyen dinamik bağlayıcı yürütülebilir dosyanın **yolunu içerir**. **Değeri her zaman `/usr/lib/dyld` olarak ayarlanmıştır**. macOS'ta dylib eşlemesi **çekirdek modunda değil, kullanıcı modunda** gerçekleşir.

### **`LC_IDENT`**

Eskidir ancak panik durumunda dökümler oluşturacak şekilde yapılandırıldığında, bir Mach-O çekirdek dökümü oluşturulur ve çekirdek sürümü `LC_IDENT` komutunda ayarlanır.

### **`LC_UUID`**

Rastgele UUID. Doğrudan herhangi bir şey için faydalı değildir ancak XNU, işlem bilgilerinin geri kalanıyla birlikte önbelleğe alır. Çökme raporlarında kullanılabilir.

### **`LC_DYLD_ENVIRONMENT`**

İşlem yürütülmeden önce dyld'ye çevresel değişkenleri belirtmeye izin verir. Bu, işlem içinde keyfi kodları yürütmeye izin verebileceğinden oldukça tehlikeli olabilir, bu yük komutu yalnızca `#define SUPPORT_LC_DYLD_ENVIRONMENT` ile derlenmiş dyld'de kullanılır ve yük yollarını belirleyen `DYLD_..._PATH` biçimindeki değişkenlere sadece işleme izin verir.

### **`LC_LOAD_DYLIB`**

Bu yükleme komutu, **yükleme ve bağlama komutunu** (dyld) **belirten** **dinamik bir kütüphane** bağımlılığını açıklar. Mach-O ikilisinin gerektirdiği her kütüphane için bir `LC_LOAD_DYLIB` yükleme komutu bulunmaktadır.

* Bu yükleme komutu, **gerçek bağımlı dinamik kütüphaneyi tanımlayan struct dylib içeren bir dylib_command** türünde bir yapıdır:
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

Bu bilgilere ayrıca şu komut satırı arayüzüyle de ulaşabilirsiniz:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
```markdown
Potansiyel kötü amaçlı yazılım ile ilişkili kütüphaneler şunlardır:

* **DiskArbitration**: USB sürücülerini izleme
* **AVFoundation:** Ses ve video yakalama
* **CoreWLAN**: Wifi taramaları.

{% hint style="info" %}
Bir Mach-O ikili dosyası, **LC\_MAIN**'de belirtilen adresten **önce** **çalıştırılacak** bir veya **daha fazla** **yapıcı** içerebilir.\
Herhangi bir yapıcının ofsetleri, **\_\_DATA\_CONST** segmentinin **\_\_mod\_init\_func** bölümünde tutulur.
{% endhint %}

## **Mach-O Verileri**

Dosyanın çekirdeğinde, yükleme komutları bölgesinde tanımlanan birkaç segmentten oluşan veri bölgesi bulunmaktadır. **Her segmentte çeşitli veri bölümleri barındırılabilir**, her bölüm de bir türe özgü kod veya veri içerir.

{% hint style="success" %}
Veri, temelde yükleme komutları **LC\_SEGMENTS\_64** tarafından yüklenen tüm **bilgileri** içeren kısmıdır.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Bu şunları içerir:

* **Fonksiyon tablosu:** Program fonksiyonları hakkında bilgileri tutar.
* **Sembol tablosu**: İkili dosya tarafından kullanılan harici fonksiyonlar hakkındaki bilgileri içerir
* Ayrıca iç fonksiyonları, değişken isimlerini ve daha fazlasını içerebilir.

Bunu kontrol etmek için [**Mach-O View**](https://sourceforge.net/projects/machoview/) aracını kullanabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Veya komut satırından:
```
```bash
size -m /bin/ls
```
## Objective-C Ortak Bölümler

`__TEXT` segmentinde (r-x):

- `__objc_classname`: Sınıf isimleri (diziler)
- `__objc_methname`: Metod isimleri (diziler)
- `__objc_methtype`: Metod tipleri (diziler)

`__DATA` segmentinde (rw-):

- `__objc_classlist`: Tüm Objective-C sınıflarına işaretçiler
- `__objc_nlclslist`: Tembel Olmayan Objective-C sınıflarına işaretçiler
- `__objc_catlist`: Kategorilere işaretçi
- `__objc_nlcatlist`: Tembel Olmayan Kategorilere işaretçi
- `__objc_protolist`: Protokoller listesi
- `__objc_const`: Sabit veri
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
