# macOS Kütüphane Enjeksiyonu

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na (https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

{% hint style="danger" %}
**dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve **dyld-852.2.tar.gz gibi bir URL kullanarak** bir **tar** dosyası olarak indirilebilir.
{% endhint %}

## **Dyld İşlemi**

Dyld'in ikili dosyalar içinde kütüphaneleri nasıl yüklediğine bir göz atın:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

Bu, [**LD\_PRELOAD'a Linux'ta**](../../../../linux-hardening/privilege-escalation/#ld\_preload) benzerdir. Bir işlemi belirli bir kütüphaneyi bir yol üzerinden yüklemek için çalıştıracağını belirtmeye izin verir (eğer env değişkeni etkinse)

Bu teknik aynı zamanda her yüklenen uygulamanın bir "Info.plist" adlı bir plist dosyasına sahip olduğu ve `LSEnvironmental` adlı bir anahtar kullanarak **çevresel değişkenlerin atanmasına izin verdiği bir ASEP tekniği olarak da kullanılabilir.

{% hint style="info" %}
2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`'in gücünü büyük ölçüde azaltmıştır**.

Koda gidin ve **`src/dyld.cpp`'yi kontrol edin**. **`pruneEnvironmentVariables`** işlevinde **`DYLD_*`** değişkenlerinin kaldırıldığını görebilirsiniz.

**`processRestricted`** işlevinde kısıtlamanın nedeni belirlenir. Bu kodu kontrol ettiğinizde nedenlerin şunlar olduğunu görebilirsiniz:

* İkili dosya `setuid/setgid`'dir
* Macho ikili dosyasında `__RESTRICT/__restrict` bölümünün varlığı.
* Yazılımın [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) ayrıcalığı olmadan sertleştirilmiş çalışma zamanına sahip olması
* Bir ikilinin **ayrıcalıklarını** `codesign -dv --entitlements :- </path/to/bin>` ile kontrol edin

Daha güncel sürümlerde bu mantığı **`configureProcessRestrictions`** işlevinin ikinci kısmında bulabilirsiniz. Ancak, yeni sürümlerde yürütülen şey, **fonksiyonun başlangıç kontrolleridir** (iOS veya simülasyonla ilgili olanları macOS'ta kullanılmayacağından bu kontrolleri kaldırabilirsiniz.
{% endhint %}

### Kütüphane Doğrulaması

İkili dosya **`DYLD_INSERT_LIBRARIES`** env değişkenini kullanmaya izin verirse bile, ikili dosya kütüphanenin imzasını kontrol ederse özel bir kütüphane yüklemeyecektir.

Özel bir kütüphane yüklemek için ikili dosyanın aşağıdaki ayrıcalıklardan birine sahip olması gerekir:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya ikili dosyanın **sertleştirilmiş çalışma zamanı bayrağı** veya **kütüphane doğrulama bayrağı** olmaması gerekir.

Bir ikilinin **sertleştirilmiş çalışma zamanına** sahip olup olmadığını `codesign --display --verbose <bin>` ile kontrol ederek **`CodeDirectory`** içindeki bayrak çalışma zamanını kontrol edebilirsiniz: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca, bir kütüphanenin **ikili dosya ile aynı sertifikayla imzalandığı** durumda bir kütüphaneyi yükleyebilirsiniz.

Bunu (kötüye kullanma) nasıl yapacağınızı ve kısıtlamaları kontrol etmek için bir örneği aşağıda bulabilirsiniz:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Kaçırma

{% hint style="danger" %}
**Önceki Kütüphane Doğrulama kısıtlamalarının** Dylib kaçırma saldırıları gerçekleştirmek için de geçerli olduğunu unutmayın.
{% endhint %}

Windows'ta olduğu gibi, MacOS'ta da **dylib'leri kaçırabilir** ve **uygulamaların** **keyfi** **kod** **çalıştırmasını** sağlayabilirsiniz (aslında bir düzenli kullanıcıdan bu mümkün olmayabilir, çünkü bir `.app` paketi içine yazmak ve bir kütüphaneyi kaçırmak için bir TCC iznine ihtiyacınız olabilir).\
Ancak, MacOS uygulamalarının kütüphaneleri yükleme şekli Windows'tan daha kısıtlıdır. Bu, **kötü amaçlı yazılım** geliştiricilerinin bu tekniği **gizlilik** için kullanabileceği ancak **bu kullanarak ayrıcalıkları yükseltmeyi kötüye kullanma olasılığının çok daha düşük olduğu anlamına gelir**.

Öncelikle, **MacOS ikili dosyalarının kütüphaneleri yüklemek için tam yolunu belirttiğini** görmek **daha yaygındır**. İkinci olarak, **MacOS asla** kütüphaneler için **$PATH** klasörlerinde arama yapmaz.

Bu işlevselliğe ilişkin **ana** kod parçası, `ImageLoader.cpp` içindeki **`ImageLoader::recursiveLoadLibraries`** işlevindedir.

Bir macho ikili dosyanın yüklemek için kullanabileceği **4 farklı başlık Komutu** vardır:

* **`LC_LOAD_DYLIB`** komutu bir dylib yüklemek için yaygın bir komuttur.
* **`LC_LOAD_WEAK_DYLIB`** komutu öncekiyle aynı şekilde çalışır, ancak dylib bulunamazsa, herhangi bir hata olmadan yürütme devam eder.
* **`LC_REEXPORT_DYLIB`** komutu sembolleri başka bir kütüphaneden proxy (veya yeniden ihraç) eder.
* **`LC_LOAD_UPWARD_DYLIB`** komutu birbirlerine bağımlı iki kütüphane olduğunda kullanılır (buna _yukarı bağımlılık_ denir).

Ancak, **2 tür dylib kaçırma** vardır:

* **Zayıf bağlantılı kütüphanelerin eksik olması**: Bu, uygulamanın **LC\_LOAD\_WEAK\_DYLIB** ile yapılandırılmış olmayan bir kütüphaneyi yüklemeye çalışacağı anlamına gelir. Sonra, **saldırgan bir dylib'i beklenen yere yerleştirirse yüklenecektir**.
* Bağlantının "zayıf" olduğu gerçeği, uygulamanın kütüphanenin bulunamaması durumunda çalışmaya devam edeceği anlamına gelir.
* Bu işle ilgili **kod**, `ImageLoaderMachO.cpp`'deki `ImageLoaderMachO::doGetDependentLibraries` işlevindedir, burada `lib->required` yalnızca `LC_LOAD_WEAK_DYLIB` doğru olduğunda `false` olur.
* **Zayıf bağlantılı kütüphaneleri** aşağıdaki gibi ikililerde bulabilirsiniz (kütüphane kaçırma kütüphaneleri oluşturma örneğine daha sonra bakacaksınız):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **@rpath ile yapılandırılmış**: Mach-O ikili dosyaları **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** komutlarına sahip olabilir. Bu komutların **değerlerine** bağlı olarak, kütüphaneler **farklı dizinlerden** yüklenecektir.
* **`LC_RPATH`**, ikilinin kütüphaneleri yüklemek için kullandığı bazı klasörlerin yollarını içerir.
* **`LC_LOAD_DYLIB`** belirli kütüphaneleri yüklemek için yol içerir. Bu yollar **`@rpath`** içerebilir, bu değerlerle **`LC_RPATH`** içindeki değerlerle **değiştirilecektir**. Eğer **`LC_RPATH`** içinde birden fazla yol varsa, her biri yüklemek için kullanılacaktır. Örnek:
* Eğer **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyorsa ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ve `/application/app.app/Contents/Framework/v2/` içeriyorsa. Her iki klasör de `library.dylib`'i yüklemek için kullanılacaktır. Eğer kütüphane `[...]/v1/` içinde bulunmuyorsa ve saldırgan onu oraya yerleştirebilirse, kütüphanenin yüklenmesini `[...]/v2/` içindeki kütüphanenin yüklenmesini ele geçirmek için kullanabilir, çünkü **`LC_LOAD_DYLIB`** içindeki yol sırası takip edilir.
* **Binarylerde rpath yollarını ve kütüphaneleri** bulmak için: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: **Ana yürütülebilir dosya**yı içeren dizinin **yolu**dur.

**`@loader_path`**: **Yük komutunu içeren Mach-O binary**'nin bulunduğu **dizin**in yolu.

* Bir yürütülebilir dosyada kullanıldığında, **`@loader_path`** etkili bir şekilde **`@executable_path`** ile **aynıdır**.
* Bir **dylib**'de kullanıldığında, **`@loader_path`** **dylib**'in yolunu verir.
{% endhint %}

Bu işlevselliği **istismar ederek ayrıcalıkları yükseltmenin** yolu, nadir bir durumda **kök** tarafından **çalıştırılan bir uygulamanın**, saldırganın yazma izinlerine sahip olduğu bir klasördeki bazı **kütüphaneyi aradığı** durumdur.

{% hint style="success" %}
Uygulamalardaki **eksik kütüphaneleri bulmak** için güzel bir **tarama aracı** [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bir [**CLI sürümü**](https://github.com/pandazheng/DylibHijack) bulunabilir.\
Bu teknik hakkında teknik detaylar içeren güzel bir **rapor** [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.
{% endhint %}

**Örnek**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
**Dlopen** hile saldırıları gerçekleştirmek için **önceki Kütüphane Doğrulama** kısıtlamalarını da hatırlayın.
{% endhint %}

**`man dlopen`**'dan:

* Yol **eğik çizgi karakteri içermiyorsa** (yani sadece bir yaprak adı ise), **dlopen() arama yapacaktır**. Eğer başlangıçta **`$DYLD_LIBRARY_PATH`** ayarlanmışsa, dyld önce o dizinde bakacaktır. Sonra, çağıran mach-o dosyası veya ana yürütülebilir dosya bir **`LC_RPATH`** belirtiyorsa, dyld o dizinlere bakacaktır. Sonra, işlem **kısıtlanmamışsa**, dyld **mevcut çalışma dizininde** arayacaktır. Son olarak, eski binaryler için dyld bazı yedek aramalar yapacaktır. Eğer başlangıçta **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa, dyld o dizinlerde arayacaktır, aksi takdirde dyld **`/usr/local/lib/`**'de (işlem kısıtlanmamışsa) ve ardından **`/usr/lib/`**'de bakacaktır (bu bilgi **`man dlopen`**'dan alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (kısıtlanmamışsa)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (kısıtlanmamışsa)
6. `/usr/lib/`

{% hint style="danger" %}
İsimde eğik çizgi yoksa, bir hile yapmanın 2 yolu olabilir:

* Eğer herhangi bir **`LC_RPATH`** **yazılabilirse** (ancak imza kontrol edilir, bu nedenle bunun için binary'nin de kısıtlanmamış olması gerekir)
* Eğer binary **kısıtlanmamışsa** ve ardından CWD'den bir şey yüklemek mümkün olabilir (veya belirtilen ortam değişkenlerinden birini kötüye kullanmak)
{% endhint %}

* Yol **bir çerçeve yolu gibi görünüyorsa** (örneğin `/stuff/foo.framework/foo`), başlangıçta **`$DYLD_FRAMEWORK_PATH`** ayarlanmışsa, dyld önce o dizinde **çerçeve kısmi yolunu** (örneğin `foo.framework/foo`) arayacaktır. Sonra, dyld **verilen yolu olduğu gibi deneyecektir** (ilişkisel yollar için mevcut çalışma dizinini kullanarak). Son olarak, eski binaryler için dyld bazı yedek aramalar yapacaktır. Eğer başlangıçta **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlanmışsa, dyld o dizinlerde arayacaktır. Aksi takdirde, **`/Library/Frameworks`**'de (macOS'ta işlem kısıtlanmamışsa), ardından **`/System/Library/Frameworks`**'de arayacaktır.
1. `$DYLD_FRAMEWORK_PATH`
2. verilen yol (ilişkisel yollar için mevcut çalışma dizinini kullanarak kısıtlanmamışsa)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (kısıtlanmamışsa)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Bir çerçeve yolu ise, bunu ele geçirmenin yolu şöyle olacaktır:

* İşlem **kısıtlanmamışsa**, CWD'den **ilişkisel yol**u kötüye kullanmak, belirtilen ortam değişkenleri (eğer belgelerde işlem kısıtlıysa DYLD\_\* ortam değişkenleri kaldırılır denilmediği için)
{% endhint %}

* Yol **eğik çizgi içeriyorsa ancak bir çerçeve yolu değilse** (yani bir dylib için tam yol veya kısmi yol), dlopen() önce (ayarlanmışsa) **`$DYLD_LIBRARY_PATH`**'de (yolun yaprak kısmıyla) bakacaktır. Sonra, dyld **verilen yolu deneyecektir** (ilişkisel yollar için mevcut çalışma dizinini kullanarak (ancak sadece kısıtlanmamış işlemler için)). Son olarak, eski binaryler için dyld bazı yedek aramalar yapacaktır. Eğer başlangıçta **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlanmışsa, dyld o dizinlerde arayacaktır, aksi takdirde dyld **`/usr/local/lib/`**'de (işlem kısıtlanmamışsa) ve ardından **`/usr/lib/`**'de bakacaktır.
1. `$DYLD_LIBRARY_PATH`
2. verilen yol (ilişkisel yollar için mevcut çalışma dizinini kullanarak kısıtlanmamışsa)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (kısıtlanmamışsa)
5. `/usr/lib/`

{% hint style="danger" %}
İsimde eğik çizgi varsa ve bir çerçeve değilse, bunu ele geçirmenin yolu şöyle olacaktır:

* Eğer binary **kısıtlanmamışsa** ve ardından CWD'den veya `/usr/local/lib`'den bir şey yüklemek mümkün olabilir (veya belirtilen ortam değişkenlerinden birini kötüye kullanmak)
{% endhint %}

{% hint style="info" %}
Not: **Dlopen aramalarını kontrol etmek** için **yapılandırma dosyaları yoktur**.

Not: Ana yürütülebilir dosya **set\[ug]id binary veya ayrıcalıklarla kod imzalanmışsa**, o zaman **tüm ortam değişkenleri yok sayılır** ve yalnızca tam yol kullanılabilir (daha detaylı bilgi için [DYLD\_INSERT\_LIBRARIES kısıtlamalarını kontrol edin](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions)).

Not: Apple platformları, 32-bit ve 64-bit kütüphaneleri birleştirmek için "evrensel" dosyalar kullanır. Bu, **ayrı 32-bit ve 64-bit arama yollarının olmadığı anlamına gelir**.

Not: Apple platformlarında çoğu OS dylib'leri **dyld önbelleğine** birleştirilir ve diskte mevcut değildir. Bu nedenle, bir OS dylib'in var olup olmadığını ön izlemek için **`stat()`** çağrısı yapmak **çalışmaz**. Bununla birlikte, **`dlopen()`** aynı adımları kullanarak uyumlu bir mach-o dosyası bulmak için **`dlopen_preflight()`**'ı kullanır.
{% endhint %}

**Yolları Kontrol Et**

Tüm seçenekleri aşağıdaki kodla kontrol edelim:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Eğer derlersen ve çalıştırırsan, **her kütüphane nerede başarısız bir şekilde arandığını görebilirsin**. Ayrıca, **FS günlüklerini filtreleyebilirsin**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Göreceli Yol Kaçırma

Eğer bir **ayrıcalıklı ikili/uygulama** (örneğin SUID veya güçlü yetkilendirmelere sahip bir ikili) bir **göreceli yol** kütüphanesini yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Kütüphane Doğrulaması devre dışı bırakılmışsa**, saldırganın ikiliyi, saldırganın kod enjekte etmesi için kütüphanenin yüklendiği göreceli yolu değiştirebileceği ve kötüye kullanabileceği mümkün olabilir.

## `DYLD_*` ve `LD_LIBRARY_PATH` çevresel değişkenlerini Temizle

`dyld-dyld-832.7.1/src/dyld2.cpp` dosyasında **`pruneEnvironmentVariables`** işlevini bulmak mümkündür, bu işlev **`DYLD_` ile başlayan** ve **`LD_LIBRARY_PATH=`** ile başlayan herhangi bir çevresel değişkeni kaldıracaktır.

Ayrıca, **suid** ve **sgid** ikililer için özellikle **`DYLD_FALLBACK_FRAMEWORK_PATH`** ve **`DYLD_FALLBACK_LIBRARY_PATH`** çevresel değişkenlerini **null** olarak ayarlayacaktır.

Bu işlev, OSX hedefleniyorsa aynı dosyanın **`_main`** işlevinden şu şekilde çağrılır:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
ve bu boolean bayrakları kod içinde aynı dosyada ayarlanır:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Bu temelde, eğer ikili dosya **suid** veya **sgid** ise, başlıkta bir **RESTRICT** segmenti bulunuyorsa veya **CS\_RESTRICT** bayrağı ile imzalanmışsa, o zaman **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** doğru olacak ve çevre değişkenleri budanacak.

CS\_REQUIRE\_LV doğruysa, değişkenler budanmayacak ancak kütüphane doğrulaması, bunların orijinal ikili dosya ile aynı sertifikayı kullandığını kontrol edecek.

## Kısıtlamaları Kontrol Et

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Bölüm `__RESTRICT` ile segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Güçlendirilmiş çalışma zamanı

Anahtarlıkta yeni bir sertifika oluşturun ve bunu ikili dosyaya imzalamak için kullanın:

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Not edin ki, baytlarla imzalanmış ikili dosyalar olsa bile, yürütüldüğünde **`CS_RESTRICT`** bayrağını dinamik olarak alabilirler ve bu nedenle bu teknik onlarda çalışmayacaktır.

Bu bayrağa sahip bir işlemin olup olmadığını kontrol edebilirsiniz ([buradan csops alın](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
ve ardından bayrağın 0x800 etkin olup olmadığını kontrol edin.
{% endhint %}

## Referanslar

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
