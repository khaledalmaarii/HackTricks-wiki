# macOS Kütüphane Enjeksiyonu

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

{% hint style="danger" %}
**dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve **şu URL gibi** bir tar ile indirilebilir: [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Dyld Süreci**

Dyld'in ikili dosyalar içinde kütüphaneleri nasıl yüklediğine bir göz atın:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

Bu, [**Linux'taki LD\_PRELOAD**](../../../../linux-hardening/privilege-escalation/#ld\_preload) gibidir. Bir sürecin çalıştırılacağını belirtmek için belirli bir kütüphaneyi bir yoldan yüklemesine izin verir (eğer env değişkeni etkinse).

Bu teknik ayrıca, her kurulu uygulamanın "Info.plist" adında bir plist'e sahip olması nedeniyle **ASEP tekniği olarak da kullanılabilir**; bu, `LSEnvironmental` adında bir anahtar kullanarak **çevresel değişkenlerin atanmasına** izin verir.

{% hint style="info" %}
2012'den beri **Apple, `DYLD_INSERT_LIBRARIES`** gücünü önemli ölçüde azaltmıştır.

Koda gidin ve **`src/dyld.cpp`** dosyasını kontrol edin. **`pruneEnvironmentVariables`** fonksiyonunda **`DYLD_*`** değişkenlerinin kaldırıldığını görebilirsiniz.

**`processRestricted`** fonksiyonunda kısıtlamanın nedeni belirlenir. O kodu kontrol ettiğinizde nedenlerin şunlar olduğunu görebilirsiniz:

* İkili dosya `setuid/setgid`
* Macho ikili dosyasında `__RESTRICT/__restrict` bölümünün varlığı.
* Yazılımın [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) yetkisi olmadan yetkilere sahip olması (hardened runtime)
* Bir ikilinin **yetkilerini** kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`

Daha güncel sürümlerde bu mantığı **`configureProcessRestrictions`** fonksiyonunun ikinci kısmında bulabilirsiniz. Ancak, daha yeni sürümlerde yürütülen şey, fonksiyonun **başlangıç kontrolleridir** (iOS veya simülasyonla ilgili if'leri kaldırabilirsiniz çünkü bunlar macOS'ta kullanılmayacaktır).
{% endhint %}

### Kütüphane Doğrulaması

İkili dosya **`DYLD_INSERT_LIBRARIES`** env değişkenini kullanmaya izin verse bile, eğer ikili dosya yüklenecek kütüphanenin imzasını kontrol ediyorsa, özel bir kütüphaneyi yüklemeyecektir.

Özel bir kütüphaneyi yüklemek için, ikili dosyanın **aşağıdaki yetkilerden birine** sahip olması gerekir:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ya da ikili dosya **hardened runtime bayrağına** veya **kütüphane doğrulama bayrağına** sahip **olmamalıdır**.

Bir ikilinin **hardened runtime** olup olmadığını `codesign --display --verbose <bin>` ile kontrol edebilirsiniz; **`CodeDirectory`** içinde runtime bayrağını kontrol ederek: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca, bir kütüphaneyi **ikili dosyayla aynı sertifika ile imzalanmışsa** yükleyebilirsiniz.

Bunu (kötüye) kullanma ve kısıtlamaları kontrol etme örneğini bulabilirsiniz:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Ele Geçirme

{% hint style="danger" %}
Unutmayın ki **önceki Kütüphane Doğrulama kısıtlamaları da** Dylib ele geçirme saldırılarını gerçekleştirmek için geçerlidir.
{% endhint %}

Windows'ta olduğu gibi, MacOS'ta da **dylib'leri ele geçirebilirsiniz** ve **uygulamaların** **keyfi** **kod** **çalıştırmasını** sağlayabilirsiniz (aslında, normal bir kullanıcıdan bu mümkün olmayabilir çünkü bir `.app` paketinin içine yazmak için bir TCC iznine ihtiyacınız olabilir ve bir kütüphaneyi ele geçirebilirsiniz).\
Ancak, **MacOS** uygulamalarının kütüphaneleri **yükleme şekli**, Windows'tan **daha kısıtlıdır**. Bu, **kötü amaçlı yazılım** geliştiricilerinin bu tekniği **gizlilik** için kullanabileceği anlamına gelir, ancak **yetki yükseltmek için bunu kötüye kullanma olasılığı çok daha düşüktür**.

Öncelikle, **MacOS ikililerinin kütüphaneleri yüklemek için tam yolu belirtmesi** daha yaygındır. İkincisi, **MacOS asla** kütüphaneler için **$PATH** klasörlerinde arama yapmaz.

Bu işlevselliğe ilişkin **kodun** ana kısmı **`ImageLoader::recursiveLoadLibraries`** içinde `ImageLoader.cpp` dosyasındadır.

Bir macho ikili dosyasının kütüphaneleri yüklemek için kullanabileceği **4 farklı başlık Komutu** vardır:

* **`LC_LOAD_DYLIB`** komutu, bir dylib yüklemek için yaygın komuttur.
* **`LC_LOAD_WEAK_DYLIB`** komutu, önceki gibi çalışır, ancak dylib bulunamazsa, yürütme hatasız devam eder.
* **`LC_REEXPORT_DYLIB`** komutu, farklı bir kütüphaneden sembolleri proxy'ler (veya yeniden ihraç eder).
* **`LC_LOAD_UPWARD_DYLIB`** komutu, iki kütüphanenin birbirine bağımlı olduğu durumlarda kullanılır (bu, _yukarı bağımlılık_ olarak adlandırılır).

Ancak, **2 tür dylib ele geçirme** vardır:

* **Eksik zayıf bağlantılı kütüphaneler**: Bu, uygulamanın **LC\_LOAD\_WEAK\_DYLIB** ile yapılandırılmış bir kütüphaneyi yüklemeye çalışacağı anlamına gelir. Sonra, **bir saldırgan beklenen yere bir dylib yerleştirirse, yüklenir**.
* Bağlantının "zayıf" olması, kütüphane bulunmasa bile uygulamanın çalışmaya devam edeceği anlamına gelir.
* Bununla ilgili **kod**, `ImageLoaderMachO::doGetDependentLibraries` fonksiyonundadır; burada `lib->required` yalnızca `LC_LOAD_WEAK_DYLIB` doğru olduğunda `false` olur.
* **Zayıf bağlantılı kütüphaneleri** ikililerde bulmak için (daha sonra ele geçirme kütüphaneleri oluşturma örneğiniz var):
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **@rpath ile yapılandırılmış**: Mach-O ikili dosyaları **`LC_RPATH`** ve **`LC_LOAD_DYLIB`** komutlarına sahip olabilir. Bu komutların **değerlerine** dayanarak, **kütüphaneler** **farklı dizinlerden** **yüklenir**.
* **`LC_RPATH`**, ikili dosya tarafından kütüphaneleri yüklemek için kullanılan bazı klasörlerin yollarını içerir.
* **`LC_LOAD_DYLIB`**, yüklenmesi gereken belirli kütüphanelerin yolunu içerir. Bu yollar **`@rpath`** içerebilir; bu, **`LC_RPATH`** içindeki değerlerle **değiştirilecektir**. **`LC_RPATH`** içinde birden fazla yol varsa, her biri yüklenmesi gereken kütüphaneyi aramak için kullanılacaktır. Örnek:
* Eğer **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyorsa ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ve `/application/app.app/Contents/Framework/v2/` içeriyorsa. Her iki klasör de `library.dylib` yüklemek için kullanılacaktır. Eğer kütüphane `[...]/v1/` içinde yoksa, bir saldırgan oraya yerleştirerek `[...]/v2/` içindeki kütüphanenin yüklenmesini ele geçirebilir; çünkü **`LC_LOAD_DYLIB`** içindeki yolların sırası takip edilir.
* **Rpath yollarını ve kütüphaneleri** ikililerde bulmak için: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: **Ana yürütülebilir dosyanın** bulunduğu dizinin **yoludur**.

**`@loader_path`**: **Yükleme komutunu içeren** **Mach-O ikili dosyasının** bulunduğu **dizinin yoludur**.

* Bir yürütülebilir dosyada kullanıldığında, **`@loader_path`** etkili bir şekilde **`@executable_path`** ile **aynıdır**.
* Bir **dylib** içinde kullanıldığında, **`@loader_path`** **dylib'in** **yolunu** verir.
{% endhint %}

Bu işlevselliği kötüye kullanarak **yetki yükseltmenin** yolu, **root** tarafından **çalıştırılan** bir **uygulamanın**, **saldırganın yazma izinlerine sahip olduğu bir klasörde** bazı **kütüphaneleri arıyor olması** durumunda olacaktır.

{% hint style="success" %}
Uygulamalardaki **eksik kütüphaneleri** bulmak için güzel bir **tarayıcı** [**Dylib Hijack Tarayıcı**](https://objective-see.com/products/dhs.html) veya bir [**CLI versiyonu**](https://github.com/pandazheng/DylibHijack) vardır.\
Bu teknikle ilgili **teknik detaylar** içeren güzel bir **rapor** [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.
{% endhint %}

**Örnek**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Ele Geçirme

{% hint style="danger" %}
Unutmayın ki **önceki Kütüphane Doğrulama kısıtlamaları da** Dlopen ele geçirme saldırılarını gerçekleştirmek için geçerlidir.
{% endhint %}

**`man dlopen`**'dan:

* Yol **bir eğik çizgi karakteri** içermiyorsa (yani sadece bir yaprak adıysa), **dlopen() arama yapacaktır**. Eğer **`$DYLD_LIBRARY_PATH`** başlatıldığında ayarlandıysa, dyld önce **o dizinde** **bakacaktır**. Sonra, eğer çağrılan mach-o dosyası veya ana yürütülebilir dosya bir **`LC_RPATH`** belirtiyorsa, dyld **o dizinlerde** **bakacaktır**. Sonra, eğer süreç **kısıtlı değilse**, dyld **geçerli çalışma dizininde** arama yapacaktır. Son olarak, eski ikililer için, dyld bazı yedeklemeleri deneyecektir. Eğer **`$DYLD_FALLBACK_LIBRARY_PATH`** başlatıldığında ayarlandıysa, dyld **o dizinlerde** arama yapacaktır, aksi takdirde dyld **`/usr/local/lib/`** (eğer süreç kısıtlı değilse) ve sonra **`/usr/lib/`** içinde arama yapacaktır (bu bilgi **`man dlopen`**'dan alınmıştır).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(eğer kısıtlı değilse)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (eğer kısıtlı değilse)
6. `/usr/lib/`

{% hint style="danger" %}
Eğer isimde eğik çizgi yoksa, ele geçirme yapmak için 2 yol olacaktır:

* Eğer herhangi bir **`LC_RPATH`** **yazılabilir** ise (ancak imza kontrol edilir, bu nedenle bunun için ikilinin de kısıtlı olmaması gerekir)
* Eğer ikili dosya **kısıtlı değilse** ve o zaman CWD'den bir şey yüklemek mümkünse (veya bahsedilen env değişkenlerinden birini kötüye kullanarak)
{% endhint %}

* Yol **bir çerçeve** yolu gibi görünüyorsa (örneğin, `/stuff/foo.framework/foo`), eğer **`$DYLD_FRAMEWORK_PATH`** başlatıldığında ayarlandıysa, dyld önce o dizinde **çerçeve kısmi yolunu** (örneğin, `foo.framework/foo`) arayacaktır. Sonra, dyld **sağlanan yolu olduğu gibi** deneyecektir (göreli yollar için geçerli çalışma dizinini kullanarak). Son olarak, eski ikililer için, dyld bazı yedeklemeleri deneyecektir. Eğer **`$DYLD_FALLBACK_FRAMEWORK_PATH`** başlatıldığında ayarlandıysa, dyld o dizinlerde arama yapacaktır. Aksi takdirde, **`/Library/Frameworks`** (macOS'ta eğer süreç kısıtlı değilse) ve sonra **`/System/Library/Frameworks`** içinde arama yapacaktır.
1. `$DYLD_FRAMEWORK_PATH`
2. sağlanan yol (eğer kısıtlı değilse göreli yollar için geçerli çalışma dizinini kullanarak)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (eğer kısıtlı değilse)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Eğer bir çerçeve yolu ise, ele geçirme yolu şöyle olacaktır:

* Eğer süreç **kısıtlı değilse**, bahsedilen env değişkenlerinden **CWD'den göreli yolu** kötüye kullanarak (belgelere göre süreç kısıtlıysa DYLD\_\* env değişkenleri kaldırılır)
{% endhint %}

* Yol **bir eğik çizgi içeriyorsa ancak bir çerçeve yolu değilse** (yani bir tam yol veya bir dylib'e giden kısmi yol), dlopen() önce (eğer ayarlandıysa) **`$DYLD_LIBRARY_PATH`** içinde (yolun yaprak kısmıyla) arar. Sonra, dyld **sağlanan yolu** dener (geçerli çalışma dizinini göreli yollar için kullanarak (ancak yalnızca kısıtlı olmayan süreçler için)). Son olarak, eski ikililer için, dyld yedeklemeleri deneyecektir. Eğer **`$DYLD_FALLBACK_LIBRARY_PATH`** başlatıldığında ayarlandıysa, dyld o dizinlerde arama yapacaktır, aksi takdirde dyld **`/usr/local/lib/`** (eğer süreç kısıtlı değilse) ve sonra **`/usr/lib/`** içinde arama yapacaktır.
1. `$DYLD_LIBRARY_PATH`
2. sağlanan yol (eğer kısıtlı değilse göreli yollar için geçerli çalışma dizinini kullanarak)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (eğer kısıtlı değilse)
5. `/usr/lib/`

{% hint style="danger" %}
Eğer isimde eğik çizgiler varsa ve çerçeve değilse, ele geçirme yolu şöyle olacaktır:

* Eğer ikili dosya **kısıtlı değilse** ve o zaman CWD'den veya `/usr/local/lib`'den bir şey yüklemek mümkünse (veya bahsedilen env değişkenlerinden birini kötüye kullanarak)
{% endhint %}

{% hint style="info" %}
Not: **dlopen aramasını kontrol etmek için** **hiçbir** yapılandırma dosyası yoktur.

Not: Eğer ana yürütülebilir dosya bir **set\[ug]id ikilisi veya yetkilerle kod imzalanmışsa**, o zaman **tüm çevresel değişkenler yok sayılır** ve yalnızca tam yol kullanılabilir ([daha fazla bilgi için DYLD\_INSERT\_LIBRARIES kısıtlamalarını kontrol edin](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions))

Not: Apple platformları, 32 bit ve 64 bit kütüphaneleri birleştirmek için "evrensel" dosyalar kullanır. Bu, **ayrı 32 bit ve 64 bit arama yolları** olmadığı anlamına gelir.

Not: Apple platformlarında çoğu OS dylib **dyld önbelleğine** **birleştirilmiştir** ve disk üzerinde mevcut değildir. Bu nedenle, bir OS dylib'in var olup olmadığını önceden kontrol etmek için **`stat()`** çağrısı **çalışmaz**. Ancak, **`dlopen_preflight()`**, uyumlu bir mach-o dosyasını bulmak için **`dlopen()`** ile aynı adımları kullanır.
{% endhint %}

**Yolları Kontrol Et**

Aşağıdaki kod ile tüm seçenekleri kontrol edelim:
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
Eğer bunu derleyip çalıştırırsanız, **her bir kütüphanenin nerede başarısız bir şekilde arandığını** görebilirsiniz. Ayrıca, **FS günlüklerini filtreleyebilirsiniz**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Göreli Yol Kaçırma

Eğer bir **yetkili ikili/uygulama** (örneğin bir SUID veya güçlü yetkilere sahip bir ikili) **göreli yol** kütüphanesi yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Kütüphane Doğrulaması devre dışıysa**, saldırganın **göreli yol yüklü kütüphaneyi** değiştirebileceği bir konuma ikiliyi taşıması mümkün olabilir ve bunu süreci kod enjekte etmek için kötüye kullanabilir.

## `DYLD_*` ve `LD_LIBRARY_PATH` çevre değişkenlerini temizle

`dyld-dyld-832.7.1/src/dyld2.cpp` dosyasında **`pruneEnvironmentVariables`** fonksiyonunu bulmak mümkündür; bu fonksiyon **`DYLD_`** ile başlayan ve **`LD_LIBRARY_PATH=`** olan herhangi bir çevre değişkenini kaldıracaktır.

Ayrıca, **suid** ve **sgid** ikilileri için **`DYLD_FALLBACK_FRAMEWORK_PATH`** ve **`DYLD_FALLBACK_LIBRARY_PATH`** çevre değişkenlerini **null** olarak ayarlayacaktır.

Bu fonksiyon, OSX hedef alındığında aynı dosyanın **`_main`** fonksiyonundan şu şekilde çağrılır:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
ve bu boolean bayrakları koddaki aynı dosyada ayarlanır:
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
Hangi, temelde, eğer ikili **suid** veya **sgid** ise, veya başlıklarda bir **RESTRICT** segmenti varsa ya da **CS\_RESTRICT** bayrağı ile imzalanmışsa, o zaman **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** doğru ve env değişkenleri temizlenir.

CS\_REQUIRE\_LV doğruysa, o zaman değişkenler temizlenmeyecek ancak kütüphane doğrulaması, bunların orijinal ikili ile aynı sertifikayı kullandığını kontrol edecektir.

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
### Section `__RESTRICT` with segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardenilmiş çalışma zamanı

Anahtar Zinciri'nde yeni bir sertifika oluşturun ve bunu ikili dosyayı imzalamak için kullanın:

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
Dikkat edin ki, **`0x0(none)`** bayraklarıyla imzalanmış ikili dosyalar olsa bile, çalıştırıldıklarında dinamik olarak **`CS_RESTRICT`** bayrağını alabilirler ve bu nedenle bu teknik onlarda çalışmayacaktır.

Bir işlemin bu bayrağa sahip olup olmadığını kontrol edebilirsiniz (get [**csops burada**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
ve ardından 0x800 bayrağının etkin olup olmadığını kontrol edin.
{% endhint %}

## Referanslar

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS İç Yapıları, Cilt I: Kullanıcı Modu. Jonathan Levin tarafından**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
