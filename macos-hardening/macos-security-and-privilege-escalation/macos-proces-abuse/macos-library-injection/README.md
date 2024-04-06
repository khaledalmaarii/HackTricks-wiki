# macOS Library Injection

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud github depolarına **PR göndererek** hilelerinizi paylaşın.

</details>

{% hint style="danger" %}
**dyld kodu açık kaynaklıdır** ve [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) adresinde bulunabilir ve **URL kullanarak** bir tar indirilebilir, örneğin [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Bu, [**LD\_PRELOAD Linux'ta**](../../../../linux-hardening/privilege-escalation/#ld\_preload) olduğu gibi bir işlemi belirli bir kütüphaneyi bir yol üzerinden yüklemek için çalıştırmak için kullanılır (eğer env değişkeni etkinse).

Bu teknik ayrıca her uygulamanın "Info.plist" adlı bir plist dosyasına sahip olduğu ve `LSEnvironmental` adlı bir anahtar kullanarak çevresel değişkenlerin atanmasına izin veren bir ASEP tekniği olarak da kullanılabilir.

{% hint style="info" %}
2012'den beri **Apple, DYLD\_INSERT\_LIBRARIES'nin gücünü önemli ölçüde azaltmıştır**.

Koda gidin ve **`src/dyld.cpp`'yi kontrol edin**. **`pruneEnvironmentVariables`** işlevinde **`DYLD_*`** değişkenlerinin kaldırıldığını görebilirsiniz.

**`processRestricted`** işlevinde kısıtlamanın nedeni belirlenir. Bu kodu kontrol ettiğinizde nedenlerin şunlar olduğunu görebilirsiniz:

* İkili dosya `setuid/setgid` özelliğine sahip
* Macho ikili dosyada `__RESTRICT/__restrict` bölümünün varlığı.
* Yazılımın [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables) yetkisi olmadan yetkilendirmeleri (güçlendirilmiş çalışma zamanı) var
* Bir ikilinin yetkilendirmelerini şu komutla kontrol edin: `codesign -dv --entitlements :- </path/to/bin>`

Daha güncel sürümlerde bu mantığı **`configureProcessRestrictions`** işlevinin ikinci kısmında bulabilirsiniz. Ancak, daha yeni sürümlerde çalıştırılan şey, işlevle ilgili başlangıç kontrolleridir (iOS veya simülasyonla ilgili olanları macOS'ta kullanılmayacağından ilgili if'leri kaldırabilirsiniz.
{% endhint %}

### Kütüphane Doğrulama

İkili dosya **`DYLD_INSERT_LIBRARIES`** env değişkenini kullanmaya izin verirse bile, ikili dosya kütüphanenin imzasını kontrol ederse özel bir kütüphane yüklemeyecektir.

Özel bir kütüphane yüklemek için, ikili dosyanın aşağıdaki yetkilendirmelerden birine sahip olması gerekir:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

veya ikili dosyanın **güçlendirilmiş çalışma zamanı bayrağı** veya **kütüphane doğrulama bayrağı** olmaması gerekir.

Bir ikili dosyanın **güçlendirilmiş çalışma zamanı** olup olmadığını `codesign --display --verbose <bin>` komutuyla kontrol edebilirsiniz ve **`CodeDirectory`** içindeki bayrak çalışma zamanını kontrol edebilirsiniz, örneğin: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Ayrıca, bir kütüphane, ikili dosya ile aynı sertifika ile imzalanmışsa yüklenebilir.

Bunu (kötüye kullanmak) nasıl yapacağınızı ve kısıtlamaları kontrol etmek için aşağıdaki bağlantıya bakın:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylib Kaçırma

{% hint style="danger" %}
Dylib kaçırma saldırıları için **önceki Kütüphane Doğrulama kısıtlamalarını da unutmayın**.
{% endhint %}

Windows'ta olduğu gibi, MacOS'ta da **dylib kaçırabilirsiniz** ve **uygulamaların** **keyfi kod** **çalıştırmasını sağlayabilirsiniz** (aslında bir düzenli kullanıcı olarak bunun mümkün olmayabilir, çünkü bir `.app` paketi içine yazmak ve bir kütüphane kaçırmak için bir TCC iznine ihtiyacınız olabilir).\
Ancak, MacOS uygulamalarının kütüphaneleri yükleme şekli Windows'tan daha kısıtlıdır. Bu, **kötü amaçlı yazılım** geliştiricilerinin bu tekniği **gizlilik** için hala kullanabileceği anlamına gelir, ancak ayrıcalıkları yükseltmek için bunu kullanabilme olasılığı çok daha düşüktür.

Öncelikle, MacOS ikili dosyalarının genellikle kütüphaneleri yüklemek için **tam yolunu belirttiğini** görmek **daha yaygındır**. İkinci olarak, MacOS kütüphaneleri **$PATH** klasörlerinde aramaz.

Bu işlevselliğe ilişkin **ana kod parçası**, `ImageLoader.cpp` içindeki \*\*\`ImageLoader::recursive

* Eğer **`LC_LOAD_DYLIB`** `@rpath/library.dylib` içeriyorsa ve **`LC_RPATH`** `/application/app.app/Contents/Framework/v1/` ve `/application/app.app/Contents/Framework/v2/` içeriyorsa, her iki klasör de `library.dylib`'i yüklemek için kullanılacak. Eğer kütüphane `[...]/v1/` içinde bulunmuyorsa ve saldırgan onu `[...]/v2/` içine yerleştirebilirse, **`LC_LOAD_DYLIB`** içindeki yol sırasına göre `library.dylib`'in yüklenmesini ele geçirebilir.
* **Rpath yollarını ve kütüphaneleri** şu komutla ikili dosyalarda bulun: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Ana yürütülebilir dosyanın bulunduğu dizinin **yolu**.

**`@loader_path`**: Yükleme komutunu içeren **Mach-O ikili dosyasının bulunduğu dizinin yolu**.

* Bir yürütülebilir dosyada kullanıldığında, **`@loader_path`**, **`@executable_path`** ile **aynıdır**.
* Bir **dylib** içinde kullanıldığında, **`@loader_path`**, **dylib**'in yolunu verir.
{% endhint %}

Bu işlevselliği kötüye kullanarak **ayrıcalıkları yükseltme** yolunun, **kök** tarafından \*\*çalıştırılan bir uygulamanın, saldırganın yazma izinlerine sahip olduğu bir klasördeki bir kütüphaneyi aradığı nadir bir durumda olmasıdır.

{% hint style="success" %}
Uygulamalardaki **eksik kütüphaneleri** bulmak için güzel bir **tarama aracı**, [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) veya bir [**CLI sürümü**](https://github.com/pandazheng/DylibHijack) kullanılabilir.\
Bu teknikle ilgili teknik ayrıntıları içeren güzel bir **rapor**, [**burada**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) bulunabilir.
{% endhint %}

**Örnek**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Dlopen hijacking saldırılarını gerçekleştirmek için **önceki Kütüphane Doğrulama kısıtlamalarını da hatırlayın**.
{% endhint %}

**`man dlopen`**'dan:

* Yol **eğik çizgi karakteri içermiyorsa** (yani sadece bir yaprak adı ise), **dlopen() arama yapar**. Eğer başlangıçta **`$DYLD_LIBRARY_PATH`** ayarlandıysa, dyld önce **o dizinde arar**. Ardından, çağıran mach-o dosyası veya ana yürütülebilir dosya bir **`LC_RPATH`** belirtiyorsa, dyld **o dizinlere bakar**. Sonra, işlem **kısıtlamasız** ise, dyld **mevcut çalışma dizininde** arar. Son olarak, eski ikili dosyalar için dyld bazı yedekler dener. Eğer başlangıçta **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlandıysa, dyld **o dizinlerde arar**, aksi takdirde dyld **`/usr/local/lib/`**'de (işlem kısıtlamasız ise) ve ardından **`/usr/lib/`**'de arar (bu bilgi **`man dlopen`**'dan alınmıştır).

1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (kısıtlamasız ise)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (kısıtlamasız ise)
6. `/usr/lib/`

{% hint style="danger" %}
Eğer adında eğik çizgi yoksa, bir hijacking yapmanın 2 yolu olabilir:

* Herhangi bir **`LC_RPATH`** yazılabilir (ancak imza kontrol edilir, bu yüzden bunun için ikili dosyanın kısıtlamasız olması gerekir)
* İkili dosya **kısıtlamasız** ise ve ardından CWD'den bir şey yüklemek mümkün (veya bahsedilen env değişkenlerinden birini kötüye kullanmak)
{% endhint %}

* Yol **bir çerçeve yolu gibi görünüyorsa** (örneğin `/stuff/foo.framework/foo`), eğer başlangıçta **`$DYLD_FRAMEWORK_PATH`** ayarlandıysa, dyld önce **o dizinde** çerçeve kısmi yolunu arar (örneğin `foo.framework/foo`). Ardından, dyld **verilen yolu olduğu gibi dener** (ilişkili yollar için mevcut çalışma dizinini kullanır). Son olarak, eski ikili dosyalar için dyld bazı yedekler dener. Eğer başlangıçta **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ayarlandıysa, dyld **o dizinlerde arar**. Aksi takdirde, dyld **`/Library/Frameworks`**'de arar (MacOS'ta işlem kısıtlamasız ise), ardından **`/System/Library/Frameworks`**'de arar.

1. `$DYLD_FRAMEWORK_PATH`
2. verilen yol (ilişkili yollar için mevcut çalışma dizinini kullanır, kısıtlamasız işlemler için)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (kısıtlamasız ise)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Eğer bir çerçeve yolu ise, onu ele geçirmenin yolu:

* İşlem **kısıtlamasız** ise, CWD'den ilişkili yol veya bahsedilen env değişkenlerini kötüye kullanmak
{% endhint %}

* Yol **bir eğik çizgi içeriyorsa ancak bir çerçeve yolu değilse** (yani tam bir yol veya bir dylib'in kısmi yolu), dlopen() önce (ayarlandıysa) **`$DYLD_LIBRARY_PATH`** içinde (yolun yaprak kısmıyla birlikte) arar. Ardından, dyld **verilen yolu dener** (ilişkili yollar için mevcut çalışma dizinini kullanır (ancak sadece kısıtlamasız işlemler için)). Son olarak, eski ikili dosyalar için dyld bazı yedekler dener. Eğer başlangıçta **`$DYLD_FALLBACK_LIBRARY_PATH`** ayarlandıysa, dyld **o dizinlerde arar**, aksi takdirde dyld **`/usr/local/lib/`**'de (işlem kısıtlamasız ise) ve ardından **`/usr/lib/`**'de arar.

1. `$DYLD_LIBRARY_PATH`
2. verilen yol (ilişkili yollar için mevcut çalışma dizinini kullanır, kısıtlamasız işlemler için)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (kısıtlamasız ise)
5. `/usr/lib/`

{% hint style="danger" %}
Eğer adında eğik çizgi varsa ve bir çerçeve değilse, onu ele geçirmenin yolu:

* İkili dosya **kısıtlamasız** ise ve ardından CWD'den veya `/usr/local/lib`'den bir şey yüklemek mümkün (veya bahsedilen env değişkenlerinden birini kötüye kullanmak)
{% endhint %}

Not: Dlopen aramasını **kontrol etmek için** yapılandırma dosyaları **yoktur**.

Not: Ana yürütülebilir dosya bir **set\[ug]id ikili dosyası veya yetkilendirmelerle kod imzalanmış** ise, **tüm çevre değişkenleri yok sayılır** ve yalnızca tam bir yol kullanılabilir (daha ayrıntılı bilgi için \[DYLD\_INSERT\_LIBRARIES kısıtlamalarını kontrol edin]\(../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_

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

Eğer derlerseniz ve çalıştırırsanız, **her bir kütüphane nerede başarısız bir şekilde arandığını** görebilirsiniz. Ayrıca, **FS günlüklerini filtreleyebilirsiniz**:

```bash
sudo fs_usage | grep "dlopentest"
```

## İlgili Yol Kaçırma

Eğer bir **yetkili ikili/uygulama** (örneğin SUID veya güçlü yetkilere sahip başka bir ikili) **bir göreceli yol** kütüphanesini yüklüyorsa (örneğin `@executable_path` veya `@loader_path` kullanarak) ve **Kütüphane Doğrulama devre dışı bırakılmışsa**, saldırganın ikiliyi, saldırganın kod enjekte etmek için kütüphaneyi değiştirebileceği bir konuma taşıması mümkün olabilir.

## `DYLD_*` ve `LD_LIBRARY_PATH` Ortam Değişkenlerini Kırpma

`dyld-dyld-832.7.1/src/dyld2.cpp` dosyasında, **`pruneEnvironmentVariables`** adlı bir işlev bulunur, bu işlev **`DYLD_`** ile başlayan ve **`LD_LIBRARY_PATH=`** olan herhangi bir ortam değişkenini kaldırır.

Ayrıca, bu işlev, **suid** ve **sgid** ikilileri için özellikle **`DYLD_FALLBACK_FRAMEWORK_PATH`** ve **`DYLD_FALLBACK_LIBRARY_PATH`** ortam değişkenlerini **null** olarak ayarlar.

Bu işlev, aynı dosyanın **`_main`** işlevinden OSX hedef alınıyorsa aşağıdaki gibi çağrılır:

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

Bu temel olarak, eğer ikili dosya **suid** veya **sgid** ise, başlıklarda bir **RESTRICT** segmenti bulunuyorsa veya **CS\_RESTRICT** bayrağıyla imzalanmışsa, o zaman **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** ifadesi doğru olacak ve çevre değişkenleri kırpılacaktır.

Dikkat edilmesi gereken nokta, CS\_REQUIRE\_LV doğru ise, değişkenler kırpılmayacak ancak kütüphane doğrulaması, değişkenlerin orijinal ikili dosya ile aynı sertifikayı kullandığını kontrol edecektir.

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

### `__RESTRICT` Bölümü, `__restrict` Segmenti ile

Bu bölümde, `__restrict` segmentiyle ilgili `__RESTRICT` bölümü yer almaktadır.

```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```

### Sertifikaları Güçlendirme

Yeni bir sertifika oluşturun ve bunu kullanarak ikili dosyayı imzalayın:

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
Unutmayın ki, bayrakları **`0x0(none)`** ile imzalanan ikili dosyalar bile yürütüldüğünde **`CS_RESTRICT`** bayrağını dinamik olarak alabilir ve bu nedenle bu teknik onlarda çalışmayacaktır.

Bir işlemin bu bayrağa sahip olup olmadığını kontrol edebilirsiniz (buradan [**csops**](https://github.com/axelexic/CSOps) alın):

```bash
csops -status <pid>
```

ve ardından bayrağın 0x800 etkin olup olmadığını kontrol edin.
{% endhint %}

## Referanslar

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın veya** bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın.**

</details>
