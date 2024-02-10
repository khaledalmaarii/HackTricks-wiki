# macOS IOKit

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* **Bir siber güvenlik şirketinde çalışıyor musunuz?** **Şirketinizi HackTricks'te duyurmak** ister misiniz? **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? **ABONELİK PLANLARINI** kontrol edin (https://github.com/sponsors/carlospolop)!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS ve HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **beni takip edin**.
* **Hacking hilelerinizi göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile paylaşın**.

</details>

## Temel Bilgiler

I/O Kit, XNU çekirdeğindeki açık kaynaklı, nesne yönelimli bir **aygıt sürücüsü çerçevesidir** ve **dinamik olarak yüklenen aygıt sürücülerini** yönetir. Modüler kodun çekirdeğe anında eklenmesine izin vererek çeşitli donanımı destekler.

IOKit sürücüleri temel olarak **çekirdekten işlevleri dışa aktarır**. Bu işlev parametre **türleri önceden tanımlanmıştır** ve doğrulanır. Ayrıca, XPC gibi, IOKit sadece **Mach mesajlarının üzerine başka bir katmandır**.

**IOKit XNU çekirdek kodu**, Apple tarafından [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) adresinde açık kaynak olarak yayınlanmıştır. Ayrıca, kullanıcı alanı IOKit bileşenleri de açık kaynaklıdır [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ancak, **hiçbir IOKit sürücüsü** açık kaynak değildir. Neyse ki, zaman zaman bir sürücünün bir sürümü, hata ayıklamayı kolaylaştıran sembollerle birlikte gelebilir. [**Firmware'den sürücü uzantılarını nasıl alacağınızı buradan kontrol edin**](./#ipsw)**.**

C++ ile yazılmıştır. C++ sembollerini çözülmüş halde alabilirsiniz:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **açık fonksiyonları**, bir istemcinin bir fonksiyonu çağırmaya çalıştığında **ek güvenlik kontrolleri** yapabilir, ancak uygulamalar genellikle IOKit fonksiyonlarıyla etkileşimde bulunabilecekleri **sandbox** tarafından **sınırlanır**.
{% endhint %}

## Sürücüler

macOS'ta şu konumda bulunurlar:

* **`/System/Library/Extensions`**
* OS X işletim sistemi tarafından oluşturulan KEXT dosyaları.
* **`/Library/Extensions`**
* 3. taraf yazılım tarafından yüklenen KEXT dosyaları.

iOS'ta şu konumda bulunurlar:

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
9'a kadar olan sıralı sürücüler **0 adresinde yüklenir**. Bu, bunların gerçek sürücüler olmadığı, **çekirdeğin bir parçası oldukları ve kaldırılamadıkları** anlamına gelir.

Belirli uzantıları bulmak için şunları kullanabilirsiniz:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Kernel uzantılarını yüklemek ve kaldırmak için şunları yapın:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**, macOS ve iOS'ta IOKit çerçevesinin önemli bir parçasıdır ve sistemdeki donanım yapılandırması ve durumunu temsil etmek için bir veritabanı görevi görür. Bu, sisteme yüklenen tüm donanım ve sürücülerin ve birbirleriyle ilişkilerinin temsil edildiği **hiyerarşik bir nesne koleksiyonudur**.

IORegistry'yi, konsoldan (özellikle iOS için özellikle kullanışlı) incelemek için **`ioreg`** komutunu kullanarak alabilirsiniz.
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**'ı [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) adresinden **Xcode Ek Araçları**ndan indirebilir ve **grafik arayüzü** üzerinden **macOS IORegistry**'i inceleyebilirsiniz.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer'da "planes" (düzlemler), IORegistry'deki farklı nesneler arasındaki ilişkileri düzenlemek ve görüntülemek için kullanılır. Her düzlem, belirli bir ilişki türünü veya sistemdeki donanım ve sürücü yapılandırmasının belirli bir görünümünü temsil eder. IORegistryExplorer'da karşılaşabileceğiniz bazı yaygın düzlemler şunlardır:

1. **IOService Düzlemi**: Bu en genel düzlemdir ve sürücüleri ve nub'ları (sürücüler arasındaki iletişim kanalları) temsil eden hizmet nesnelerini gösterir. Bu nesneler arasındaki sağlayıcı-müşteri ilişkilerini gösterir.
2. **IODeviceTree Düzlemi**: Bu düzlem, cihazların fiziksel bağlantılarını sisteme bağlandıkları şekilde temsil eder. USB veya PCI gibi otobüsler aracılığıyla bağlanan cihazların hiyerarşisini görselleştirmek için sıklıkla kullanılır.
3. **IOPower Düzlemi**: Nesneleri ve güç yönetimi açısından ilişkilerini gösterir. Başkalarının güç durumunu etkileyen nesneleri gösterebilir ve güçle ilgili sorunları gidermek için kullanışlıdır.
4. **IOUSB Düzlemi**: Özellikle USB cihazlarına ve ilişkilerine odaklanır, USB hub'larının ve bağlı cihazların hiyerarşisini gösterir.
5. **IOAudio Düzlemi**: Bu düzlem, sistem içindeki ses cihazlarını ve ilişkilerini temsil etmek içindir.
6. ...

## Sürücü İletişim Kod Örneği

Aşağıdaki kod, `"YourServiceNameHere"` adlı IOKit hizmetine bağlanır ve seçici 0 içindeki işlevi çağırır. Bunun için:

* öncelikle **`IOServiceMatching`** ve **`IOServiceGetMatchingServices`**'i çağırarak hizmeti alır.
* Ardından **`IOServiceOpen`** çağrısı yaparak bir bağlantı kurar.
* Ve son olarak, **`IOConnectCallScalarMethod`** ile seçici 0'ı (seçici, çağırmak istediğiniz işlevin atandığı numara) belirterek bir işlevi çağırır.
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
**Diğer** fonksiyonlar da **`IOConnectCallScalarMethod`** dışında IOKit fonksiyonlarını çağırmak için kullanılabilir, örneğin **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Sürücü giriş noktasını tersine çevirme

Bunları örneğin bir [**firmware görüntüsünden (ipsw)**](./#ipsw) elde edebilirsiniz. Ardından, favori decompilerınıza yükleyin.

Çağrıyı alan ve doğru fonksiyonu çağıran sürücü fonksiyonu olan **`externalMethod`** fonksiyonunu decompile etmeye başlayabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Bu korkunç çağrı demangled anlamına gelir:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Önceki tanımda **`self`** parametresinin eksik olduğuna dikkat edin, doğru tanım şu şekilde olmalıdır:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Aslında, gerçek tanımı [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) adresinde bulabilirsiniz:
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Bu bilgilerle, Ctrl+Right -> `Düzenleme işlevi imzası`'nı yeniden yazabilir ve bilinen türleri ayarlayabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Yeni dekompilasyon kodu şu şekilde görünecektir:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Bir sonraki adım için **`IOExternalMethodDispatch2022`** yapısının tanımlanmış olması gerekmektedir. [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) adresinde açık kaynak olarak bulunmaktadır, şu şekilde tanımlayabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Şimdi, `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`'i takip ederek birçok veri görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Veri Türünü **`IOExternalMethodDispatch2022:`** olarak değiştirin:

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

değişiklikten sonra:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

Ve şimdi, **7 öğeli bir dizi** olduğunu biliyoruz (son dekompilasyon kodunu kontrol edin), 7 öğeli bir dizi oluşturmak için tıklayın:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Dizi oluşturulduktan sonra, tüm dışa aktarılan işlevleri görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Hatırlarsanız, kullanıcı alanından bir dışa aktarılan işlevi **çağırmak** için işlevin adını değil, **seçici numarasını** kullanmamız gerekiyor. Burada, seçici **0**'ın **`initializeDecoder`** işlevi olduğunu, seçici **1**'in **`startDecoder`** olduğunu, seçici **2**'nin **`initializeEncoder`** olduğunu görebilirsiniz...
{% endhint %}

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde çalışıyor musunuz?** **Şirketinizi HackTricks'te tanıtmak** ister misiniz? **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin.
* [**PEASS ve HackTricks'in resmi ürünlerini alın**](https://peass.creator-spring.com)
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**Telegram grubuna**](https://t.me/peass) katılın veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **beni takip edin**.
* **Hacking hilelerinizi paylaşın**, [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **göndererek**.

</details>
