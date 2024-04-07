# macOS IOKit

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz?** **Şirketinizi HackTricks'te görmek ister misiniz?** **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) **kontrol edin!**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) keşfedin, [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) için özel koleksiyonumuz
* [**Resmi PEASS ve HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **grubuna katılın** veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live) **takip edin**.
* **Hacking püf noktalarınızı paylaşın, PR göndererek** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile.**

</details>

## Temel Bilgiler

I/O Kit, XNU çekirdeğindeki açık kaynaklı, nesne yönelimli **cihaz sürücüsü çerçevesi**dir, **dinamik olarak yüklenen cihaz sürücülerini** işler. Çeşitli donanımı destekleyen çekirdeğe modüler kodun anında eklenmesine izin verir.

IOKit sürücüleri temelde **çekirdekten işlevleri dışa aktarır**. Bu işlev parametre **türleri önceden tanımlanmıştır** ve doğrulanır. Dahası, XPC gibi, IOKit sadece **Mach mesajlarının üstünde başka bir katmandır**.

**IOKit XNU çekirdek kodu**, Apple tarafından [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) adresinde açık kaynak olarak yayınlanmıştır. Ayrıca, kullanıcı alanı IOKit bileşenleri de açık kaynaklıdır [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ancak, **hiçbir IOKit sürücüsü** açık kaynak değildir. Neyse ki, zaman zaman bir sürücünün sürümü, onu hata ayıklamayı kolaylaştıran sembollerle gelebilir. [**Firmware'den sürücü uzantılarını nasıl alacağınızı buradan kontrol edin**](./#ipsw)**.**

**C++** dilinde yazılmıştır. Demangled C++ sembollerini alabilirsiniz:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **açık fonksiyonları**, bir istemcinin bir fonksiyonu çağırmaya çalıştığında **ek güvenlik kontrolleri** gerçekleştirebilir ancak uygulamalar genellikle **IOKit fonksiyonlarıyla etkileşime girebilecekleri** **kum havuzu** tarafından sınırlanmıştır.
{% endhint %}

## Sürücüler

macOS'ta şurada bulunurlar:

* **`/System/Library/Extensions`**
* OS X işletim sistemi içine yerleştirilmiş KEXT dosyaları.
* **`/Library/Extensions`**
* 3. taraf yazılım tarafından yüklenen KEXT dosyaları

iOS'ta şurada bulunurlar:

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
Listedeki sürücüler 9'a kadar **0 adresinde yüklenir**. Bu, bunların gerçek sürücüler olmadığı ve **çekilemeyeceği anlamına gelir**.

Belirli uzantıları bulmak için şunu kullanabilirsiniz:
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

**IORegistry**, macOS ve iOS'taki IOKit çerçevesinin kritik bir parçasıdır ve sistem donanım konfigürasyonunu ve durumunu temsil etmek için bir veritabanı görevi görür. Tüm donanım ve sürücülerin sistemde yüklenmiş olduğu ve birbirleriyle olan ilişkilerini temsil eden **hiyerarşik nesneler koleksiyonudur**.

IORegistry'ye **`ioreg`** komutunu kullanarak erişebilir ve konsoldan inceleyebilirsiniz (özellikle iOS için kullanışlıdır).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**IORegistryExplorer**'ı [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) adresinden **Xcode Ek Araçları**'ndan indirebilir ve **grafiksel** arayüz aracılığıyla **macOS IORegistry**'yi inceleyebilirsiniz.

<figure><img src="../../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer'da "planes" farklı nesneler arasındaki ilişkileri düzenlemek ve göstermek için kullanılır. Her plane, sistem donanımının ve sürücü yapılandırmasının belirli bir görünümünü veya ilişki türünü temsil eder. IORegistryExplorer'da karşılaşabileceğiniz bazı yaygın plane'ler şunlardır:

1. **IOService Plane**: Bu en genel plane'dir, sürücüleri ve nub'ları (sürücüler arasındaki iletişim kanalları) temsil eden hizmet nesnelerini gösterir. Bu nesneler arasındaki sağlayıcı-müşteri ilişkilerini gösterir.
2. **IODeviceTree Plane**: Bu plane, cihazların sistemdeki bağlantılarını temsil eder. USB veya PCI gibi otobüsler aracılığıyla bağlanan cihazların hiyerarşisini görselleştirmek için sıkça kullanılır.
3. **IOPower Plane**: Nesneleri ve ilişkilerini güç yönetimi açısından gösterir. Diğer nesnelerin güç durumunu etkileyen nesneleri gösterebilir, güçle ilgili sorunları gidermek için faydalıdır.
4. **IOUSB Plane**: Özellikle USB cihazlarına ve ilişkilerine odaklanır, USB hub'larının ve bağlı cihazların hiyerarşisini gösterir.
5. **IOAudio Plane**: Bu plane, ses cihazlarını ve sistem içindeki ilişkilerini temsil etmek içindir.
6. ...

## Sürücü İletişim Kodu Örneği

Aşağıdaki kod, `"YourServiceNameHere"` adlı IOKit hizmetine bağlanır ve seçici 0 içindeki işlevi çağırır. Bunun için:

* öncelikle **`IOServiceMatching`** ve **`IOServiceGetMatchingServices`** çağrılarını yaparak hizmeti alır.
* Ardından **`IOServiceOpen`** çağrısını yaparak bir bağlantı kurar.
* Ve son olarak **`IOConnectCallScalarMethod`** ile seçici 0'ı (seçici, çağırmak istediğiniz işlevin atanmış olduğu sayıdır) belirterek bir işlevi çağırır.
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
**IOConnectCallScalarMethod** gibi IOKit işlevlerini çağırmak için kullanılabilecek **IOConnectCallMethod**, **IOConnectCallStructMethod** gibi **diğer** işlevler bulunmaktadır...

## Sürücü giriş noktasını tersine çevirme

Bunları örneğin bir [**firmware görüntüsünden (ipsw)**](./#ipsw) elde edebilirsiniz. Daha sonra, favori dekompilerinize yükleyin.

**externalMethod** işlevini decompile etmeye başlayabilirsiniz çünkü bu, çağrıyı alan ve doğru işlevi çağıran sürücü işlevidir:

<figure><img src="../../../.gitbook/assets/image (1165).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1166).png" alt=""><figcaption></figcaption></figure>

O korkunç çağrı demagled anlamına gelir:

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
Bu bilgi ile Ctrl+Sağ -> `Düzenle işlev imzası` yeniden yazılabilir ve bilinen türler ayarlanabilir:

<figure><img src="../../../.gitbook/assets/image (1171).png" alt=""><figcaption></figcaption></figure>

Yeni dekompiled kod şu şekilde görünecek:

<figure><img src="../../../.gitbook/assets/image (1172).png" alt=""><figcaption></figcaption></figure>

Bir sonraki adım için **`IOExternalMethodDispatch2022`** yapısının tanımlanmış olması gerekmektedir. [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) adresinde açık kaynaklıdır, şu şekilde tanımlayabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1167).png" alt=""><figcaption></figcaption></figure>

Şimdi, `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` takip ederek birçok veri görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1173).png" alt="" width="563"><figcaption></figcaption></figure>

Veri Türünü **`IOExternalMethodDispatch2022:`** olarak değiştirin:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt="" width="375"><figcaption></figcaption></figure>

değişiklikten sonra:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Ve şimdi, içinde **7 elemanın bir dizisi** olduğunu biliyoruz (son dekompiled kodu kontrol edin), 7 elemanlık bir dizi oluşturmak için tıklayın:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="563"><figcaption></figcaption></figure>

Dizi oluşturulduktan sonra tüm ihraç edilen işlevleri görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1178).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Hatırlarsanız, kullanıcı alanından bir **ihraç edilen** işlevi **çağırmak** için işlevin adını değil, **seçici numarasını** çağırmamız gerekir. Burada, seçicinin **0** olduğu işlevin **`initializeDecoder`**, seçicinin **1** olduğu işlevin **`startDecoder`**, seçicinin **2** olduğu işlevin **`initializeEncoder`** olduğunu görebilirsiniz...
{% endhint %}
