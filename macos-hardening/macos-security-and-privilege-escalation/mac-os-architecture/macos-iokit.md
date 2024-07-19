# macOS IOKit

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Temel Bilgiler

I/O Kit, XNU çekirdeğinde açık kaynaklı, nesne yönelimli **cihaz sürücüsü çerçevesidir** ve **dinamik olarak yüklenen cihaz sürücülerini** yönetir. Farklı donanımları destekleyerek çekirdeğe modüler kod eklenmesine olanak tanır.

IOKit sürücüleri esasen **çekirdekten fonksiyonlar dışa aktarır**. Bu fonksiyon parametre **tipleri** **önceden tanımlıdır** ve doğrulanır. Ayrıca, XPC'ye benzer şekilde, IOKit sadece **Mach mesajlarının** üstünde başka bir katmandır.

**IOKit XNU çekirdek kodu**, Apple tarafından [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) adresinde açık kaynak olarak yayınlanmıştır. Ayrıca, kullanıcı alanı IOKit bileşenleri de açık kaynaklıdır [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ancak, **hiçbir IOKit sürücüsü** açık kaynak değildir. Yine de, zaman zaman bir sürücü sürümü, hata ayıklamayı kolaylaştıran sembollerle birlikte gelebilir. [**Firmware'den sürücü uzantılarını nasıl alacağınızı buradan kontrol edin**](./#ipsw)**.**

**C++** ile yazılmıştır. Demangled C++ sembollerini almak için:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **açık fonksiyonlar** bir istemcinin bir fonksiyonu çağırmaya çalıştığında **ek güvenlik kontrolleri** gerçekleştirebilir, ancak uygulamaların genellikle etkileşimde bulunabilecekleri IOKit fonksiyonlarıyla **sandbox** tarafından **sınırlı** olduğunu unutmayın.
{% endhint %}

## Sürücüler

macOS'ta şunlarda bulunurlar:

* **`/System/Library/Extensions`**
* OS X işletim sistemine entegre edilmiş KEXT dosyaları.
* **`/Library/Extensions`**
* Üçüncü taraf yazılımlar tarafından yüklenen KEXT dosyaları.

iOS'ta şunlarda bulunurlar:

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
9'a kadar listelenen sürücüler **0 adresinde yüklenmiştir**. Bu, bunların gerçek sürücüler olmadığı, ancak **çekirdek parçası oldukları ve boşaltılamayacakları** anlamına gelir.

Belirli uzantıları bulmak için şunları kullanabilirsiniz:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Kernel uzantılarını yüklemek ve kaldırmak için:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry**, macOS ve iOS'taki IOKit çerçevesinin önemli bir parçasıdır ve sistemin donanım yapılandırmasını ve durumunu temsil eden bir veritabanı olarak hizmet eder. Bu, sistemde yüklü olan tüm donanım ve sürücüleri temsil eden **hiyerarşik bir nesne koleksiyonudur** ve bunların birbirleriyle olan ilişkilerini gösterir.

IORegistry'yi, konsoldan incelemek için cli **`ioreg`** kullanarak alabilirsiniz (özellikle iOS için faydalıdır).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
**`IORegistryExplorer`**'ı **Xcode Ek Araçlar**'dan [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) adresinden indirebilir ve **macOS IORegistry**'ni **grafiksel** bir arayüz aracılığıyla inceleyebilirsiniz.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

IORegistryExplorer'da, "düzlemler" IORegistry'deki farklı nesneler arasındaki ilişkileri düzenlemek ve görüntülemek için kullanılır. Her düzlem, belirli bir ilişki türünü veya sistemin donanım ve sürücü yapılandırmasının belirli bir görünümünü temsil eder. IORegistryExplorer'da karşılaşabileceğiniz bazı yaygın düzlemler şunlardır:

1. **IOService Düzlemi**: Bu, sürücüleri ve nubs'ları (sürücüler arasındaki iletişim kanalları) temsil eden hizmet nesnelerini görüntüleyen en genel düzlemdir. Bu nesneler arasındaki sağlayıcı-müşteri ilişkilerini gösterir.
2. **IODeviceTree Düzlemi**: Bu düzlem, cihazların sisteme bağlı olduğu fiziksel bağlantıları temsil eder. Genellikle USB veya PCI gibi bus'lar aracılığıyla bağlı cihazların hiyerarşisini görselleştirmek için kullanılır.
3. **IOPower Düzlemi**: Güç yönetimi açısından nesneleri ve bunların ilişkilerini görüntüler. Diğerlerinin güç durumunu etkileyen nesneleri gösterebilir, güçle ilgili sorunları gidermek için yararlıdır.
4. **IOUSB Düzlemi**: Özellikle USB cihazları ve bunların ilişkilerine odaklanır, USB hub'larının ve bağlı cihazların hiyerarşisini gösterir.
5. **IOAudio Düzlemi**: Bu düzlem, ses cihazlarını ve bunların sistem içindeki ilişkilerini temsil etmek içindir.
6. ...

## Sürücü İletişim Kodu Örneği

Aşağıdaki kod, IOKit hizmetine `"YourServiceNameHere"` bağlanır ve seçici 0 içindeki fonksiyonu çağırır. Bunun için:

* Öncelikle **`IOServiceMatching`** ve **`IOServiceGetMatchingServices`** çağrılarak hizmet alınır.
* Ardından **`IOServiceOpen`** çağrılarak bir bağlantı kurulur.
* Son olarak, seçici 0'ı belirterek **`IOConnectCallScalarMethod`** ile bir fonksiyon çağrılır (seçici, çağırmak istediğiniz fonksiyona atanan numaradır).
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
There are **other** functions that can be used to call IOKit functions apart of **`IOConnectCallScalarMethod`** like **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Sürücü giriş noktasını tersine mühendislik

Bunları örneğin bir [**firmware image (ipsw)**](./#ipsw) üzerinden elde edebilirsiniz. Ardından, bunu en sevdiğiniz dekompilerde yükleyin.

**`externalMethod`** fonksiyonunu decompile etmeye başlayabilirsiniz çünkü bu, çağrıyı alacak ve doğru fonksiyonu çağıracak sürücü fonksiyonudur:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

O korkunç çağrı demagled, şunları ifade eder: 

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Önceki tanımda **`self`** parametresinin eksik olduğunu unutmayın, iyi bir tanım şöyle olmalıdır:

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
Bu bilgiyle Ctrl+Right -> `Edit function signature` yazabilir ve bilinen türleri ayarlayabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Yeni decompile edilmiş kod şöyle görünecek:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Sonraki adımda **`IOExternalMethodDispatch2022`** yapısını tanımlamamız gerekiyor. Bu yapı [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) adresinde açık kaynak olarak mevcuttur, bunu tanımlayabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Şimdi, `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` ifadesinin ardından birçok veri görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Veri Türünü **`IOExternalMethodDispatch2022:`** olarak değiştirin:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

değişiklikten sonra:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Ve şimdi orada **7 elemanlı bir dizi** olduğunu biliyoruz (son decompile edilmiş kodu kontrol edin), 7 elemanlı bir dizi oluşturmak için tıklayın:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Dizi oluşturulduktan sonra, tüm dışa aktarılan fonksiyonları görebilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Hatırlarsanız, kullanıcı alanından bir **dışa aktarılan** fonksiyonu **çağırmak** için fonksiyonun adını değil, **seçici numarasını** çağırmamız gerekiyor. Burada seçici **0** fonksiyonu **`initializeDecoder`**, seçici **1** **`startDecoder`**, seçici **2** **`initializeEncoder`** olduğunu görebilirsiniz...
{% endhint %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
