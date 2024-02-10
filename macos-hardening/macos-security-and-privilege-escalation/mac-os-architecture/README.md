# macOS Kernel ve Sistem Uzantıları

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan ileri seviyeye taşıyın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family) içerir
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## XNU Çekirdeği

**macOS'un çekirdeği XNU'dur**, "X is Not Unix" anlamına gelir. Bu çekirdek temel olarak **Mach mikroçekirdeği** (daha sonra tartışılacak) ve **Berkeley Yazılım Dağıtımı (BSD)**'den gelen öğelerden oluşur. XNU ayrıca **I/O Kit adlı bir sistem aracılığıyla çekirdek sürücüleri için bir platform sağlar**. XNU çekirdeği, Darwin açık kaynak projesinin bir parçasıdır, bu da **kaynak kodunun özgürce erişilebilir** olduğu anlamına gelir.

Bir güvenlik araştırmacısı veya Unix geliştirici perspektifinden bakıldığında, **macOS**, zarif bir GUI'ye ve bir dizi özel uygulamaya sahip bir **FreeBSD** sistemiyle oldukça **benzer** hissedebilir. BSD için geliştirilen çoğu uygulama, Unix kullanıcıları için tanıdık olan komut satırı araçları macOS'ta değişiklik yapmadan derlenip çalıştırılabilir. Bununla birlikte, XNU çekirdeği Mach'ı içerdiği için geleneksel bir Unix benzeri sistem ile macOS arasında bazı önemli farklılıklar vardır ve bu farklılıklar potansiyel sorunlara veya benzersiz avantajlara neden olabilir.

XNU'nun açık kaynak sürümü: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX uyumlu** olacak şekilde tasarlanmış bir **mikroçekirdek**tir. Temel tasarım prensiplerinden biri, **çekirdek** alanında çalışan **kod miktarını en aza indirmek** ve bunun yerine dosya sistemi, ağ ve I/O gibi birçok tipik çekirdek işlevinin **kullanıcı düzeyi görevleri olarak çalışmasına izin vermek**ti.

XNU'da Mach, **çekirdek** tarafından genellikle işlenen birçok kritik düşük seviye işlem için sorumludur, örneğin işlemci zamanlaması, çoklu görev ve sanal bellek yönetimi.

### BSD

XNU **çekirdeği**, aynı adres alanında Mach ile birlikte çalışan **FreeBSD** projesinden türetilmiş birçok kodu da **içerir**. Bununla birlikte, XNU içindeki FreeBSD kodu, uyumluluğunu sağlamak için değişiklikler gerektirdiğinden, orijinal FreeBSD kodundan önemli ölçüde farklı olabilir. FreeBSD, aşağıdaki gibi birçok çekirdek işlemine katkıda bulunur:

* İşlem yönetimi
* Sinyal işleme
* Kullanıcı ve grup yönetimi de dahil olmak üzere temel güvenlik mekanizmaları
* Sistem çağrısı altyapısı
* TCP/IP yığını ve soketler
* Güvenlik duvarı ve paket filtreleme

BSD ve Mach arasındaki etkileşimi anlamak, farklı kavramsal çerçevelerinden dolayı karmaşık olabilir. Örneğin, BSD, temel yürütme birimi olarak işlemleri kullanırken, Mach iş parçacıklarına dayalı olarak çalışır. Bu fark, BSD'nin çekirdek içindeki kodu, bir görev ve bir iş parçacığı yapısını oluşturmak için Mach işlevlerini kullanan BSD kodu tarafından XNU'da uzlaştırılır.

Ayrıca, **Mach ve BSD farklı güvenlik modellerini** sürdürür: **Mach'ın** güvenlik modeli **port haklarına** dayanırken, BSD'nin güvenlik modeli **işlem sahipliğine** dayanır. Bu iki model arasındaki farklar bazen yerel ayrıcalık yükseltme güvenlik açıklarına neden olmuştur. Tipik sistem çağrılarının yanı sıra, kullanıcı alanı programlarının çekirdek ile etkileşimde bulunmasına izin veren **Mach tuzağı**ları da vardır. Bu farklı unsurlar bir araya gelerek macOS çekirdeğinin çok yönlü, karma bir mimarisini oluşturur.

### I/O Kit - Sürücüler

I/O Kit, XNU çekirdeğindeki açık kaynaklı, nesne yönelimli bir **aygıt sürücüsü çerçevesi**dir ve **dinamik olarak yüklenen aygıt sürücülerini** yönetir. Modüler kodun çekirdeğe anında eklenmesine olanak tanır ve çeşitli donanımı destekler.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Süreçler Arası İletişim

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache**, XNU çekirdeğinin **önceden derlenmiş ve önceden bağlantılı bir sürümü**dür ve temel aygıt **sürücüleri** ve **çekirdek uzantıları** içerir. Sıkıştırılmış bir formatta depolanır ve önyükleme işlemi sırasında belleğe açılır. Kernelcache, hazır çalışmaya hazır bir çekirdek ve önemli sürücülerin bulunmasıyla daha hızlı bir önyükleme süresi sağlar, aksi takdirde bu bileşenlerin önyükleme sırasında dinamik olarak yüklenmesi ve bağlanması için harcanacak zaman ve kaynakları azaltır.

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** konumunda bulunur, macOS'ta ise **`find / -name kernelcache 2>/dev/null`** komutuyla bulunabilir.

#### IMG4

IMG4 dosya formatı, Apple'ın iOS ve macOS cihazlarında **çekirdekcache** gibi firmware bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullandığı bir konteyner formatıdır. IMG4 formatı, bir başlık ve gerçek yük (çekirdek veya önyükleyici gibi) ile bir imza ve bir dizi manifest özelliği gibi farklı veri parçalarını kapsayan birkaç etiket içerir. Format, firmware bileşeninin oturum açmadan önce cihazın onaylamasına ve bütünlüğünü doğrulamasına olanak tanır.

Genellikle aşağıdaki bileşenlerden oluşur:

* **Yük (IM4P)**:
* Sık sık sıkıştırılmış (LZFSE4, LZSS, ...)
* İsteğe bağlı olarak şifrelenmiş
* **Manifest (IM4M)**:
* İmza içerir
* Ek Anahtar/Değer sözlüğü
* **Geri Yükleme Bilgisi (IM4R)**:
* APNonce olarak da bilinir
* Bazı güncellemelerin tekrarlanmasını önler
* İSTEĞE BAĞLI: Genellikle bulunmaz

Kernelcache'i açmak için:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Kernelcache Sembolleri

Bazen Apple, sembollerle birlikte **kernelcache** yayınlar. Sembollerle birlikte bazı firmware'leri [https://theapplewiki.com](https://theapplewiki.com/) adresindeki bağlantıları takip ederek indirebilirsiniz.

### IPSW

Bunlar, Apple'ın **firmware'leri** olup [**https://ipsw.me/**](https://ipsw.me/) adresinden indirebileceğiniz dosyalardır. Diğer dosyalar arasında **kernelcache** bulunur.\
Dosyaları çıkarmak için sadece **unzip** yapmanız yeterlidir.

Firmware'i çıkardıktan sonra, **`kernelcache.release.iphone14`** gibi bir dosya elde edersiniz. Bu dosya **IMG4** formatındadır ve ilgili bilgileri aşağıdaki yöntemlerle çıkarabilirsiniz:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Çıkarılan kernelcache için sembolleri kontrol edebilirsiniz: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Bununla birlikte, şimdi **tüm uzantıları** veya **ilgilendiğiniz birini** çıkarabiliriz:
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS Çekirdek Uzantıları

macOS, yüksek ayrıcalıklarla çalışacak olan kodun yüklenmesine karşı **son derece kısıtlayıcıdır** (.kext). Aslında, varsayılan olarak (bir bypass bulunmadıkça) neredeyse imkansızdır.

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS Sistem Uzantıları

macOS, Çekirdek Uzantıları yerine kullanıcı düzeyinde API'ler sunan Sistem Uzantılarını oluşturdu. Bu şekilde, geliştiriciler çekirdek uzantıları kullanmaktan kaçınabilirler.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referanslar

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
