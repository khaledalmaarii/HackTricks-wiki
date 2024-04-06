# macOS Kernel & System Extensions

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## XNU Çekirdeği

**macOS'un çekirdeği XNU**'dur, "X is Not Unix" anlamına gelir. Bu çekirdek temel olarak **Mach mikroçekirdeği**nden (daha sonra tartışılacak) ve **Berkeley Yazılım Dağıtımı (BSD)**'den gelen öğelerden oluşur. XNU ayrıca **I/O Kit adlı bir sistem aracılığıyla çekirdek sürücülerine platform sağlar**. XNU çekirdeği, Darwin açık kaynak projesinin bir parçasıdır, bu da **kaynak kodunun serbestçe erişilebilir** olduğu anlamına gelir.

Bir güvenlik araştırmacısı veya Unix geliştirici açısından bakıldığında, **macOS**, şık bir GUI'ye ve bir dizi özel uygulamaya sahip bir **FreeBSD** sistemiyle oldukça **benzer** hissettirebilir. BSD için geliştirilen çoğu uygulama, Unix kullanıcılarına tanıdık gelen komut satırı araçları macOS'ta herhangi bir değişiklik yapmadan derlenip çalıştırılabilir. Ancak, XNU çekirdeği Mach'ı içerdiğinden, geleneksel bir Unix benzeri sistem ile macOS arasında bazı önemli farklılıklar vardır ve bu farklar potansiyel sorunlara neden olabilir veya benzersiz avantajlar sağlayabilir.

XNU'nun açık kaynak sürümü: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX uyumlu** bir **mikroçekirdek**tir. Temel tasarım prensiplerinden biri, **çekirdek alanında çalışan kod miktarını en aza indirgemek** ve dosya sistemi, ağ ve G/Ç gibi birçok tipik çekirdek işlevinin **kullanıcı düzeyi görevleri olarak çalışmasına izin vermektir**.

XNU'da, Mach, işlemci planlaması, çoklu görev, ve sanal bellek yönetimi gibi bir çekirdek tipik olarak ele aldığı birçok kritik düşük seviye işlemden sorumludur.

### BSD

XNU **çekirdeği** ayrıca **FreeBSD** projesinden türetilen önemli miktarda kodu **içerir**. Bu kod, Mach ile aynı adres alanında **çekirdeğin bir parçası olarak çalışır**. Ancak, XNU içindeki FreeBSD kodu, uyumluluğunu sağlamak için değişiklikler gerektiğinden, orijinal FreeBSD kodundan önemli ölçüde farklı olabilir. FreeBSD, aşağıdakiler de dahil olmak üzere birçok çekirdek işlemine katkıda bulunur:

* İşlem yönetimi
* Sinyal işleme
* Kullanıcı ve grup yönetimi de dahil olmak üzere temel güvenlik mekanizmaları
* Sistem çağrısı altyapısı
* TCP/IP yığını ve soketler
* Güvenlik duvarı ve paket filtreleme

BSD ve Mach arasındaki etkileşimi anlamak karmaşık olabilir, çünkü bunların farklı kavramsal çerçeveleri vardır. Örneğin, BSD, temel yürütme birimi olarak işlemleri kullanırken, Mach, iş parçacıklarına dayalı olarak çalışır. Bu uyumsuzluk, XNU'da, **her BSD işlemini yalnızca bir Mach göreviyle ilişkilendirerek** uzlaştırılır. BSD'nin fork() sistem çağrısı kullanıldığında, çekirdek içindeki BSD kodu, bir görev ve bir iş parçacığı yapısı oluşturmak için Mach işlevlerini kullanır.

Ayrıca, **Mach ve BSD'nin her birinin farklı güvenlik modelleri vardır**: **Mach'ın** güvenlik modeli **port haklarına** dayanırken, BSD'nin güvenlik modeli **işlem sahipliğine** dayanır. Bu iki model arasındaki farklar bazen yerel ayrıcalık yükseltme güvenlik açıklarına neden olmuştur. Tipik sistem çağrılarından başka, **kullanıcı alanı programlarının çekirdek ile etkileşimine izin veren Mach tuzağı**lar da bulunmaktadır. Bu farklı unsurlar bir araya gelerek macOS çekirdeğinin çok yönlü, karmaşık mimarisini oluşturur.

### I/O Kit - Sürücüler

I/O Kit, XNU çekirdeğindeki açık kaynaklı, nesne yönelimli bir **cihaz sürücü çerçevesi**dir, **dinamik olarak yüklenen cihaz sürücülerini** yönetir. Çeşitli donanımı destekleyen modüler kodun çekirdeğe anında eklenmesine izin verir.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Süreçler Arası İletişim

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

**Kernelcache**, XNU çekirdeğinin **ön derlenmiş ve ön bağlantılı bir sürümü** ile temel cihaz **sürücüleri** ve **çekirdek uzantıları**nı içeren bir yapıdır. Sıkıştırılmış bir formatta depolanır ve önyükleme işlemi sırasında belleğe açılır. Kernelcache, önyükleme sırasında bu bileşenlerin dinamik olarak yüklenmesi ve bağlanması için harcanacak zaman ve kaynakları azaltarak, hazır çalışmaya hazır bir çekirdek ve önemli sürücülerin bulunabilir olmasını sağlayarak **daha hızlı bir önyükleme süresi** sağlar.

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** konumundadır, macOS'ta ise **`find / -name kernelcache 2>/dev/null`** veya **`mdfind kernelcache | grep kernelcache`** komutlarıyla bulunabilir.

Yüklenen çekirdek uzantılarını kontrol etmek için **`kextstat`** komutunu çalıştırmak mümkündür.

#### IMG4

IMG4 dosya formatı, Apple'ın iOS ve macOS cihazlarında **firmware** bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullandığı bir konteyner formatıdır (örneğin **kernelcache**). IMG4 formatı, bir başlık ve gerçek yük (örneğin bir çekirdek veya önyükleyici), bir imza ve bir dizi manifest özelliği içeren farklı etiketleri içerir. Format, cihazın, bileşeni yürütmeye başlamadan önce bileşenin otantikliğini ve bütünlüğünü doğrulamasına olanak tanıyan kriptografik doğrulamayı destekler.

Genellikle aşağıdaki bileşenlerden oluşur:

* **Yük (IM4P)**:
* Genellikle sıkıştırılmıştır (LZFSE4, LZSS, ...)
* İsteğe bağlı olarak şifrelenmiş
* **Manifest (IM4M)**:
* İmza içerir
* Ek Anahtar/Değer sözlüğü
* **Restore Bilgisi (IM4R)**:
* APNonce olarak da bilinir
* Bazı güncellemelerin tekrar oynatılmasını önler
* İSTEĞE BAĞLI: Genellikle bulunmaz

Çekirdekcache'i açmak için:

```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

#### Kernelcache Sembolleri

Bazen Apple, **sembolleri** içeren **kernelcache** yayınlıyor. Bazı sembollerle birlikte firmware'leri [https://theapplewiki.com](https://theapplewiki.com/) adresinden indirebilirsiniz.

### IPSW

Bunlar, [**https://ipsw.me/**](https://ipsw.me/) adresinden indirebileceğiniz Apple **firmware'leri**dir. Diğer dosyalar arasında **kernelcache** bulunur.\
Dosyaları **çıkarmak** için sadece onu **zip** dosyasından çıkarmanız yeterlidir.

Firmware çıkardıktan sonra şu türde bir dosya elde edersiniz: **`kernelcache.release.iphone14`**. Bu, **IMG4** formatındadır ve ilginç bilgileri çıkarmak için şu aracı kullanabilirsiniz:

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

**`nm -a kernelcache.release.iphone14.e | wc -l`** komutunu kullanarak çıkarılan kernelcache için sembolleri kontrol edebilirsiniz.

Bununla birlikte şimdi **tüm uzantıları** veya **ilgilendiğiniz uzantıyı** çıkarabiliriz:

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

## macOS Kernel Uzantıları

macOS, **yüksek ayrıcalıklarla çalışacak olan kodlar nedeniyle Kernel Uzantılarını** (.kext) yüklemeyi oldukça kısıtlayıcıdır. Aslında, varsayılan olarak neredeyse imkansızdır (bir bypass bulunmadıkça).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS Sistem Uzantıları

Kernel Uzantıları yerine macOS, çekirdek ile etkileşim için kullanıcı düzeyinde API'lar sunan Sistem Uzantılarını oluşturdu. Bu sayede geliştiriciler çekirdek uzantılarını kullanmaktan kaçınabilirler.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referanslar

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬** [**Discord grubuna**](https://discord.gg/hRep4RUj7f) **veya** [**telegram grubuna**](https://t.me/peass) **katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)\*\* takip edin.\*\*
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
