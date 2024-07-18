# macOS Çekirdek & Sistem Uzantıları

{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## XNU Çekirdeği

**macOS'un çekirdeği XNU'dur**, "X is Not Unix" anlamına gelir. Bu çekirdek temel olarak **Mach mikroçekirdeği** (daha sonra tartışılacak), **ve** Berkeley Yazılım Dağıtımı (**BSD**) unsurlarından oluşur. XNU ayrıca **I/O Kit adlı bir sistem aracılığıyla çekirdek sürücülerine platform sağlar**. XNU çekirdeği, Darwin açık kaynak projesinin bir parçasıdır, bu da **kaynak kodunun serbestçe erişilebilir** olduğu anlamına gelir.

Bir güvenlik araştırmacısı veya Unix geliştiricisi açısından bakıldığında, **macOS**, şık bir GUI'ye ve bir dizi özel uygulamaya sahip bir **FreeBSD** sistemiyle oldukça **benzer** hissedebilir. BSD için geliştirilen çoğu uygulama, Unix kullanıcıları için tanıdık olan komut satırı araçları macOS'ta herhangi bir değişiklik yapmadan derlenip çalıştırılabilir. Ancak, XNU çekirdeği Mach'ı içerdiğinden, geleneksel bir Unix benzeri sistem ile macOS arasında bazı önemli farklılıklar vardır ve bu farklılıklar potansiyel sorunlara neden olabilir veya benzersiz avantajlar sağlayabilir.

XNU'nun açık kaynak sürümü: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX uyumlu** bir **mikroçekirdek**tir. Temel tasarım prensiplerinden biri, **çekirdek** alanında çalışan **kod** miktarını **en aza indirgemek** ve dosya sistemi, ağ ve I/O gibi birçok tipik çekirdek işlevini **kullanıcı düzeyi görevleri olarak çalıştırmaya izin vermektir**.

XNU'da, Mach, işlemci zamanlama, çoklu görev, ve sanal bellek yönetimi gibi bir çekirdek genellikle ele aldığı birçok kritik düşük seviye işlemden **sorumludur**.

### BSD

XNU **çekirdeği** ayrıca **FreeBSD** projesinden türetilen önemli miktarda kodu **içerir**. Bu kod, Mach ile birlikte **çekirdeğin bir parçası olarak çalışır**, aynı adres alanında. Ancak, XNU içindeki FreeBSD kodu, uyumluluğunu sağlamak için değişiklikler gerektiğinden, orijinal FreeBSD kodundan önemli ölçüde farklılık gösterebilir. FreeBSD, aşağıdaki gibi birçok çekirdek işlemine katkıda bulunur:

* İşlem yönetimi
* Sinyal işleme
* Kullanıcı ve grup yönetimi de dahil olmak üzere temel güvenlik mekanizmaları
* Sistem çağrısı altyapısı
* TCP/IP yığını ve soketler
* Güvenlik duvarı ve paket filtreleme

BSD ve Mach arasındaki etkileşimi anlamak karmaşık olabilir, farklı kavramsal çerçevelerinden dolayı. Örneğin, BSD, temel yürütme birimi olarak işlemleri kullanırken, Mach, iş parçacıklarına dayalı olarak çalışır. Bu uyumsuzluk, XNU'da, **her BSD işlemini yalnızca bir Mach göreviyle ilişkilendirerek** uzlaştırılır. BSD'nin fork() sistem çağrısı kullanıldığında, çekirdekteki BSD kodu, bir görev ve bir iş parçacığı yapısı oluşturmak için Mach işlevlerini kullanır.

Ayrıca, **Mach ve BSD her biri farklı güvenlik modellerini sürdürür**: **Mach'ın** güvenlik modeli **port haklarına** dayanırken, BSD'nin güvenlik modeli **işlem sahipliğine** dayanır. Bu iki model arasındaki farklılıklar bazen yerel ayrıcalık yükseltme güvenlik açıklarına neden olmuştur. Tipik sistem çağrılarından başka, **kullanıcı alanı programlarının çekirdek ile etkileşimine izin veren Mach tuzağı** da bulunmaktadır. Bu farklı unsurlar bir araya gelerek macOS çekirdeğinin çok yönlü, karmaşık mimarisini oluşturur.

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

**Kernelcache**, XNU çekirdeğinin **ön derlenmiş ve ön bağlantılı bir sürümü** ile temel cihaz **sürücüleri** ve **çekirdek uzantıları**nı içeren bir dosyadır. Sıkıştırılmış bir formatta depolanır ve önyükleme sırasında belleğe açılır. Kernelcache, önyükleme süresini hızlandırarak, hazır çalışmaya hazır bir çekirdek ve önemli sürücülerin mevcut olmasını sağlayarak, önyükleme sırasında bu bileşenlerin dinamik olarak yüklenmesi ve bağlanması için harcanacak zaman ve kaynakları azaltır.

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** konumundadır, macOS'ta ise **`find / -name kernelcache 2>/dev/null`** veya **`mdfind kernelcache | grep kernelcache`** komutlarıyla bulunabilir.

Yüklenen çekirdek uzantılarını kontrol etmek için **`kextstat`** komutunu çalıştırmak mümkündür.

#### IMG4

IMG4 dosya formatı, Apple'ın iOS ve macOS cihazlarında **firmware** bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullandığı bir konteyner formatıdır (örneğin **kernelcache**). IMG4 formatı, bir başlık ve gerçek yük (örneğin bir çekirdek veya önyükleyici) gibi farklı veri parçalarını kapsayan birkaç etiket içerir. Format, cihazın bileşeni yürütmeye geçmeden önce bileşenin otantikliğini ve bütünlüğünü doğrulamasına olanak tanıyan kriptografik doğrulamayı destekler.

Genellikle aşağıdaki bileşenlerden oluşur:

* **Yük (IM4P)**:
* Genellikle sıkıştırılmış (LZFSE4, LZSS, …)
* İsteğe bağlı olarak şifrelenmiş
* **Manifesto (IM4M)**:
* İmza içerir
* Ek Anahtar/Değer sözlüğü
* **Geri Yükleme Bilgisi (IM4R)**:
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

Bazen Apple, **sembolleri** içeren **kernelcache** yayınlıyor. Bazı firmware'leri sembollerle birlikte indirebilirsiniz, [https://theapplewiki.com](https://theapplewiki.com/) adresindeki bağlantıları takip ederek.

### IPSW

Bunlar, [**https://ipsw.me/**](https://ipsw.me/) adresinden indirebileceğiniz Apple **firmware'leri**dir. Diğer dosyalar arasında **kernelcache** bulunacaktır.\
Dosyaları **çıkarmak** için sadece onu **zip** dosyasından çıkarmanız yeterlidir.

Firmware çıkarıldıktan sonra şöyle bir dosya elde edersiniz: **`kernelcache.release.iphone14`**. Bu, **IMG4** formatındadır ve ilginç bilgileri çıkarmak için şu aracı kullanabilirsiniz:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
İşte çıkarılmış kernelcache için sembolleri kontrol edebilirsiniz: **`nm -a kernelcache.release.iphone14.e | wc -l`**

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

macOS, **Kernel Uzantılarını** (.kext) yüklemeye karşı son derece kısıtlayıcıdır çünkü bu kodun çalışacağı yüksek ayrıcalıklardan dolayı. Aslında, varsayılan olarak neredeyse imkansızdır (bir bypass bulunmadıkça).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS Sistem Uzantıları

Kernel Uzantıları yerine macOS, çekirdek ile etkileşim için kullanıcı düzeyinde API'lar sunan Sistem Uzantılarını oluşturdu. Bu şekilde, geliştiriciler çekirdek uzantılarını kullanmaktan kaçınabilirler.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referanslar

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
AWS Hacking öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
