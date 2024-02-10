# macOS Bellek Dökümü

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Bellek Sanatıkları

### Takas Dosyaları

`/private/var/vm/swapfile0` gibi takas dosyaları, **fiziksel bellek dolu olduğunda önbellek olarak hizmet verir**. Fiziksel bellekte yer kalmadığında, veriler bir takas dosyasına aktarılır ve ihtiyaç duyulduğunda tekrar fiziksel belleğe getirilir. swapfile0, swapfile1 gibi isimlerle birden fazla takas dosyası bulunabilir.

### Uyku Görüntüsü

`/private/var/vm/sleepimage` konumunda bulunan dosya, **uyku modunda** önemlidir. **OS X uyku modundayken bellek verileri bu dosyada depolanır**. Bilgisayar uyandığında, sistem bellek verilerini bu dosyadan alır ve kullanıcının kaldığı yerden devam etmesini sağlar.

Modern MacOS sistemlerinde, bu dosyanın genellikle güvenlik nedenleriyle şifrelendiğini ve kurtarmanın zor olduğunu belirtmek gerekir.

* Uyku görüntüsü için şifrelemenin etkin olup olmadığını kontrol etmek için `sysctl vm.swapusage` komutu çalıştırılabilir. Bu, dosyanın şifrelenip şifrelenmediğini gösterecektir.

### Bellek Basıncı Günlükleri

MacOS sistemlerindeki başka bir önemli bellek ile ilgili dosya, **bellek basıncı günlükleri**dir. Bu günlükler `/var/log` konumunda bulunur ve sistem bellek kullanımı ve basınç olayları hakkında detaylı bilgiler içerir. Bellek ile ilgili sorunları teşhis etmek veya sistem belleğinin zaman içinde nasıl yönetildiğini anlamak için özellikle faydalı olabilirler.

## osxpmem ile bellek dökümü

Bir MacOS makinede belleği dökmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Not**: Aşağıdaki talimatlar yalnızca Intel mimarisine sahip Mac'ler için çalışacaktır. Bu araç şu anda arşivlenmiştir ve son sürümü 2017'de yayınlanmıştır. Aşağıdaki talimatlarla indirilen ikili dosya, Apple Silicon 2017'de mevcut olmadığı için Intel çipleri hedef almaktadır. arm64 mimarisi için ikili dosyayı derlemek mümkün olabilir, ancak bunu kendiniz denemelisiniz.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Eğer şu hatayı bulursanız: `osxpmem.app/MacPmem.kext yüklenemedi - (libkern/kext) kimlik doğrulama hatası (dosya sahipliği/izinleri); hatalar için sistem/çekirdek günlüklerini kontrol edin veya kextutil(8)'i deneyin` Bunun düzeltilmesi için şunları yapabilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, "Güvenlik ve Gizlilik --> Genel" bölümünde **kext yüklemeye izin verilerek** düzeltilebilir, sadece **izin verin**.

Ayrıca, uygulamayı indirmek, kext'i yüklemek ve belleği dökmek için bu **tek satırlık komutu** kullanabilirsiniz:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
