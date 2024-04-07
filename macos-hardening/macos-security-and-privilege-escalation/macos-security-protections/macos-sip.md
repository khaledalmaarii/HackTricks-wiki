# macOS SIP

<details>

<summary><strong>AWS hacklemeyi sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## **Temel Bilgiler**

**System Integrity Protection (SIP)**, macOS'ta en yetkili kullanıcıların bile ana sistem klasörlerine izinsiz değişiklik yapmasını engellemek için tasarlanmış bir mekanizmadır. Bu özellik, korunan alanlarda dosya ekleme, değiştirme veya silme gibi işlemleri kısıtlayarak sistemin bütünlüğünü korumada kritik bir rol oynar. SIP tarafından korunan başlıca klasörler şunlardır:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIP'nin davranışını belirleyen kurallar, genellikle sıkı SIP kısıtlamalarının istisnaları olarak işaretlenen yıldız (\*) ile başlayan yolların bulunduğu **`/System/Library/Sandbox/rootless.conf`** konfigürasyon dosyasında tanımlanmıştır.

Aşağıdaki örneği düşünün:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Bu parça, SIP'nin genellikle **`/usr`** dizinini güvence altına aldığını, ancak değişikliklere izin verilen belirli alt dizinlerin (`/usr/libexec/cups`, `/usr/local` ve `/usr/share/man`) yollarının önünde yer alan yıldız (\*) işareti ile belirtildiğini ima etmektedir.

Bir dizinin veya dosyanın SIP tarafından korunup korunmadığını doğrulamak için **`ls -lOd`** komutunu kullanarak **`restricted`** veya **`sunlnk`** bayrağının varlığını kontrol edebilirsiniz. Örneğin:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Bu durumda, **`sunlnk`** bayrağı, `/usr/libexec/cups` dizininin **silinemeyeceğini** ancak içindeki dosyaların oluşturulabileceğini, değiştirilebileceğini veya silinebileceğini belirtir.

Öte yandan:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
İşte **`restricted`** bayrağı, `/usr/libexec` dizininin SIP ile korunduğunu gösterir. SIP ile korunan bir dizinde, dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Dahası, bir dosya **`com.apple.rootless`** genişletilmiş **özniteliği** içeriyorsa, o dosya da **SIP ile korunur**.

**SIP ayrıca diğer kök işlemleri de sınırlar**:

* Güvenilmeyen çekirdek uzantılarını yükleme
* Apple tarafından imzalanan işlemler için görev bağlantı noktalarını alma
* NVRAM değişkenlerini değiştirme
* Çekirdek hata ayıklamaya izin verme

Seçenekler, bir bit bayrağı olarak nvram değişkeninde tutulur (`csr-active-config` Intel için ve ARM için önyüklü Cihaz Ağacından `lp-sip0` okunur). Bayrakları XNU kaynak kodunda `csr.sh` dosyasında bulabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

Sisteminizde SIP'in etkin olup olmadığını aşağıdaki komutla kontrol edebilirsiniz:
```bash
csrutil status
```
Eğer SIP'yi devre dışı bırakmanız gerekiyorsa, bilgisayarınızı kurtarma modunda yeniden başlatmanız gerekir (başlangıç sırasında Command+R tuşlarına basarak), ardından aşağıdaki komutu çalıştırın:
```bash
csrutil disable
```
Eğer SIP'i etkin tutmak istiyorsanız ancak hata ayıklama korumalarını kaldırmak istiyorsanız, bunu şu şekilde yapabilirsiniz:
```bash
csrutil enable --without debug
```
### Diğer Kısıtlamalar

* **İmzasız çekirdek uzantılarının** (kexts) yüklenmesine izin verilmez, yalnızca doğrulanmış uzantıların sistem çekirdeğiyle etkileşmesi sağlanır.
* **macOS sistem süreçlerinin hata ayıklanmasını engeller**, çekirdek sistem bileşenlerini yetkisiz erişim ve değişikliklerden korur.
* **dtrace gibi araçların** sistem süreçlerini incelemesini engeller, sistem işleyişinin bütünlüğünü daha da korur.

[**Bu konuda SIP bilgileri hakkında daha fazla bilgi edinin**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## SIP Atlatmaları

SIP'nin atlatılması bir saldırganın şunları yapmasını sağlar:

* **Kullanıcı Verilerine Erişim**: Tüm kullanıcı hesaplarından hassas kullanıcı verileri olan posta, mesajlar ve Safari geçmişi gibi verilere erişim sağlar.
* **TCC Atlatması**: TCC (Şeffaflık, Onay ve Kontrol) veritabanını doğrudan manipüle ederek web kamerası, mikrofon ve diğer kaynaklara yetkisiz erişim sağlar.
* **Kalıcılık Oluşturma**: SIP korumalı konumlara kötü amaçlı yazılım yerleştirerek, kök ayrıcalıklarıyla bile kaldırılamaz hale getirir. Bu ayrıca Kötü Amaçlı Yazılım Kaldırma Aracı'nı (MRT) değiştirme potansiyelini içerir.
* **Çekirdek Uzantılarını Yükleme**: Ek güvenlik önlemleri olsa da, SIP'nin atlatılması imzasız çekirdek uzantılarını yükleme işlemini basitleştirir.

### Yükleyici Paketler

**Apple'ın sertifikasıyla imzalanmış yükleyici paketler**, bu korumaları atlayabilir. Bu, standart geliştiriciler tarafından imzalanan paketlerin, SIP korumalı dizinleri değiştirmeye çalıştıklarında engelleneceği anlamına gelir.

### Varolmayan SIP dosyası

Potansiyel bir açık nokta, **`rootless.conf`** dosyasında belirtilen ancak şu anda mevcut olmayan bir dosyanın oluşturulabileceğidir. Kötü amaçlı yazılım, sisteme **kalıcılık oluşturmak** için bunu kullanabilir. Örneğin, kötü niyetli bir program, `/System/Library/LaunchDaemons` dizininde bir .plist dosyası oluşturabilir, `rootless.conf` dosyasında listelenmiş ancak mevcut olmayan bir dosya olduğunda.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
**`com.apple.rootless.install.heritable`** yetkisi SIP'yi atlamaya izin verir
{% endhint%}

#### Shrootless

[**Bu blog yazısındaki araştırmacılar**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) macOS'in Sistem Bütünlük Koruması (SIP) mekanizmasında 'Shrootless' açığı olarak adlandırılan bir zafiyet keşfettiler. Bu zafiyet, **`system_installd`** adlı daemon etrafında dönüyor ve bu daemonun **`com.apple.rootless.install.heritable`** yetkisi bulunuyor, bu da çocuk işlemlerinden herhangi birinin SIP'nin dosya sistem kısıtlamalarını atlamasına izin veriyor.

**`system_installd`** daemonu, **Apple** tarafından imzalanmış paketleri yükler.

Araştırmacılar, bir Apple imzalı paketin (.pkg dosyası) yüklenmesi sırasında, pakette bulunan **post-install** betiklerinin **`system_installd`** tarafından çalıştırıldığını buldular. Bu betikler, varsayılan kabuk olan **`zsh`** tarafından yürütülür ve etkileşimsiz modda bile varsa **`/etc/zshenv`** dosyasından komutları otomatik olarak çalıştırır. Bu davranış saldırganlar tarafından istismar edilebilir: kötü niyetli bir `/etc/zshenv` dosyası oluşturarak ve **`system_installd`**'nin `zsh`'yi çağırmasını bekleyerek cihazda keyfi işlemler gerçekleştirebilirler.

Ayrıca, **`/etc/zshenv`'in yalnızca bir SIP atlatma için değil genel bir saldırı tekniği olarak kullanılabileceği** keşfedildi. Her kullanıcı profili, kök izinleri gerektirmeyen ancak `/etc/zshenv` ile aynı şekilde davranan bir `~/.zshenv` dosyasına sahiptir. Bu dosya, her `zsh` başladığında tetiklenen bir kalıcılık mekanizması olarak veya bir ayrıcalık yükseltme mekanizması olarak kullanılabilir. Bir yönetici kullanıcı `sudo -s` veya `sudo <komut>` kullanarak kök ayrıcalıklarına yükseldiğinde, `~/.zshenv` dosyası tetiklenir ve etkili bir şekilde kök ayrıcalıklara yükselir.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) kapsamında, aynı **`system_installd`** işleminin **post-install betiğini** `/tmp` içindeki SIP tarafından korunan rastgele adlandırılmış bir klasöre yerleştirdiği ve bunun kötüye kullanılabileceği keşfedildi. **`/tmp`'nin kendisinin SIP tarafından korunmadığı** için, bir **sanal görüntü** üzerine **bağlanabilir**, ardından **yükleme** işlemi bu klasöre **post-install betiğini** koyar, sanal görüntüyü **bağlantısız bırakır**, tüm **klasörleri yeniden oluşturur** ve **yürütülecek** **payload** ile **post-installasyon** betiğini **ekler**.

#### [fsck\_cs yardımcı programı](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**'nin sembolik bağlantıları takip edebilme yeteneği nedeniyle önemli bir dosyayı bozacak şekilde yanıltıldığı bir zafiyet tespit edildi. Özellikle, saldırganlar _`/dev/diskX`_ ile `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` dosyası arasında bir bağlantı oluşturdular. _`/dev/diskX`_ üzerinde **`fsck_cs`** çalıştırıldığında, `Info.plist` dosyası bozuldu. Bu dosyanın bütünlüğü, çekirdek uzantılarının yüklenmesini kontrol eden SIP'nin (Sistem Bütünlük Koruma) işletim sistemi için hayati önem taşır. Bozulduğunda, SIP'nin çekirdek hariç tutmaları yönetme yeteneği tehlikeye girer.

Bu zafiyeti sömürmek için kullanılan komutlar:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu zafiyetin sömürülmesinin ciddi sonuçları vardır. Genellikle çekirdek uzantıları için izinleri yönetmekten sorumlu olan `Info.plist` dosyası etkisiz hale gelir. Bu, `AppleHWAccess.kext` gibi belirli uzantıları karalisteleyememe gibi sonuçlar doğurur. Sonuç olarak, SIP'nin kontrol mekanizması devre dışı bırakıldığında, bu uzantı yüklenebilir ve sistem RAM'ine yetkisiz okuma ve yazma erişimi sağlayabilir.

#### [SIP korumalı klasörlerin üzerine bağlama](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP korumalı klasörlerin üzerine yeni bir dosya sistemi bağlamak** korumayı atlamak için mümkün oldu.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Yükseltme atlaması (2016)](https://objective-see.org/blog/blog\_0x14.html)

Sistem, `Install macOS Sierra.app` içindeki gömülü bir kurulum diski görüntüsünden başlatılmak üzere ayarlanmıştır ve `bless` yardımcı programını kullanarak işletim sistemini yükseltir. Kullanılan komut aşağıdaki gibidir:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Süreç güvenliği, bir saldırganın önyükleme yapmadan önce yükseltme görüntüsünü (`InstallESD.dmg`) değiştirmesi durumunda tehlikeye girebilir. Strateji, bir saldırganın dinamik yükleyiciyi (dyld) kötü amaçlı bir sürümle (`libBaseIA.dylib`) değiştirmesini içerir. Bu değişiklik, yükleyici başlatıldığında saldırganın kodunun yürütülmesine neden olur.

Saldırganın kodu, yükseltme süreci sırasında kontrol kazanır ve sistemin yükleyiciye olan güvenini sömürür. Saldırı, `InstallESD.dmg` görüntüsünün `extractBootBits` yöntemine özellikle hedeflenen yöntem sarmalamayla devam eder. Bu, disk görüntüsü kullanılmadan önce kötü amaçlı kodun enjekte edilmesine olanak tanır.

Ayrıca, `InstallESD.dmg` içinde, yükseltme kodunun kök dosya sistemi olarak hizmet eden bir `BaseSystem.dmg` bulunmaktadır. Buna bir dinamik kütüphane enjekte etmek, kötü amaçlı kodun işletim sistemi düzeyindeki dosyaları değiştirebilen bir süreç içinde çalışmasına olanak tanır, sistem tehlikesi potansiyelini önemli ölçüde artırır.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Bu [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) konuşmasında, SIP'yi atlayabilen **`systemmigrationd`**'nin bir **bash** ve bir **perl** betiğini nasıl yürüttüğü ve bu betiklerin **`BASH_ENV`** ve **`PERL5OPT`** ortam değişkenleri aracılığıyla kötüye kullanılabileceği gösterilmektedir.

### **com.apple.rootless.install**

{% hint style="danger" %}
**`com.apple.rootless.install`** yetkisi SIP'yi atlamaya olanak tanır
{% endhint %}

`com.apple.rootless.install` yetkisi, macOS'ta Sistem Bütünlüğü Koruması (SIP) atlamak için bilinmektedir. Bu özellik özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile ilgili olarak belirtilmiştir.

Bu özel durumda, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumunda bulunan sistem XPC hizmeti bu yetkiye sahiptir. Bu, ilgili işlemin SIP kısıtlamalarını atlamasına olanak tanır. Ayrıca, bu hizmet özellikle güvenlik önlemleri uygulamadan dosyaların taşınmasına izin veren bir yöntem sunar.

## Mühürlü Sistem Anlık Görüntüleri

Mühürlü Sistem Anlık Görüntüleri, Apple'ın **macOS Big Sur (macOS 11)**'de tanıttığı bir özellik olup ek bir güvenlik ve sistem kararlılığı katmanı sağlamak için **Sistem Bütünlüğü Koruması (SIP)** mekanizmasının bir parçasıdır. Bunlar, temelde sistem hacminin salt okunur sürümleridir.

İşte daha detaylı bir bakış:

1. **Değişmez Sistem**: Mühürlü Sistem Anlık Görüntüleri, macOS sistem hacmini "değişmez" yapar, yani değiştirilemez. Bu, güvenliği veya sistem kararlılığını tehlikeye atabilecek yetkisiz veya kazara değişiklikleri önler.
2. **Sistem Yazılım Güncellemeleri**: macOS güncellemelerini veya yükseltmelerini yüklediğinizde, macOS yeni bir sistem anlık görüntüsü oluşturur. macOS başlangıç hacmi daha sonra bu yeni görüntüye geçmek için **APFS (Apple Dosya Sistemi)** kullanır. Güncellemelerin uygulanma süreci, sistem güncellemesi sırasında bir sorun çıkarsa sistem her zaman önceki görüntüye geri dönebilir.
3. **Veri Ayrımı**: macOS Catalina'da tanıtılan Veri ve Sistem hacmi ayrımı kavramıyla birlikte, Mühürlü Sistem Anlık Görüntüleri özelliği, tüm verilerinizin ve ayarlarınızın ayrı bir "**Veri**" hacminde depolandığından emin olur. Bu ayrım, verilerinizi sisteme bağımlı olmaktan kurtarır, bu da sistem güncellemelerinin sürecini basitleştirir ve sistem güvenliğini artırır.

Bu anlık görüntülerin macOS tarafından otomatik olarak yönetildiğini ve APFS'nin alan paylaşım yetenekleri sayesinde diskinizde ek alan kaplamadığını unutmayın. Ayrıca, bu anlık görüntülerin, tüm sistemin yedeklerini içeren **Time Machine anlık görüntülerinden** farklı olduğunu belirtmek önemlidir.

### Anlık Görüntüleri Kontrol Etme

**`diskutil apfs list`** komutu, **APFS hacimlerinin detaylarını** ve düzenini listeler:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Önceki çıktıda **kullanıcı erişilebilir konumların** `/System/Volumes/Data` altında bağlandığı görülebilir.

Ayrıca, **macOS Sistem hacmi anlık görüntüsü** `/` altında bağlanır ve **mühürlüdür** (işletim sistemi tarafından kriptografik olarak imzalanmıştır). Bu nedenle, SIP atlanırsa ve değiştirilirse, **işletim sistemi artık başlatılmaz**.

Mührün etkin olup olmadığını **doğrulamak** için şu komutu çalıştırmak mümkündür:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ayrıca, anlık disk de **salt okunur** olarak bağlanır:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
