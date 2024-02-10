# macOS SIP

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a göz atın!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## **Temel Bilgiler**

macOS'teki **System Integrity Protection (SIP)**, en yetkili kullanıcıların bile korumalı sistem klasörlerinde yetkisiz değişiklikler yapmasını engellemek için tasarlanmış bir mekanizmadır. Bu özellik, korunan alanlarda dosya ekleme, değiştirme veya silme gibi eylemleri kısıtlayarak sistemin bütünlüğünü korumada önemli bir rol oynar. SIP tarafından korunan temel klasörler şunlardır:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIP'nin davranışını belirleyen kurallar, **`/System/Library/Sandbox/rootless.conf`** konfigürasyon dosyasında tanımlanır. Bu dosyanın içinde, yıldız (*) ile başlayan yollar, aksi takdirde sıkı SIP kısıtlamalarına istisna olarak belirtilir.

Aşağıdaki örneği düşünün:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Bu parça, SIP'nin genel olarak **`/usr`** dizinini güvence altına aldığını, ancak (`/usr/libexec/cups`, `/usr/local` ve `/usr/share/man`) gibi belirli alt dizinlerde değişikliklere izin verildiğini göstermektedir. Bu izinler, yolun önünde (*) işareti ile belirtilir.

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
İşte, **`restricted`** bayrağı, `/usr/libexec` dizininin SIP tarafından korunduğunu gösterir. SIP korumalı bir dizinde, dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Ayrıca, bir dosya **`com.apple.rootless`** genişletilmiş **özniteliğini** içeriyorsa, bu dosya da **SIP tarafından korunur**.

**SIP ayrıca diğer kök eylemlerini de sınırlar**:

* Güvenilmeyen çekirdek uzantılarını yükleme
* Apple tarafından imzalanan işlemler için görev bağlantılarını alma
* NVRAM değişkenlerini değiştirme
* Çekirdek hata ayıklamaya izin verme

Seçenekler, bir bit bayrağı olarak nvram değişkeninde tutulur (Intel için `csr-active-config` ve ARM için önyüklü Aygıt Ağacından `lp-sip0` okunur). Bayrakları XNU kaynak kodunda `csr.sh` dosyasında bulabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

Sisteminizde SIP'nin etkin olup olmadığını aşağıdaki komutla kontrol edebilirsiniz:
```bash
csrutil status
```
SIP'yi devre dışı bırakmanız gerekiyorsa, bilgisayarınızı kurtarma modunda yeniden başlatmanız gerekmektedir (başlatma sırasında Command+R tuşlarına basarak), ardından aşağıdaki komutu çalıştırın:
```bash
csrutil disable
```
SIP'yi etkin tutmak isterseniz ancak hata ayıklama korumalarını kaldırmak isterseniz, bunu aşağıdaki şekilde yapabilirsiniz:
```bash
csrutil enable --without debug
```
### Diğer Kısıtlamalar

- **Onaylanmamış çekirdek uzantılarının** (kexts) yüklenmesine izin vermez, yalnızca doğrulanmış uzantıların sistem çekirdeğiyle etkileşime girmesini sağlar.
- macOS sistem süreçlerinin **hata ayıklanmasını engeller**, çekirdek sistem bileşenlerini yetkisiz erişim ve değişikliklerden korur.
- dtrace gibi **araçların sistem süreçlerini incelemesini engeller**, sistem işleyişinin bütünlüğünü daha da korur.

**[Bu konuşmada SIP hakkında daha fazla bilgi edinin](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## SIP Atlamaları

SIP'nin atlanması, bir saldırganın aşağıdaki işlemleri gerçekleştirmesine olanak tanır:

- **Kullanıcı Verilerine Erişim**: Tüm kullanıcı hesaplarından hassas kullanıcı verilerini (posta, mesajlar ve Safari geçmişi gibi) okuma.
- **TCC Atlaması**: TCC (Şeffaflık, Onay ve Kontrol) veritabanını doğrudan manipüle ederek web kamerası, mikrofon ve diğer kaynaklara yetkisiz erişim sağlama.
- **Kalıcılık Kurma**: Malware'yi SIP korumalı konumlara yerleştirerek, kök ayrıcalıklarıyla bile kaldırılamaz hale getirme. Bu aynı zamanda Malware Kaldırma Aracı'nın (MRT) manipüle edilme potansiyelini de içerir.
- **Çekirdek Uzantıları Yükleme**: Ek güvenlik önlemleri olsa da, SIP'nin atlanması, onaylanmamış çekirdek uzantılarının yüklenme sürecini basitleştirir.

### Yükleyici Paketleri

**Apple'ın sertifikasıyla imzalanan yükleyici paketleri**, bu korumaları atlatabilir. Bu, standart geliştiriciler tarafından imzalanan paketlerin bile SIP korumalı dizinleri değiştirmeye çalıştığında engelleneceği anlamına gelir.

### Varolmayan SIP Dosyası

Potansiyel bir açık nokta, **`rootless.conf`** dosyasında belirtilen ancak mevcut olmayan bir dosyanın oluşturulabilmesidir. Kötü amaçlı yazılım, bu durumu kullanarak sisteme **kalıcılık sağlayabilir**. Örneğin, kötü amaçlı bir program, `rootless.conf` dosyasında listelenmiş ancak mevcut olmayan `/System/Library/LaunchDaemons` dizininde bir .plist dosyası oluşturabilir.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
**`com.apple.rootless.install.heritable`** yetkisi, SIP'nin atlanmasına izin verir.
{% endhint %}

#### Shrootless

[**Bu blog yazısındaki araştırmacılar**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/), macOS'in Sistem Bütünlük Koruması (SIP) mekanizmasında 'Shrootless' adı verilen bir zafiyet keşfettiler. Bu zafiyet, **`system_installd`** adlı hizmet süreci etrafında dönüyor ve bu sürecin **`com.apple.rootless.install.heritable`** yetkisi, SIP'nin dosya sistemi kısıtlamalarını atlamak için herhangi bir alt sürecine izin veriyor.

**`system_installd`** hizmet süreci, **Apple** tarafından imzalanan paketleri yükler.

Araştırmacılar, Apple tarafından imzalanan bir paketin (.pkg dosyası) kurulumu sırasında, pakete dahil edilen herhangi bir **post-install** betiğini çalıştırır. Bu betikler, varsayılan kabuk olan **`zsh`** tarafından yürütülür ve etkileşimli olmayan modda bile **`/etc/zshenv`** dosyasından komutları otomatik olarak çalıştırır. Bu davranış saldırganlar tarafından istismar edilebilir: kötü niyetli bir `/etc/zshenv` dosyası oluşturarak ve **`system_installd`**'nin `zsh`'yi çağırmasını bekleyerek, cihaz üzerinde keyfi işlemler gerçekleştirebilirler.

Ayrıca, **`/etc/zshenv`'nin yalnızca bir SIP atlama tekniği olarak değil, genel bir saldırı tekniği olarak da kullanılabileceği** keşfedildi. Her kullanıcı profili, `/etc/zshenv` ile aynı şekilde davranan bir `~/.zshenv` dosyasına sahiptir, ancak kök izinleri gerektirmez. Bu dosya, her `zsh` başladığında tetiklenen bir kalıcılık mekanizması olarak veya bir ayrıcalık yükseltme mekanizması olarak kullanılabilir. Bir yönetici kullanıcısı `sudo -s` veya `sudo <komut>` kullanarak köke yükseldiğinde, `~/.zshenv` dosyası tetiklenir ve etkili bir şekilde köke yükselir.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) içinde aynı **`system_installd`** sürecinin hala kötüye kullanılabileceği keşfedildi, çünkü **post-install betiği**ni **SIP tarafından korunan rastgele adlandırılmış bir klasöre** yerleştiriyordu. Sorun şu ki, **`/tmp` SIP tarafından korunmamaktadır**, bu yüzden üzerine bir **sanal görüntü bağlanabilir**, ardından **yükleyici** bu klasöre **post-install betiğini** yerleştirir, sanal görüntüyü **ayırır**, tüm **klasörleri yeniden oluşturur** ve **yürütülecek** **payload** ile **post-installation** betiğini ekler.

#### [fsck\_cs yardımcı programı](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**'nin **sembolik bağlantıları takip edebilme** yeteneği nedeniyle, **`fsck_cs`**'nin önemli bir dosyayı bozmasına neden olacak şekilde yanıltıldığı bir zafiyet tespit edildi. Saldırganlar özellikle _`/dev/diskX`_ ile `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` dosyası arasında bir bağlantı oluşturdu. **`fsck_cs`**'yi _`/dev/diskX`_ üzerinde çalıştırmak, `Info.plist`'in bozulmasına yol açtı. Bu dosyanın bütünlüğü, çekirdek uzantılarının yüklenmesini kontrol eden sistem bütünlük koruması (SIP) için hayati önem taşır. Bir kez bozulduğunda, SIP'nin çekirdek hariç tutmaları yönetme yeteneği tehlikeye girer.

Bu zafiyeti istismar etmek için kullanılan komutlar:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu güvenlik açığının sömürülmesi ciddi sonuçları beraberinde getirir. Normalde çekirdek uzantıları için izinleri yöneten `Info.plist` dosyası etkisiz hale gelir. Bu, `AppleHWAccess.kext` gibi belirli uzantıları kara listeye alma yeteneğinin olmamasını içerir. Sonuç olarak, SIP'nin kontrol mekanizması bozulduğunda, bu uzantı yüklenebilir ve sistem RAM'ine yetkisiz okuma ve yazma erişimi sağlar.


#### [SIP korumalı klasörlerin üzerine bağlama](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP korumalı klasörlerin üzerine yeni bir dosya sistemi bağlamak**, korumayı atlamak için mümkün oldu.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Yükseltici atlatma (2016)](https://objective-see.org/blog/blog\_0x14.html)

Sistem, işletim sistemini yükseltmek için `Install macOS Sierra.app` içinde yer alan bir yerleşik kurulum diski görüntüsünden başlatılmak üzere yapılandırılmıştır ve `bless` yardımcı programı kullanılmaktadır. Kullanılan komut aşağıdaki gibidir:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bu sürecin güvenliği, saldırganın başlatmadan önce yükseltme görüntüsünü (`InstallESD.dmg`) değiştirmesi durumunda tehlikeye girebilir. Strateji, kötü niyetli bir sürüm (`libBaseIA.dylib`) ile bir dinamik yükleyiciyi (dyld) değiştirmeyi içerir. Bu değiştirme, yükleyici başlatıldığında saldırganın kodunun yürütülmesine neden olur.

Saldırganın kodu, yükseltme süreci sırasında kontrol kazanır ve sistemin yükleyiciye olan güvenini istismar eder. Saldırı, `InstallESD.dmg` görüntüsünün `extractBootBits` yöntemine özellikle hedeflenen yöntem sarmalamayla değiştirilerek devam eder. Bu, disk görüntüsü kullanılmadan önce kötü amaçlı kodun enjekte edilmesine olanak tanır.

Ayrıca, `InstallESD.dmg` içinde, yükseltme kodunun kök dosya sistemi olarak hizmet eden bir `BaseSystem.dmg` bulunur. Bu dinamik bir kitaplığın enjekte edilmesi, kötü amaçlı kodun, işletim sistemi düzeyindeki dosyaları değiştirebilen bir işlem içinde çalışmasına olanak tanır ve sistem tehlikesini önemli ölçüde artırır.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Bu [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) konuşmasında, SIP'yi atlayabilen **`systemmigrationd`**'nin bir **bash** ve bir **perl** betiğini nasıl yürüttüğü gösterilmektedir ve bu, env değişkenleri **`BASH_ENV`** ve **`PERL5OPT`** aracılığıyla kötüye kullanılabilir.

### **com.apple.rootless.install**

{% hint style="danger" %}
**`com.apple.rootless.install`** yetkisi, SIP'yi atlamaya izin verir
{% endhint %}

`com.apple.rootless.install` yetkisi, macOS'ta Sistem Bütünlüğü Koruması'nı (SIP) atlamak için kullanıldığı bilinmektedir. Bu özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile ilgili olarak belirtilmiştir.

Bu özel durumda, bu yetkiye sahip olan sistem XPC hizmeti, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumunda bulunur. Bu, ilgili işlemin SIP kısıtlamalarını atlamasına olanak tanır. Ayrıca, bu hizmet, herhangi bir güvenlik önlemi uygulamadan dosyaların taşınmasına izin veren bir yöntem sunar.

## Mühürlü Sistem Anlık Görüntüleri

Mühürlü Sistem Anlık Görüntüleri, Apple'ın **macOS Big Sur (macOS 11)**'de tanıttığı bir özelliktir ve ek bir güvenlik ve sistem istikrarı katmanı sağlamak için **Sistem Bütünlüğü Koruması (SIP)** mekanizmasının bir parçası olarak sunulur. Bunlar, temelde sistem hacminin değiştirilemez bir sürümüdür.

Daha ayrıntılı bir bakış:

1. **Değiştirilemez Sistem**: Mühürlü Sistem Anlık Görüntüleri, macOS sistem hacmini "değiştirilemez" yapar, yani değiştirilemez. Bu, güvenliği veya sistem istikrarını tehlikeye atabilecek herhangi bir yetkisiz veya kazara sistem değişikliğini önler.
2. **Sistem Yazılımı Güncellemeleri**: macOS güncellemelerini veya yükseltmelerini yüklediğinizde, macOS yeni bir sistem anlık görüntüsü oluşturur. macOS başlangıç ​​hacmi daha sonra bu yeni anlık görüntüye geçmek için **APFS (Apple Dosya Sistemi)**'ni kullanır. Güncelleme işleminin tamamı, sistem güncellemesi sırasında bir şeyler yanlış giderse her zaman önceki anlık görüntüye geri dönülebilmesi nedeniyle daha güvenli ve daha güvenilir hale gelir.
3. **Veri Ayrımı**: macOS Catalina'da tanıtılan Veri ve Sistem hacmi ayrımı kavramıyla birlikte, Mühürlü Sistem Anlık Görüntüsü özelliği, tüm verilerinizin ve ayarlarınızın ayrı bir "**Veri**" hacminde depolanmasını sağlar. Bu ayrım, verilerinizi sistemden bağımsız hale getirir ve sistem güncelleme sürecini basitleştirir ve sistem güvenliğini artırır.

Bu anlık görüntülerin macOS tarafından otomatik olarak yönetildiğini ve APFS'nin alan paylaşma yetenekleri sayesinde diskinizde ek alan kaplamadığını unutmayın. Ayrıca, bu anlık görüntüler, tüm sistemin kullanıcı tarafından erişilebilir yedeklemeleri olan **Time Machine anlık görüntülerinden** farklıdır.

### Anlık Görüntüleri Kontrol Etme

**`diskutil apfs list`** komutu, **APFS hacimlerinin** ayrıntılarını ve düzenini listeler:

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

Önceki çıktıda, **kullanıcı tarafından erişilebilen konumların** `/System/Volumes/Data` altında bağlandığı görülebilir.

Ayrıca, **macOS Sistem hacmi anlık görüntüsü** `/` altında bağlanır ve **mühürlüdür** (OS tarafından kriptografik olarak imzalanmıştır). Bu nedenle, SIP atlanır ve değiştirilirse, **işletim sistemi artık başlatılamaz**.

Mührün etkin olduğunu **doğrulamak** için aşağıdaki komutu çalıştırabilirsiniz:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ayrıca, anlık görüntü diski de **salt okunur** olarak bağlanır:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
