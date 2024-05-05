# macOS SIP

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

***

## **Temel Bilgiler**

**macOS'taki Sistem Bütünlük Koruması (SIP)**, en yetkili kullanıcıların bile ana sistem klasörlerine izinsiz değişiklikler yapmasını engellemeyi amaçlayan bir mekanizmadır. Bu özellik, korunan alanlarda dosya eklemeyi, değiştirmeyi veya silmeyi kısıtlayarak sistemin bütünlüğünü korumada kritik bir rol oynar. SIP tarafından korunan başlıca klasörler şunlardır:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIP'nin davranışlarını belirleyen kurallar, genellikle sıkı SIP kısıtlamalarının istisnaları olarak işaretlenen yıldız (\*) ile başlayan yolların bulunduğu **`/System/Library/Sandbox/rootless.conf`** konfigürasyon dosyasında tanımlanmıştır.

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
İşte, **`restricted`** bayrağı, `/usr/libexec` dizininin SIP ile korunduğunu gösterir. Bir SIP korumalı dizinde, dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Ayrıca, bir dosya **`com.apple.rootless`** genişletilmiş **özniteliği** içeriyorsa, o dosya da **SIP ile korunur**.

**SIP ayrıca diğer kök eylemleri de sınırlar**:

* Güvenilmeyen çekirdek uzantılarını yükleme
* Apple tarafından imzalanan işlemler için görev portlarını alma
* NVRAM değişkenlerini değiştirme
* Çekirdek hata ayıklamaya izin verme

Seçenekler, bir bit bayrağı olarak nvram değişkeninde tutulur (`csr-active-config` Intel için ve ARM için önyüklü Cihaz Ağacından `lp-sip0` okunur). Bayrakları `csr.sh` içindeki XNU kaynak kodunda bulabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

Sisteminizde SIP'in etkin olup olmadığını kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
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

* **İmzasız çekirdek uzantılarının** (kexts) yüklenmesine izin verilmez, yalnızca doğrulanmış uzantılar sistem çekirdeğiyle etkileşime geçebilir.
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

**Apple'ın sertifikasıyla imzalanan yükleyici paketler**, bu korumaları atlayabilir. Bu, standart geliştiriciler tarafından imzalanan paketlerin bile SIP korumalı dizinleri değiştirmeye çalıştıklarında engelleneceği anlamına gelir.

### Varolmayan SIP dosyası

Bir dosya **`rootless.conf`** içinde belirtilmişse ancak şu anda mevcut değilse, oluşturulabilir. Kötü amaçlı yazılım, sisteme **kalıcılık oluşturmak** için bunu sömürebilir. Örneğin, kötü amaçlı bir program, `/System/Library/LaunchDaemons` içinde bir .plist dosyası oluşturabilir, eğer `rootless.conf` içinde listelenmişse ancak mevcut değilse.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
**`com.apple.rootless.install.heritable`** yetkisi SIP'yi atlamaya izin verir
{% endhint%}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Sistemin kod imzasını doğruladıktan sonra yükleyici paketini değiştirmenin mümkün olduğu keşfedildi ve ardından sistem orijinal yerine kötü amaçlı paketi yüklerdi. Bu eylemler **`system_installd`** tarafından gerçekleştirildiğinden, SIP'yi atlamaya izin verirdi.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Bir paket bir bağlanabilir görüntüden veya harici sürücüden yüklendiğinde, **yükleyici** binary'yi **o dosya sistemi**nden (SIP korumalı konum yerine) **çalıştırır**, bu da **`system_installd`**'nin keyfi bir binary çalıştırmasına neden olur.

#### CVE-2021-30892 - Shrootless

[**Bu blog gönderisinden araştırmacılar**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) macOS'in Sistem Bütünlük Koruması (SIP) mekanizmasında 'Shrootless' açığı olarak adlandırılan bir zayıflık keşfedildi. Bu zayıflık, 'com.apple.rootless.install.heritable' yetkisine sahip olan **`system_installd`** daemonu etrafında dönüyor ve bu yetki, SIP'nin dosya sistem kısıtlamalarını atlamak için herhangi bir alt işlemine izin verir.

**`system_installd`** daemonu, **Apple** tarafından imzalanmış paketleri yükler.

Araştırmacılar, bir Apple imzalı paketin (.pkg dosyası) yüklenmesi sırasında, pakete dahil edilen herhangi bir **son yükleme** betiğinin **`system_installd`** tarafından çalıştırıldığını bulmuşlardır. Bu betikler varsayılan kabuk olan **`zsh`** tarafından yürütülür ve hatta etkileşimsiz modda bile varsa, **`/etc/zshenv`** dosyasından otomatik olarak komutları çalıştırır. Bu davranış saldırganlar tarafından sömürülebilir: kötü niyetli bir `/etc/zshenv` dosyası oluşturarak ve **`system_installd`'nin `zsh`'yi çağırmasını** bekleyerek, cihazda keyfi işlemler gerçekleştirebilirler.

Ayrıca, **`/etc/zshenv`'nin yalnızca bir SIP atlatma için değil genel bir saldırı tekniği olarak kullanılabileceği** keşfedildi. Her kullanıcı profili, kök izinleri gerektirmeyen ancak her `zsh` başladığında tetiklenen bir `~/.zshenv` dosyasına sahiptir. Bu dosya, her `zsh` başladığında tetiklenen bir kalıcılık mekanizması olarak veya bir ayrıcalık yükseltme mekanizması olarak kullanılabilir. Bir yönetici kullanıcı `sudo -s` veya `sudo <komut>` kullanarak kök ayrıcalıklarına yükseldiğinde, `~/.zshenv` dosyası tetiklenir ve etkili bir şekilde kök ayrıcalıklarına yükselir.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) kapsamında, aynı **`system_installd`** işleminin, **post-install betiğini** `/tmp` içindeki SIP tarafından korunan rastgele adlandırılmış bir klasöre yerleştirdiği ve bunun kötüye kullanılabildiği keşfedildi. **`/tmp`'nin** kendisinin SIP tarafından korunmadığı gerçeği nedeniyle, bir **sanal görüntüyü bağlamak**, ardından **yükleyicinin** oraya **post-install betiğini** yerleştirmesi, sanal görüntüyü **bağlamadan** önce tüm **klasörleri yeniden oluşturması** ve **yürütülecek payload ile post-installasyon** betiğini **eklemesi** mümkün olmuştur.

#### [fsck\_cs yardımcı programı](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**'nin sembolik bağlantıları takip edebilme yeteneği nedeniyle, kritik bir dosyanın bozulmasına neden olacak şekilde yanıltıldığı bir zayıflık tespit edildi. Özellikle, saldırganlar _`/dev/diskX`_ ile `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` dosyası arasında bir bağlantı oluşturmuşlardır. _`/dev/diskX`_ üzerinde **`fsck_cs`** çalıştırmak, `Info.plist`'nin bozulmasına neden olmuştur. Bu dosyanın bütünlüğü, çekirdek uzantılarının yüklenmesini kontrol eden SIP'nin (Sistem Bütünlük Koruma) için hayati önem taşır. Bozulduğunda, SIP'nin çekirdek hariç tutmaları yönetme yeteneği tehlikeye girer.

Bu zafiyeti sömürmek için kullanılan komutlar:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu zafiyetin sömürülmesinin ciddi sonuçları vardır. Normalde çekirdek uzantıları için izinleri yöneten `Info.plist` dosyası etkisiz hale gelir. Bu, `AppleHWAccess.kext` gibi belirli uzantıları karalisteleyememe gibi sonuçları da içerir. Sonuç olarak, SIP'nin kontrol mekanizması bozulduğunda, bu uzantı yüklenebilir ve sistem RAM'ine yetkisiz okuma ve yazma erişimi sağlayabilir.

#### [SIP korumalı klasörlerin üzerine bağlama](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**Koruma önlemini atlamak için SIP korumalı klasörlerin üzerine yeni bir dosya sistemi bağlamak mümkün oldu.**
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Yükselticiyi atlatma (2016)](https://objective-see.org/blog/blog\_0x14.html)

Sistem, `Install macOS Sierra.app` içindeki gömülü bir kurulum diski görüntüsünden önyükleme yapacak şekilde ayarlanmıştır ve işletim sistemini yükseltmek için `bless` yardımcı programını kullanır. Kullanılan komut aşağıdaki gibidir:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Süreç güvenliği, bir saldırganın önyükleme işleminden önce yükseltme imgesini (`InstallESD.dmg`) değiştirmesi durumunda tehlikeye girebilir. Strateji, bir dinamik yükleyiciyi (dyld) kötü amaçlı bir sürümle (`libBaseIA.dylib`) değiştirerek saldırganın kodunun yürütülmesine neden olur.

Saldırganın kodu, yükseltme süreci sırasında kontrolü ele geçirir ve sistemin yükleyiciye olan güvenini sömürür. Saldırı, özellikle `extractBootBits` yöntemine hedeflenen yöntem sarmalamayla `InstallESD.dmg` imgesinin değiştirilmesi yoluyla devam eder. Bu, disk imajının kullanılmadan önce kötü amaçlı kodun enjekte edilmesine olanak tanır.

Ayrıca, `InstallESD.dmg` içinde, yükseltme kodunun kök dosya sistemi olarak hizmet veren bir `BaseSystem.dmg` bulunmaktadır. Buna bir dinamik kitaplık enjekte etmek, kötü amaçlı kodun işletilmesine olanak tanır ve OS seviyesinde dosyaları değiştirebilen bir işlem içinde çalışarak sistem tehlikesi potansiyelini önemli ölçüde artırır.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Bu [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) konuşmasında, SIP'yi atlayabilen **`systemmigrationd`**'nin bir **bash** ve bir **perl** betiğini nasıl yürüttüğü gösterilmektedir ve bu, env değişkenleri **`BASH_ENV`** ve **`PERL5OPT`** aracılığıyla kötüye kullanılabilir.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**Bu blog gönderisinde detaylandırıldığı gibi**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` paketlerinden bir `postinstall` betiği yürütülüyordu:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
Ve ${SHARED_SUPPORT_PATH}/SharedSupport.dmg içinde bir sembolik bağ oluşturmak mümkündü ve bu, bir kullanıcının **SIP korumasını atlayarak herhangi bir dosyayı kısıtlamadan açmasına izin verirdi**.

### **com.apple.rootless.install**

{% hint style="danger" %}
**`com.apple.rootless.install`** yetkisi SIP'i atlamaya izin verir
{% endhint %}

`com.apple.rootless.install` yetkisi, macOS'ta Sistem Bütünlüğü Koruması'nı (SIP) atlamak için bilinmektedir. Bu özellik özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile ilişkilendirilmiştir.

Bu özel durumda, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumunda bulunan sistem XPC servisi bu yetkiye sahiptir. Bu, ilgili işlemin SIP kısıtlamalarını atlamasına olanak tanır. Ayrıca, bu servis, güvenlik önlemleri uygulamadan dosyaların taşınmasına izin veren bir yöntem sunar.

## Mühürlü Sistem Anlık Görüntüleri

Mühürlü Sistem Anlık Görüntüleri, Apple'ın **macOS Big Sur (macOS 11)**'de tanıttığı bir özelliktir ve ek bir güvenlik ve sistem kararlılığı katmanı sağlamak amacıyla **Sistem Bütünlüğü Koruması (SIP)** mekanizmasının bir parçasıdır. Bunlar esasen sistemin sabit diski için salt okunur sürümlerdir.

İşte daha detaylı bir bakış:

1. **Değişmez Sistem**: Mühürlü Sistem Anlık Görüntüleri, macOS sistem diskinin "değişmez" olmasını sağlar, yani değiştirilemez. Bu, güvenliği veya sistem kararlılığını tehlikeye atabilecek herhangi izinsiz veya kazara değişiklikleri önler.
2. **Sistem Yazılım Güncellemeleri**: macOS güncellemelerini veya yükseltmelerini yüklediğinizde, macOS yeni bir sistem anlık görüntüsü oluşturur. macOS başlangıç diski daha sonra bu yeni görüntüye geçmek için **APFS (Apple Dosya Sistemi)** kullanır. Güncellemelerin uygulanma süreci, sistem güncellemesi sırasında bir sorun çıkarsa sistem her zaman önceki görüntüye geri dönebilir.
3. **Veri Ayrımı**: macOS Catalina'da tanıtılan Veri ve Sistem diski ayrımı kavramı ile birlikte, Mühürlü Sistem Anlık Görüntüleri özelliği, tüm veri ve ayarlarınızın ayrı bir "**Veri**" diskinde depolandığından emin olur. Bu ayrım, verilerinizi sisteme bağımlı olmaktan kurtarır, bu da sistem güncellemelerinin sürecini basitleştirir ve sistem güvenliğini artırır.

Bu anlık görüntülerin macOS tarafından otomatik olarak yönetildiğini ve APFS'nin alan paylaşım yetenekleri sayesinde diskinizde ekstra alan kaplamadığını unutmayın. Ayrıca, bu anlık görüntülerin, tüm sistemin yedeklerini kullanıcı erişimine açık olan **Zaman Makinesi anlık görüntülerinden** farklı olduğunu belirtmek önemlidir.

### Anlık Görüntüleri Kontrol Et

**`diskutil apfs list`** komutu, **APFS birimlerinin** ve düzenlerinin ayrıntılarını listeler:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Konteyner Referansı:     disk3
|   Boyut (Kapasite Tavanı):      494384795648 B (494.4 GB)
|   Hacimler Tarafından Kullanılan Kapasite:   219214536704 B (219.2 GB) (kullanılanın %44.3'ü)
|   Ayrılmamış Kapasite:       275170258944 B (275.2 GB) (boş %55.7)
|   |
|   +-&#x3C; Fiziksel Depolama disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Fiziksel Depolama Diski:   disk0s2
|   |   Boyut:                       494384795648 B (494.4 GB)
|   |
|   +-> Hacim disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Hacim Diski (Rol):   disk3s1 (Sistem)
</strong>|   |   Ad:                      Macintosh HD (Büyük/küçük harf duyarsız)
<strong>|   |   Bağlama Noktası:               /System/Volumes/Update/mnt1
</strong>|   |   Kullanılan Kapasite:         12819210240 B (12.8 GB)
|   |   Mühürlü:                    Bozuk
|   |   FileVault:                 Evet (Kilitsiz)
|   |   Şifreli:                 Hayır
|   |   |
|   |   Anlık Görüntü:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Anlık Görüntü Diski:             disk3s1s1
<strong>|   |   Anlık Görüntü Bağlama Noktası:      /
</strong><strong>|   |   Anlık Görüntü Mühürlü:           Evet
</strong>[...]
+-> Hacim disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Hacim Diski (Rol):   disk3s5 (Veri)
|   Ad:                      Macintosh HD - Data (Büyük/küçük harf duyarsız)
<strong>    |   Bağlama Noktası:               /System/Volumes/Data
</strong><strong>    |   Kullanılan Kapasite:         412071784448 B (412.1 GB)
</strong>    |   Mühürlü:                    Hayır
|   FileVault:                 Evet (Kilitsiz)
</code></pre>

Önceki çıktıda **kullanıcı erişilebilir konumların** `/System/Volumes/Data` altında bağlandığı görülebilir.

Ayrıca, **macOS Sistem hacmi anlık görüntüsü** `/` altında bağlanmış ve **mühürlü** (işletim sistemi tarafından kriptografik olarak imzalanmış) durumdadır. Bu nedenle, eğer SIP atlanırsa ve değiştirilirse, **işletim sistemi artık başlatılamaz**.

Mührün etkin olup olmadığını **doğrulamak** için şu komutu çalıştırmak da mümkündür:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ayrıca, anlık disk de **salt okunur** olarak bağlanır:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin</summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
