# macOS Dosyaları, Klasörleri, İkili Dosyalar ve Bellek

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Dosya hiyerarşisi düzeni

* **/Applications**: Yüklenen uygulamalar burada olmalıdır. Tüm kullanıcılar bunlara erişebilir.
* **/bin**: Komut satırı ikili dosyaları
* **/cores**: Var ise, çekirdek dökümlerini depolamak için kullanılır
* **/dev**: Her şey bir dosya olarak işlendiği için burada donanım cihazları bulunabilir.
* **/etc**: Yapılandırma dosyaları
* **/Library**: Tercihler, önbellekler ve günlüklerle ilgili birçok alt dizin ve dosya burada bulunabilir. Kök dizinde ve her kullanıcının dizininde bir Kütüphane klasörü bulunur.
* **/private**: Belgelenmemiş, ancak bahsedilen birçok klasör özel dizine sembolik bağlantılardır.
* **/sbin**: Temel sistem ikili dosyaları (yönetimle ilgili)
* **/System**: OS X'in çalışmasını sağlayan dosya. Burada genellikle yalnızca Apple'a özgü dosyalar bulunur (üçüncü taraf değil).
* **/tmp**: Dosyalar 3 gün sonra silinir (bu, /private/tmp'ye bir sembolik bağlantıdır)
* **/Users**: Kullanıcıların ev dizini.
* **/usr**: Yapılandırma ve sistem ikili dosyaları
* **/var**: Günlük dosyaları
* **/Volumes**: Bağlanan sürücüler burada görünecektir.
* **/.vol**: `stat a.txt` komutunu çalıştırarak `16777223 7545753 -rw-r--r-- 1 kullanıcıadı wheel ...` gibi bir şey elde edersiniz, burada ilk sayı dosyanın bulunduğu birim numarası ve ikinci sayı inode numarasıdır. Bu dosyanın içeriğine /.vol/ ile o bilgiyi kullanarak erişebilirsiniz `cat /.vol/16777223/7545753`

### Uygulama Klasörleri

* **Sistem uygulamaları** `/System/Applications` altında bulunur
* **Yüklenen** uygulamalar genellikle `/Applications` veya `~/Applications` içinde yüklenir
* **Uygulama verileri**, kök olarak çalışan uygulamalar için `/Library/Application Support` içinde ve kullanıcı olarak çalışan uygulamalar için `~/Library/Application Support` içinde bulunabilir.
* **Root olarak çalışması gereken** üçüncü taraf uygulama **daemonları** genellikle `/Library/PrivilegedHelperTools/` içinde bulunur
* **Kumlanmış** uygulamalar `~/Library/Containers` klasörüne eşlenir. Her uygulamanın, uygulamanın paket kimliğine (`com.apple.Safari`) göre adlandırılmış bir klasörü vardır.
* **Çekirdek** `/System/Library/Kernels/kernel` içinde bulunur
* **Apple'ın çekirdek uzantıları** `/System/Library/Extensions` içinde bulunur
* **Üçüncü taraf çekirdek uzantıları** `/Library/Extensions` içinde saklanır

### Hassas Bilgiler İçeren Dosyalar

MacOS, şifreler gibi bilgileri çeşitli yerlerde saklar:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Zafiyetli pkg Yükleyicileri

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X Özel Uzantıları

* **`.dmg`**: Apple Disk Görüntü dosyaları, yükleyiciler için çok yaygındır.
* **`.kext`**: Belirli bir yapıyı takip etmelidir ve bir sürücünün OS X sürümüdür. (bir paket)
* **`.plist`**: Ayrıca özellik listesi olarak da bilinen bilgileri XML veya ikili biçimde depolar.
* XML veya ikili olabilir. İkili olanlar şunlarla okunabilir:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Dizin yapısını takip eden Apple uygulamaları (Bir paket).
* **`.dylib`**: Dinamik kitaplıklar (Windows DLL dosyaları gibi)
* **`.pkg`**: xar (eXtensible Archive format) ile aynıdır. İçeriğini yüklemek için installer komutu kullanılabilir.
* **`.DS_Store`**: Bu dosya her dizinde bulunur, dizinin özniteliklerini ve özelleştirmelerini kaydeder.
* **`.Spotlight-V100`**: Bu klasör, sistemdeki her bir birimin kök dizininde görünür.
* **`.metadata_never_index`**: Bu dosya bir birimin kökünde bulunuyorsa Spotlight o birimi dizine eklemeyecektir.
* **`.noindex`**: Bu uzantıya sahip dosya ve klasörler Spotlight tarafından dizine eklenmeyecektir.

### macOS Paketleri

Bir paket, Finder'da bir nesne gibi görünen bir **dizindir** (Bir paket örneği `*.app` dosyalarıdır).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Paylaşılan Önbelleği

MacOS'ta (ve iOS'ta) tüm sistem paylaşılan kitaplıklar, çerçeveler ve dylib'ler gibi, **tek bir dosyada**, dyld paylaşılan önbelleğine adı verilen bir dosyada birleştirilir. Bu, kodun daha hızlı yüklenmesini sağlar.

Dyld paylaşılan önbellek gibi, çekirdek ve çekirdek uzantıları da önyüklendiği bir çekirdek önbelleğine derlenir ve önyükleme sırasında yüklenir.

Tek dosyadan dylib paylaşılan önbellekten kitaplıkları çıkarmak için eskiden kullanılan [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) adlı ikili dosya günümüzde çalışmayabilir, ancak [**dyldextractor**](https://github.com/arandomdev/dyldextractor) kullanabilirsiniz:

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

Eski sürümlerde **paylaşılan önbelleği** **`/System/Library/dyld/`** içinde bulabilirsiniz.

iOS'te bunları **`/System/Library/Caches/com.apple.dyld/`** içinde bulabilirsiniz.

{% hint style="success" %}
`dyld_shared_cache_util` aracı çalışmasa bile, **paylaşılan dyld ikilisini Hopper'a** geçirebilir ve Hopper tüm kütüphaneleri tanımlayabilir ve **hangisini** incelemek istediğinizi **seçmenize** izin verecektir:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Özel Dosya İzinleri

### Klasör izinleri

Bir **klasörde**, **okuma** onu **listelemenize**, **yazma** onun üzerindeki dosyaları **silmenize** ve **yazmanıza**, **yürütme** ise dizini **gezinmenize** izin verir. Örneğin, bir kullanıcının **okuma izni** olduğu bir dizinde, **yürütme izni olmadığı** bir dosyayı **okuyamaz**.

### Bayrak değiştiricileri

Dosyalara ayarlanabilecek bazı bayraklar vardır ve bu bayraklar dosyanın farklı davranmasını sağlar. Bir dizindeki dosyaların bayraklarını `ls -lO /path/directory` komutuyla kontrol edebilirsiniz.

* **`uchg`**: **uchange** bayrağı olarak bilinen bu bayrak, **dosyanın değiştirilmesini veya silinmesini engeller**. Bayrağı ayarlamak için: `chflags uchg file.txt`
* Kök kullanıcı bayrağı **kaldırabilir** ve dosyayı değiştirebilir.
* **`restricted`**: Bu bayrak, dosyanın **SIP tarafından korunmasını** sağlar (bu bayrağı bir dosyaya ekleyemezsiniz).
* **`Sticky bit`**: Sticky bit'e sahip bir dizinde, **yalnızca** dizinin **sahibi veya kök** dosyaları **yeniden adlandırabilir veya silebilir**. Genellikle bu, /tmp dizininde, normal kullanıcıların diğer kullanıcıların dosyalarını silmesini veya taşımasını engellemek için ayarlanır.

### **Dosya ACL'leri**

Dosya **ACL'leri**, farklı kullanıcılara daha **ayrıntılı izinler** atayabileceğiniz **ACE** (Erişim Kontrol Girişleri) içerir.

Bir **dizine** bu izinleri verebilirsiniz: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Ve bir **dosyaya**: `read`, `write`, `append`, `execute`.

Dosya ACL'leri içeren bir dosyada, izinleri **listelerken** "+" işaretini **bulacaksınız** gibi:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Dosyanın ACL'lerini aşağıdaki komutla **okuyabilirsiniz**:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Aşağıdaki komutla **ACL'ye sahip tüm dosyaları** bulabilirsiniz (bu işlem çok yavaş olabilir):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Kaynak Çatalları | macOS ADS

Bu, MacOS makinelerinde **Alternatif Veri Akışları** elde etmek için bir yöntemdir. Bir dosyanın içine **com.apple.ResourceFork** adlı bir genişletilmiş öznitelik içinde içerik kaydederek, içeriği **file/..namedfork/rsrc** içinde kaydedebilirsiniz.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Bu genişletilmiş niteliği içeren tüm dosyaları şu şekilde bulabilirsiniz:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Evrensel ikili dosyalar ve** Mach-o Formatı

Mac OS ikili dosyaları genellikle **evrensel ikili dosyalar** olarak derlenir. Bir **evrensel ikili dosya**, aynı dosyada **çoklu mimarileri destekleyebilir**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS bellek dökme

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Mac OS Risk Kategorisi Dosyaları

`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` dizini, **farklı dosya uzantılarıyla ilişkili risk bilgilerinin depolandığı** yerdir. Bu dizin dosyaları çeşitli risk seviyelerine göre kategorize eder ve Safari'nin bu dosyaları indirme işleminden sonra nasıl işleyeceğini etkiler. Kategoriler şunlardır:

- **LSRiskCategorySafe**: Bu kategorideki dosyalar **tamamen güvenli** olarak kabul edilir. Safari, bu dosyaları otomatik olarak indirildikten sonra açar.
- **LSRiskCategoryNeutral**: Bu dosyalar herhangi bir uyarı içermez ve Safari tarafından **otomatik olarak açılmaz**.
- **LSRiskCategoryUnsafeExecutable**: Bu kategoriye ait dosyalar, dosyanın bir uygulama olduğunu belirten bir uyarı **tetikler**. Bu, kullanıcıyı uyarmak için bir güvenlik önlemi olarak hizmet verir.
- **LSRiskCategoryMayContainUnsafeExecutable**: Bu kategori, arşivler gibi bir yürütülebilir içerebilecek dosyalar için kullanılır. Safari, tüm içeriğin güvenli veya tarafsız olduğunu doğrulayamazsa, bir uyarı **tetikler**.

## Günlük dosyaları

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: İndirilen dosyalar hakkında, indirildikleri URL gibi bilgileri içerir.
* **`/var/log/system.log`**: OSX sistemlerinin ana günlüğüdür. syslogging'in yürütülmesinden sorumlu olan com.apple.syslogd.plist'tir (devre dışı bırakılıp bırakılmadığını kontrol etmek için `launchctl list` içinde "com.apple.syslogd" arayabilirsiniz).
* **`/private/var/log/asl/*.asl`**: Bu, ilginç bilgiler içerebilecek Apple Sistem Günlükleridir.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" aracılığıyla son zamanlarda erişilen dosyaları ve uygulamaları depolar.
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Sistem başlatıldığında başlatılacak öğeleri depolar.
* **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility Uygulaması için günlük dosyası (USB dahil sürücüler hakkında bilgi)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Kablosuz erişim noktaları hakkında veri.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Devre dışı bırakılan daemonların listesi.

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'ler**](https://opensea.io/collection/the-peass-family) içerir
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
