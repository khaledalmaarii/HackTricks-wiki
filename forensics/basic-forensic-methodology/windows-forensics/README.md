# Windows Sanal Varlıklar

## Windows Sanal Varlıklar

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Genel Windows Sanal Varlıklar

### Windows 10 Bildirimleri

`\Users\<kullanıcıadı>\AppData\Local\Microsoft\Windows\Notifications` yolunda `appdb.dat` (Windows yıldönümünden önce) veya `wpndatabase.db` (Windows Yıldönümünden sonra) adlı veritabanını bulabilirsiniz.

Bu SQLite veritabanı içinde, ilginç veriler içerebilecek tüm bildirimleri (XML formatında) içeren `Notification` tablosunu bulabilirsiniz.

### Zaman Çizelgesi

Zaman Çizelgesi, ziyaret edilen web sayfalarının, düzenlenen belgelerin ve yürütülen uygulamaların **zamansal tarihçesini** sağlayan bir Windows özelliğidir.

Veritabanı `\Users\<kullanıcıadı>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` yolunda bulunur. Bu veritabanı bir SQLite aracıyla veya [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) aracıyla açılabilir **ve 2 dosya oluşturur, bu dosyalar [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) aracıyla açılabilir**.

### ADS (Alternatif Veri Akışları)

İndirilen dosyalar, nasıl indirildiğini gösteren **ADS Zone.Identifier**'ı içerebilir, intranet, internet vb. Dosyanın nereden indirildiğini gösteren **URL** gibi **daha fazla bilgi** içeren bazı yazılımlar (örneğin tarayıcılar) genellikle ekler.

## **Dosya Yedekleri**

### Geri Dönüşüm Kutusu

Vista/Win7/Win8/Win10'da **Geri Dönüşüm Kutusu** sürücünün kökünde (`C:\$Recycle.bin`) bulunabilir.

Bu klasörde bir dosya silindiğinde 2 belirli dosya oluşturulur:

* `$I{id}`: Dosya bilgisi (ne zaman silindiği)
* `$R{id}`: Dosyanın içeriği

![](<../../../.gitbook/assets/image (486).png>)

Bu dosyaları kullanarak silinen dosyaların orijinal adresini ve silindiği tarihi almak için [**Rifiuti**](https://github.com/abelcheung/rifiuti2) aracını kullanabilirsiniz (Vista - Win10 için `rifiuti-vista.exe` kullanın).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Hacim Gölge Kopyaları

Gölge Kopyası, kullanımda oldukları zaman bile bilgisayar dosyalarının veya hacimlerinin **yedek kopyalarını** veya anlık görüntülerini oluşturabilen Microsoft Windows'a dahil edilmiş bir teknolojidir.

Bu yedeklemeler genellikle dosya sisteminin kökündeki `\System Volume Information` dizininde bulunur ve adları aşağıdaki görüntüde gösterilen **UID'lerden** oluşur:

![](<../../../.gitbook/assets/image (520).png>)

Forensik imajı **ArsenalImageMounter** ile bağlayarak, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) aracı bir gölge kopyasını incelemek ve hatta gölge kopya yedeklerinden **dosyaları çıkarmak** için kullanılabilir.

![](<../../../.gitbook/assets/image (521).png>)

Kayıt defteri girdisi `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, **yedeklenmemesi gereken** dosyaları ve anahtarları içerir:

![](<../../../.gitbook/assets/image (522).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` kayıt defteri ayrıca `Hacim Gölge Kopyaları` hakkında yapılandırma bilgilerini içerir.

### Ofis Otomatik Kaydedilen Dosyalar

Ofis otomatik kaydedilen dosyaları şurada bulabilirsiniz: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Kabuk Öğeleri

Bir kabuk öğesi, başka bir dosyaya erişim bilgilerini içeren bir öğedir.

### Son Belgeler (LNK)

Windows, kullanıcı **bir dosyayı açtığında, kullanırken veya oluşturduğunda** bu **kısayolları otomatik olarak oluşturur**:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Bir klasör oluşturulduğunda, klasöre, üst klasöre ve büyük üst klasöre bir bağlantı da oluşturulur.

Bu otomatik olarak oluşturulan bağlantı dosyaları, köken hakkında bilgi içerir, dosya mı yoksa klasör mü olduğu, o dosyanın **MAC zamanları**, dosyanın nerede depolandığına dair **hacim bilgileri** ve **hedef dosyanın klasörü**. Bu bilgiler, silinmiş olsalar bile bu dosyaları kurtarmak için faydalı olabilir.

Ayrıca, bağlantı dosyasının **oluşturulma tarihi**, orijinal dosyanın **ilk kez kullanıldığı zaman** ve bağlantı dosyasının **değiştirilme tarihi**, orijinal dosyanın **en son ne zaman kullanıldığı** zamanıdır.

Bu dosyaları incelemek için [**LinkParser**](http://4discovery.com/our-tools/) aracını kullanabilirsiniz.

Bu araçta **2 set** zaman damgası bulacaksınız:

* **İlk Set:**
1. Dosya Değiştirme Tarihi
2. Dosya Erişim Tarihi
3. Dosya Oluşturma Tarihi
* **İkinci Set:**
1. Bağlantı Değiştirme Tarihi
2. Bağlantı Erişim Tarihi
3. Bağlantı Oluşturma Tarihi.

İlk zaman damgası seti **dosyanın zaman damgalarına** referans verir. İkinci set, **bağlı dosyanın zaman damgalarına** referans verir.

Aynı bilgilere erişmek için Windows CLI aracını çalıştırabilirsiniz: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### Jumplists

Bu, her uygulama için gösterilen son dosyalardır. **Uygulama tarafından kullanılan son dosyaların listesi**'dir ve her uygulamada erişebileceğiniz bir listedir. Bunlar **otomatik olarak oluşturulabilir veya özel olabilir**.

Otomatik oluşturulan **jumplist'ler**, `C:\Users\{kullanıcıadı}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` dizininde saklanır. Jumplist'ler, başlangıç ​​ID'si uygulamanın ID'si olan `{id}.autmaticDestinations-ms` formatını takip eder.

Özel jumplist'ler, `C:\Users\{kullanıcıadı}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` dizininde saklanır ve genellikle uygulama tarafından dosya ile ilgili bir şeyin **önemli** olduğu belirtildiğinde oluşturulur (belki favori olarak işaretlenmiştir).

Herhangi bir jumplist'in **oluşturulma zamanı**, dosyanın **erişildiği ilk zamanı** gösterir ve **değiştirilme zamanı** ise son zamanı gösterir.

[JumplistExplorer](https://ericzimmerman.github.io/#!index.md) kullanarak jumplist'leri inceleyebilirsiniz.

![](<../../../.gitbook/assets/image (474).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasıyla ilgili olduğunu unutmayın_)

### Shellbags

[**Shellbags'ın ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB'lerinin Kullanımı

Bir USB cihazının kullanıldığını belirlemek mümkündür çünkü şunlar oluşturulur:

* Windows Son Klasörü
* Microsoft Office Son Klasörü
* Jumplist'ler

Bazı LNK dosyalarının orijinal yola değil, WPDNSE klasörüne işaret ettiğini unutmayın:

![](<../../../.gitbook/assets/image (476).png>)

WPDNSE klasöründeki dosyalar orijinal dosyaların bir kopyasıdır, bu nedenle PC'nin yeniden başlatılmasını sağlamazlar ve GUID bir shellbag'den alınır.

### Kayıt Defteri Bilgileri

USB bağlı cihazlar hakkında ilginç bilgiler içeren kayıt defteri anahtarlarının neler olduğunu öğrenmek için [bu sayfaya bakın](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB bağlantısının ne zaman oluşturulduğu hakkında zaman damgalarını almak için `C:\Windows\inf\setupapi.dev.log` dosyasını kontrol edin ( `Section start` için arama yapın).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Dedektifi

[**USBDetective**](https://usbdetective.com), bir görüntüye bağlanmış USB cihazları hakkında bilgi edinmek için kullanılabilir.

![](<../../../.gitbook/assets/image (483).png>)

### Tak ve Çalıştır Temizliği

'Plug and Play Temizliği' olarak bilinen zamanlanmış görev, eski sürücü sürümlerinin kaldırılması için tasarlanmıştır. En son sürücü paketi sürümünü koruma amacıyla belirtilen amacının aksine, çevrimiçi kaynaklar, son 30 günde kullanılmayan sürücülerin hedef alındığını öne sürmektedir. Sonuç olarak, son 30 günde bağlı olmayan taşınabilir cihazlar için sürücüler silinebilir.

Görev aşağıdaki dizinde bulunur:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Görevin içeriğini gösteren bir ekran görüntüsü sağlanmıştır:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Görevin Ana Bileşenleri ve Ayarları:**
- **pnpclean.dll**: Bu DLL, gerçek temizleme işleminden sorumludur.
- **UseUnifiedSchedulingEngine**: `TRUE` olarak ayarlanmıştır, genel görev zamanlama motorunun kullanıldığını gösterir.
- **MaintenanceSettings**:
- **Dönem ('P1M')**: Görev Zamanlayıcısını, düzenli Otomatik bakım sırasında aylık olarak temizlik görevini başlatmaya yönlendirir.
- **Son Tarih ('P2M')**: Görevin iki ardışık ay için başarısız olması durumunda, acil Otomatik bakım sırasında görevi yürütmek üzere Zamanlayıcıya talimat verir.

Bu yapılandırma, sürücülerin düzenli bakımını ve temizliğini sağlar ve ardışık başarısızlıklar durumunda görevin tekrar denemesi için hükümler içerir.

**Daha fazla bilgi için kontrol edin:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-postalar

E-postaların **2 ilginç bölümü vardır: Başlıklar ve e-posta içeriği**. **Başlıklar** içinde şu bilgileri bulabilirsiniz:

* E-postaları **kimin** gönderdiği (e-posta adresi, IP, e-postayı yönlendiren posta sunucuları)
* E-postanın ne zaman gönderildiği

Ayrıca, `References` ve `In-Reply-To` başlıklarında mesajların kimliğini bulabilirsiniz:

![](<../../../.gitbook/assets/image (484).png>)

### Windows Posta Uygulaması

Bu uygulama e-postaları HTML veya metin olarak kaydeder. E-postaları `\Users\<kullanıcıadı>\AppData\Local\Comms\Unistore\data\3\` içindeki alt klasörlerde bulabilirsiniz. E-postalar `.dat` uzantısıyla kaydedilir.

E-postaların **meta verileri** ve **kişileri** **EDB veritabanı** içinde bulunabilir: `\Users\<kullanıcıadı>\AppData\Local\Comms\UnistoreDB\store.vol`

Dosyanın uzantısını `.vol` yerine `.edb` olarak değiştirerek [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) aracını kullanabilirsiniz. `Message` tablosu içinde e-postaları görebilirsiniz.

### Microsoft Outlook

Exchange sunucuları veya Outlook istemcileri kullanıldığında bazı MAPI başlıkları olacaktır:

* `Mapi-Client-Submit-Time`: E-postanın gönderildiği sistem saati
* `Mapi-Conversation-Index`: Konunun çocuk mesajlarının sayısı ve konunun her mesajının zaman damgası
* `Mapi-Entry-ID`: Mesaj kimliği.
* `Mappi-Message-Flags` ve `Pr_last_Verb-Executed`: MAPI istemcisi hakkında bilgiler (mesaj okundu mu? okunmadı mı? yanıtlandı mı? yönlendirildi mi? ofiste değil mi?)

Microsoft Outlook istemcisinde, gönderilen/alınan tüm mesajlar, kişiler verisi ve takvim verisi şu dizinde bir PST dosyasında saklanır:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Kullanılan dosyayı gösteren kayıt defteri yolu `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`'tur.

PST dosyasını [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) aracını kullanarak açabilirsiniz.

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST Dosyaları

Bir **OST dosyası**, Microsoft Outlook'un **IMAP** veya **Exchange** sunucusu ile yapılandırıldığında oluşturulur ve bir PST dosyasına benzer bilgileri depolar. Bu dosya, sunucu ile senkronize edilir, verileri **son 12 ay** boyunca **maksimum 50GB** boyutunda saklar ve PST dosyası ile aynı dizinde bulunur. Bir OST dosyasını görüntülemek için [**Kernel OST görüntüleyici**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.

### Ek Dosyaları Kurtarma

Kaybolan ek dosyalar aşağıdaki yerlerden kurtarılabilir:

- **IE10 için**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 ve üstü için**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Dosyaları

**Thunderbird**, verileri depolamak için **MBOX dosyalarını** kullanır ve dosyaları `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` dizininde bulunur.

### Görüntü Önizlemeleri

- **Windows XP ve 8-8.1**: Önizlemeleri olan bir klasöre erişmek, silinmesinden sonra bile görüntü önizlemelerini depolayan bir `thumbs.db` dosyası oluşturur.
- **Windows 7/10**: `thumbs.db`, UNC yolu üzerinden bir ağa erişildiğinde oluşturulur.
- **Windows Vista ve daha yeni sürümler**: Önizleme önizlemeleri `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` dizininde **thumbcache\_xxx.db** adlı dosyalarla merkezi olarak saklanır. Bu dosyaları görüntülemek için [**Thumbsviewer**](https://thumbsviewer.github.io) ve [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) araçları kullanılabilir.

### Windows Kayıt Defteri Bilgileri

Geniş sistem ve kullanıcı etkinlik verilerini depolayan Windows Kayıt Defteri, şu dosyalarda bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` alt anahtarları için `%windir%\System32\Config`.
- `HKEY_CURRENT_USER` için `%UserProfile%{User}\NTUSER.DAT`.
- Windows Vista ve sonraki sürümler, `HKEY_LOCAL_MACHINE` kayıt defteri dosyalarını `%Windir%\System32\Config\RegBack\` dizininde yedekler.
- Ayrıca, program yürütme bilgileri, Windows Vista ve Windows 2008 Server'dan itibaren `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` dosyasında saklanır.

### Araçlar

Kayıt defteri dosyalarını analiz etmek için bazı araçlar şunlardır:

* **Kayıt Düzenleyici**: Windows'ta yüklüdür. Geçerli oturumun Windows kayıt defterinde gezinmek için bir GUI sağlar.
* [**Kayıt Düzenleyici**](https://ericzimmerman.github.io/#!index.md): Kayıt dosyasını yüklemenize ve GUI ile gezinmenize olanak tanır. Ayrıca ilginç bilgiler içeren anahtarları vurgulayan yer işaretleri içerir.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen kayıt defterinde gezinmenize izin veren bir GUI'ye sahiptir ve yüklenen kayıt defterindeki ilginç bilgileri vurgulayan eklentiler içerir.
* [**Windows Kayıt Defteri Kurtarma**](https://www.mitec.cz/wrr.html): Kayıt defterinden önemli bilgileri çıkarmak için yetenekli başka bir GUI uygulamasıdır.

### Silinen Öğe Kurtarma

Bir anahtar silindiğinde işaretlenir, ancak işgal ettiği alan ihtiyaç duyulana kadar kaldırılmaz. Bu nedenle, **Kayıt Düzenleyici** gibi araçlar kullanılarak bu silinen anahtarların kurtarılması mümkündür.

### Son Yazma Zamanı

Her Anahtar-Değer, son olarak değiştirildiği zamanı gösteren bir **zaman damgası** içerir.

### SAM

Dosya/hive **SAM**, sistemin **kullanıcıları, grupları ve kullanıcı şifreleri** hash'lerini içerir.

`SAM\Domains\Account\Users` içinde kullanıcı adını, RID'yi, son girişi, son başarısız girişi, giriş sayacını, şifre politikasını ve hesabın ne zaman oluşturulduğunu elde edebilirsiniz. **Hash'leri** almak için ayrıca **SYSTEM** dosya/hive'ına ihtiyacınız vardır.

### Windows Kayıt Defterindeki İlginç Girişler

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Yürütülen Programlar

### Temel Windows İşlemleri

Bu [yazıda](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) şüpheli davranışları tespit etmek için yaygın Windows işlemleri hakkında bilgi edinebilirsiniz.

### Windows Son Uygulamaları

Kayıt defterinde `NTUSER.DAT` içinde `Software\Microsoft\Current Version\Search\RecentApps` yolunda **yürütülen uygulama**, **en son çalıştırılma zamanı** ve **kaç kez** başlatıldığı hakkında bilgiler içeren alt anahtarlar bulabilirsiniz.

### BAM (Arka Plan Etkinlik Düzenleyicisi)

`SYSTEM` dosyasını bir kayıt düzenleyici ile açabilir ve `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` yolunda her kullanıcı tarafından **yürütülen uygulamaların bilgilerini** (yol içindeki `{SID}` dikkate alın) ve **ne zaman** çalıştırıldıklarını (zaman, kayıt defterinin Veri değerinin içindedir) bulabilirsiniz.

### Windows Prefetch

Ön bellekleme, bir bilgisayarın, bir kullanıcının **yakın gelecekte erişebileceği gerekli kaynakları sessizce almasına** olanak tanıyan bir tekniktir, böylece kaynaklar daha hızlı erişilebilir.

Windows ön belleği, **daha hızlı yüklemek için yürütülen programların önbelleklerini oluşturmayı** içerir. Bu önbellekler, `.pf` uzantılı dosyalar olarak `C:\Windows\Prefetch` yolunda oluşturulur. XP/VISTA/WIN7'de 128 dosya sınırı ve Win8/Win10'da 1024 dosya sınırı vardır.

Dosya adı `{program_adı}-{hash}.pf` şeklinde oluşturulur (hash, yürütülebilir dosyanın yol ve argümanlarına dayanır). W10'da bu dosyalar sıkıştırılmıştır. Dosyanın tek başına varlığı, programın bir noktada **çalıştırıldığını** gösterir. 

Dosya `C:\Windows\Prefetch\Layout.ini`, **önbelleğe alınan dosyaların klasör adlarını** içerir. Bu dosya, **çalıştırılan dosyaların sayısı**, **çalıştırılma tarihleri** ve program tarafından **açılan dosyalar** hakkında bilgiler içerir.

Bu dosyaları incelemek için [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) aracını kullanabilirsiniz.
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Süper Ön Yükleme

**Süper Ön Yükleme** ön yükleme ile aynı amaca sahiptir, **programları daha hızlı yükleyerek** bir sonraki yüklemenin ne olacağını tahmin eder. Ancak, ön yükleme hizmetini yerine koymaz.\
Bu hizmet, `C:\Windows\Prefetch\Ag*.db` içinde veritabanı dosyaları oluşturacaktır.

Bu veritabanlarında **programın adı**, **çalıştırma sayısı**, **açılan dosyalar**, **erişilen hacim**, **tam yol**, **zaman aralıkları** ve **zaman damgaları** bulabilirsiniz.

Bu bilgilere [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) aracını kullanarak erişebilirsiniz.

### SRUM

**Sistem Kaynak Kullanımı İzleyicisi** (SRUM) bir işlem tarafından **tüketilen kaynakları izler**. W8'de ortaya çıktı ve verileri `C:\Windows\System32\sru\SRUDB.dat` konumunda bulunan bir ESE veritabanında saklar.

Aşağıdaki bilgileri verir:

* Uygulama Kimliği ve Yolu
* İşlemi yürüten kullanıcı
* Gönderilen Baytlar
* Alınan Baytlar
* Ağ Arayüzü
* Bağlantı süresi
* İşlem süresi

Bu bilgi her 60 dakikada bir güncellenir.

Bu dosyadan bilgiyi [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) aracını kullanarak elde edebilirsiniz.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, ayrıca **ShimCache** olarak da bilinen, uygulama uyumluluk sorunlarıyla başa çıkmak için **Microsoft** tarafından geliştirilen **Uygulama Uyumluluk Veritabanı**nın bir parçasını oluşturur. Bu sistem bileşeni, şunları içeren çeşitli dosya meta verilerini kaydeder:

- Dosyanın tam yolu
- Dosyanın boyutu
- **$Standard\_Information** (SI) altında Son Değiştirilme zamanı
- ShimCache'in Son Güncelleme zamanı
- İşlem Yürütme Bayrağı

Bu tür veriler, işletim sisteminin sürümüne bağlı olarak belirli konumlarda kaydedilir:

- XP için, veriler `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` altında depolanır ve 96 giriş kapasitesine sahiptir.
- Server 2003 için ve Windows sürümleri 2008, 2012, 2016, 7, 8 ve 10 için depolama yolu `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` olup sırasıyla 512 ve 1024 girişi barındırır.

Depolanan bilgileri ayrıştırmak için [**AppCompatCacheParser** aracı](https://github.com/EricZimmerman/AppCompatCacheParser) kullanılması önerilir.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** dosyası, bir sistemin üzerinde çalıştırılan uygulamalar hakkında ayrıntıları kaydeden bir kayıt hive'ıdır. Genellikle `C:\Windows\AppCompat\Programas\Amcache.hve` konumunda bulunur.

Bu dosya, son zamanlarda çalıştırılan işlemlerin kayıtlarını saklamak için dikkat çekicidir, bu da uygulamaların bir sistemdeki etkinliğini izlemek için çok değerli bir bilgidir.

**Amcache.hve** dosyasından verileri çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) aracı kullanılabilir. Aşağıdaki komut, **Amcache.hve** dosyasının içeriğini ayrıştırmak ve sonuçları CSV formatında çıkarmak için AmcacheParser'ın nasıl kullanılacağına dair bir örnektir:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Oluşturulan CSV dosyaları arasında, `Amcache_Unassociated file entries` özellikle dikkat çekicidir çünkü ilişkilendirilmemiş dosya girişleri hakkında sağladığı zengin bilgilerle bilinir.

En ilginç CSV dosyası `Amcache_Unassociated file entries` olarak oluşturulmuştur.

### RecentFileCache

Bu sanat eseri yalnızca W7'de `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` içinde bulunabilir ve bazı ikili dosyaların son yürütülmesi hakkında bilgiler içerir.

Dosyayı ayrıştırmak için [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) aracını kullanabilirsiniz.

### Zamanlanmış görevler

Onları `C:\Windows\Tasks` veya `C:\Windows\System32\Tasks` içinden çıkarabilir ve XML olarak okuyabilirsiniz.

### Hizmetler

Hizmetleri `SYSTEM\ControlSet001\Services` altında kayıt defterinde bulabilirsiniz. Ne zaman ve neyin yürütüleceğini görebilirsiniz.

### **Windows Mağazası**

Yüklü uygulamalar `\ProgramData\Microsoft\Windows\AppRepository\` içinde bulunabilir.\
Bu depoda sisteme yüklenen **her uygulama** hakkında **`StateRepository-Machine.srd`** veritabanı içinde bir **günlük** bulunur.

Bu veritabanının Application tablosu içinde "Uygulama Kimliği", "Paket Numarası" ve "Görüntü Adı" sütunlarını bulmak mümkündür. Bu sütunlar önceden yüklenmiş ve yüklenmiş uygulamalar hakkında bilgi içerir ve yüklenen uygulamaların kimlikleri sıralı olmalıdır.

Ayrıca, yüklü uygulamaları kayıt defteri yolunda **bulabilirsiniz**: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Ve **kaldırılan** **uygulamaları** şurada bulabilirsiniz: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Olayları

Windows olayları içinde görünen bilgiler:

* Ne olduğu
* Zaman damgası (UTC + 0)
* İlgili Kullanıcılar
* İlgili Ana Bilgisayarlar (ana bilgisayar adı, IP)
* Erişilen Varlıklar (dosyalar, klasörler, yazıcılar, hizmetler)

Olay günlükleri, Windows Vista'dan önce `C:\Windows\System32\config` içinde ve Windows Vista'dan sonra `C:\Windows\System32\winevt\Logs` içinde bulunur. Windows Vista'dan önce, olay günlükleri ikili formatta ve sonrasında **XML formatında** ve **.evtx** uzantısını kullanır.

Olay dosyalarının konumu, olay günlüğünün **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** içinde bulunabilir.

Bu olaylar Windows Olay Görüntüleyicisi (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) gibi diğer araçlarla veya [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** gibi diğer araçlarla görselleştirilebilir.**

## Windows Güvenlik Olay Günlüğünü Anlama

Erişim olayları, `C:\Windows\System32\winevt\Security.evtx` konumundaki güvenlik yapılandırma dosyasında kaydedilir. Bu dosyanın boyutu ayarlanabilir ve kapasitesine ulaşıldığında, eski olaylar üzerine yazılır. Kaydedilen olaylar arasında kullanıcı girişleri ve çıkışları, kullanıcı eylemleri ve güvenlik ayarlarına yapılan değişiklikler, ayrıca dosya, klasör ve paylaşılan varlıklara erişim bulunur.

### Kullanıcı Kimlik Doğrulama için Ana Olay Kimlikleri:

- **Olay Kimliği 4624**: Bir kullanıcının başarılı bir şekilde kimlik doğruladığını gösterir.
- **Olay Kimliği 4625**: Kimlik doğrulama başarısızlığını belirtir.
- **Olay Kimlikleri 4634/4647**: Kullanıcı çıkış olaylarını temsil eder.
- **Olay Kimliği 4672**: Yönetici ayrıcalıklarıyla girişi belirtir.

#### Olay Kimliği 4634/4647 İçindeki Alt Türler:

- **Etkileşimli (2)**: Doğrudan kullanıcı girişi.
- **Ağ (3)**: Paylaşılan klasörlere erişim.
- **Toplu (4)**: Toplu işlemlerin yürütülmesi.
- **Hizmet (5)**: Hizmet başlatmaları.
- **Vekil (6)**: Vekil kimlik doğrulaması.
- **Kilidi Aç (7)**: Şifre ile kilidin açılması.
- **Ağ Düz Metin (8)**: Genellikle IIS'den gelen düz metin şifre iletimi.
- **Yeni Kimlik Bilgileri (9)**: Erişim için farklı kimlik bilgilerinin kullanımı.
- **Uzak Etkileşimli (10)**: Uzak masaüstü veya terminal hizmetleri girişi.
- **Önbellek Etkileşimli (11)**: Etki alanı denetleyicisi ile iletişim olmadan önbellek kimlik bilgileriyle giriş.
- **Önbellek Uzak Etkileşimli (12)**: Önbellek kimlik bilgileriyle uzaktan giriş.
- **Önbellek Kilidi Aç (13)**: Önbellek kimlik bilgileriyle kilidin açılması.

#### Olay Kimliği 4625 için Durum ve Alt Durum Kodları:

- **0xC0000064**: Kullanıcı adı mevcut değil - Kullanıcı adı sıralama saldırısını gösterebilir.
- **0xC000006A**: Doğru kullanıcı adı ancak yanlış şifre - Olası şifre tahmini veya kaba kuvvet saldırısını gösterebilir.
- **0xC0000234**: Kullanıcı hesabı kilitli - Birden fazla başarısız giriş denemesi sonucunda kilitlenmiş hesapları takip edebilir.
- **0xC0000072**: Hesap devre dışı bırakıldı - Devre dışı bırakılmış hesaplara yetkisiz erişim denemelerini gösterebilir.
- **0xC000006F**: İzin verilen saatler dışında oturum açma - Belirlenen oturum açma saatleri dışında erişim denemelerini gösterebilir, yetkisiz erişimin olası bir işareti olabilir.
- **0xC0000070**: İş istasyonu kısıtlamalarının ihlali - Yetkisiz bir konumdan oturum açma girişimi olabilir.
- **0xC0000193**: Hesap süresinin dolması - Süresi dolmuş kullanıcı hesaplarıyla erişim denemelerini gösterebilir.
- **0xC0000071**: Süresi dolmuş şifre - Güncel olmayan şifrelerle oturum açma denemelerini gösterebilir.
- **0xC0000133**: Zaman senkronizasyon sorunları - İstemci ve sunucu arasındaki büyük zaman farkları, pass-the-ticket gibi daha sofistike saldırıların işareti olabilir.
- **0xC0000224**: Zorunlu şifre değişikliği gereklidir - Sık zorunlu değişiklikler, hesap güvenliğini bozmaya yönelik bir girişimi gösterebilir.
- **0xC0000225**: Bir güvenlik sorunu yerine bir sistem hatasını gösterir.
- **0xC000015b**: Reddedilen oturum açma türü - Yetkisiz oturum açma türü ile erişim denemesini gösterebilir, örneğin bir kullanıcının bir hizmet oturumu açmaya çalışması.

#### Olay Kimliği 4616:
- **Zaman Değişikliği**: Sistem zamanının değiştirilmesi, olay zaman çizgisini karıştırabilir.

#### Olay Kimliği 6005 ve 6006:
- **Sistem Başlatma ve Kapatma**: Olay Kimliği 6005 sistem başlatıldığını, Olay Kimliği 6006 ise kapatıldığını belirtir.

#### Olay Kimliği 1102:
- **Günlük Silme**: Güvenlik günlüklerinin temizlenmesi, genellikle yasadışı faaliyetleri örtbas etmek için bir işaret olabilir.

#### USB Cihaz Takibi için Olay Kimlikleri:
- **20001 / 20003 / 10000**: USB cihazının ilk bağlantısı.
- **10100**: USB sürücü güncellemesi.
- **Olay Kimliği 112**: USB cihazı takma zamanı.

Bu giriş türlerini ve kimlik bilgilerini nerede bulabileceğiniz ve kimlik bilgilerini nerede bulabileceğiniz gibi pratik örnekler için [Altered Security'nin detaylı kılavuzuna](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) başvurun.

Olay ayrıntıları, durum ve alt durum kodları da dahil olmak üzere olay nedenleri hakkında daha fazla bilgi sağlar, özellikle Olay Kimliği 4625'te dikkate değerdir.

### Windows Olaylarını Kurtarma

Silinmiş Windows Olaylarını kurtarma şansını artırmak için şüpheli bilgisayarı doğrudan fişten çekerek kapatmanız önerilir. **Bulk_extractor**, `.evtx` uzantısını belirten bir kurtarma aracı, bu tür olayları kurtarmak için önerilir.

### Windows Olayları Aracılığıyla Ortak Saldırıları Tanımlama

Ortak siber saldırıları tanımlamak için Windows Olay Kimliklerini kullanma kılavuzu için [Red Team Recipe](https://redteamrecipe.com/event-codes/) adresini ziyaret edin.

#### Kaba Kuvvet Saldırıları

Birden fazla Olay Kimliği 4625 kaydıyla tanımlanabilir, saldırı başarılı olursa bir Olay Kimliği 4624 ile devam eder.

#### Zaman Değişikliği

Olay Kimliği 4616 tarafından kaydedilen sistem zamanı değişiklikleri, adli analizi karmaşık hale getirebilir.

#### USB Cihaz Takibi

USB cihaz takibi için kullanışlı Sistem Olay Kimlikleri, başlangıçta kullanım için 20001/20003/10000, sürücü güncellemeleri için 10100 ve takma zamanları için DeviceSetupManager'dan Olay Kimliği 112'yi içerir.
#### Sistem Güç Olayları

EventID 6005, sistem başlangıcını gösterirken, EventID 6006 kapanışı işaretler.

#### Günlük Silme

Güvenlik EventID 1102, günlüklerin silinmesini işaret eder, bu da adli analiz için kritik bir olaydır.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Sıfırdan kahraman olacak şekilde AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** istiyorsanız [**ABONELİK PLANLARI**]'na(https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
