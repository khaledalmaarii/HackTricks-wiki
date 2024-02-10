# Windows Sanat Eserleri

## Windows Sanat Eserleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Genel Windows Sanat Eserleri

### Windows 10 Bildirimleri

`\Users\<kullanıcıadı>\AppData\Local\Microsoft\Windows\Notifications` yolunda, Windows yıldönümünden önce `appdb.dat` veya Windows Yıldönümünden sonra `wpndatabase.db` adlı veritabanını bulabilirsiniz.

Bu SQLite veritabanı içinde, ilginç veriler içerebilecek tüm bildirimleri (XML formatında) içeren `Notification` tablosunu bulabilirsiniz.

### Zaman Çizelgesi

Zaman Çizelgesi, ziyaret edilen web sayfalarının, düzenlenen belgelerin ve yürütülen uygulamaların **zaman sırasına göre tarihçesini** sağlayan bir Windows özelliğidir.

Veritabanı, `\Users\<kullanıcıadı>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` yolunda bulunur. Bu veritabanı, bir SQLite aracı veya [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) aracı ile açılabilir ve [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) aracı ile açılabilen 2 dosya oluşturur.

### ADS (Alternatif Veri Akışları)

İndirilen dosyalar, intranet, internet vb. üzerinden **nasıl** indirildiğini gösteren **ADS Zone.Identifier**'ı içerebilir. Bazı yazılımlar (tarayıcılar gibi) genellikle dosyanın indirildiği **URL** gibi **daha fazla bilgi** ekler.

## **Dosya Yedekleri**

### Geri Dönüşüm Kutusu

Vista/Win7/Win8/Win10'da **Geri Dönüşüm Kutusu**, sürücünün kökünde (`C:\$Recycle.bin`) **`$Recycle.bin`** klasöründe bulunabilir.\
Bu klasörde bir dosya silindiğinde 2 belirli dosya oluşturulur:

* `$I{id}`: Dosya bilgisi (silindiği tarih}
* `$R{id}`: Dosyanın içeriği

![](<../../../.gitbook/assets/image (486).png>)

Bu dosyaları kullanarak, silinen dosyaların orijinal adresini ve silindiği tarihi almak için [**Rifiuti**](https://github.com/abelcheung/rifiuti2) aracını kullanabilirsiniz (Vista - Win10 için `rifiuti-vista.exe` kullanın).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Gölgeli Kopyalar

Shadow Copy, kullanımda olsalar bile, bilgisayar dosyalarının veya birimlerinin **yedek kopyalarını** veya anlık görüntülerini oluşturabilen Microsoft Windows'a dahil edilen bir teknolojidir.

Bu yedeklemeler genellikle dosya sisteminin kökündeki `\System Volume Information` içinde bulunur ve adları aşağıdaki görüntüde gösterilen **UID'lerden** oluşur:

![](<../../../.gitbook/assets/image (520).png>)

Forensik imajı **ArsenalImageMounter** ile bağladıktan sonra, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) aracı bir gölgeli kopyayı incelemek ve hatta gölgeli kopya yedeklemelerinden **dosyaları çıkarmak** için kullanılabilir.

![](<../../../.gitbook/assets/image (521).png>)

Kayıt defteri girdisi `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, **yedeklenmeyecek** dosyaları ve anahtarları içerir:

![](<../../../.gitbook/assets/image (522).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` kayıt defteri de `Volume Shadow Copies` hakkında yapılandırma bilgileri içerir.

### Office Otomatik Kaydedilen Dosyalar

Office otomatik kaydedilen dosyaları şurada bulabilirsiniz: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Kabuk Öğeleri

Bir kabuk öğesi, başka bir dosyaya nasıl erişileceği hakkında bilgi içeren bir öğedir.

### Son Belgeler (LNK)

Windows, kullanıcı bir dosyayı **açtığında, kullandığında veya oluşturduğunda** otomatik olarak bu **kısayolları oluşturur**:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Bir klasör oluşturulduğunda, klasöre, üst klasöre ve büyük üst klasöre birer bağlantı da oluşturulur.

Bu otomatik olarak oluşturulan bağlantı dosyaları, **dosyanın kaynağı** hakkında bilgi içerir, örneğin bir **dosya** mı yoksa bir **klasör** mü olduğu, dosyanın **MAC zamanları**, dosyanın depolandığı **birim bilgisi** ve **hedef dosyanın klasörü**. Bu bilgiler, dosyaların silinmesi durumunda bu dosyaları kurtarmak için kullanışlı olabilir.

Ayrıca, bağlantı dosyasının **oluşturulma tarihi**, orijinal dosyanın **ilk kullanıldığı zaman**dır ve bağlantı dosyasının **değiştirilme tarihi**, kaynak dosyanın **son kullanıldığı zaman**dır.

Bu dosyaları incelemek için [**LinkParser**](http://4discovery.com/our-tools/) aracını kullanabilirsiniz.

Bu araçta **2 set** zaman damgası bulacaksınız:

* **İlk Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **İkinci Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

İlk zaman damgası seti, **dosyanın kendi zaman damgalarına** referans verir. İkinci set, **bağlantılı dosyanın zaman damgalarına** referans verir.

Aynı bilgilere Windows CLI aracı [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) çalıştırarak da ulaşabilirsiniz.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Bu durumda, bilgiler bir CSV dosyasına kaydedilecektir.

### Jumplists

Bunlar, her uygulama için gösterilen son dosyalardır. Her uygulamada erişebileceğiniz bir uygulamanın **son kullanılan dosyalarının listesi**dir. Bunlar otomatik olarak oluşturulabilir veya özelleştirilebilir.

Otomatik olarak oluşturulan **jumplists**, `C:\Users\{kullanıcıadı}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` dizininde saklanır. Jumplists, başlangıç ​​ID'si uygulamanın ID'si olan `{id}.autmaticDestinations-ms` formatında adlandırılır.

Özel jumplists, `C:\Users\{kullanıcıadı}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` dizininde saklanır ve genellikle uygulama tarafından dosya ile ilgili önemli bir şey olduğunda oluşturulur (favori olarak işaretlenmiş olabilir).

Herhangi bir jumplist'in **oluşturulma zamanı**, dosyanın **ilk erişildiği zamanı** ve **değiştirilme zamanı**ni gösterir.

Jumplists'i [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) kullanarak inceleyebilirsiniz.

![](<../../../.gitbook/assets/image (474).png>)

(_JumplistExplorer tarafından sağlanan zaman damgalarının jumplist dosyasıyla ilgili olduğunu unutmayın_)

### Shellbags

[**Shellbags'ın ne olduğunu öğrenmek için bu bağlantıyı takip edin.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB'lerin Kullanımı

Bir USB cihazının kullanıldığını belirlemek mümkündür çünkü şunların oluşturulmasıyla ilgilidir:

* Windows Son Klasörü
* Microsoft Office Son Klasörü
* Jumplists

Dikkat edilmesi gereken nokta, bazı LNK dosyalarının orijinal yol yerine WPDNSE klasörüne işaret etmesidir:

![](<../../../.gitbook/assets/image (476).png>)

WPDNSE klasöründeki dosyalar, orijinal olanların bir kopyasıdır, bu nedenle bilgisayar yeniden başlatıldığında hayatta kalamazlar ve GUID bir shellbag'den alınır.

### Kayıt Defteri Bilgileri

USB bağlantısıyla ilgili ilginç bilgiler içeren kayıt defteri anahtarlarını öğrenmek için [bu sayfayı kontrol edin](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB bağlantısının ne zaman gerçekleştiği hakkında zaman damgalarını elde etmek için `C:\Windows\inf\setupapi.dev.log` dosyasını kontrol edin (`Section start` için arama yapın).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com), bir görüntüye bağlanan USB cihazları hakkında bilgi edinmek için kullanılabilir.

![](<../../../.gitbook/assets/image (483).png>)

### Tak ve Çalıştır Temizliği

'Plug and Play Temizliği' olarak bilinen zamanlanmış görev, eski sürücü sürümlerinin kaldırılması için tasarlanmıştır. Belirtilen amacının aksine, çevrimiçi kaynaklar, son 30 günde kullanılmayan sürücülerin de hedef alındığını öne sürmektedir. Sonuç olarak, geçen 30 günde bağlanmayan taşınabilir cihazların sürücüleri silinebilir.

Görev aşağıdaki konumda bulunur:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Görevin içeriğini gösteren bir ekran görüntüsü sağlanmıştır:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Görevin Ana Bileşenleri ve Ayarları:**
- **pnpclean.dll**: Bu DLL, gerçek temizleme işlemini gerçekleştirir.
- **UseUnifiedSchedulingEngine**: Genel görev zamanlama motorunun kullanımını gösteren `TRUE` olarak ayarlanmıştır.
- **MaintenanceSettings**:
- **Dönem ('P1M')**: Görev Zamanlayıcısının düzenli Otomatik bakım sırasında aylık olarak temizleme görevini başlatmasını yönlendirir.
- **Son Tarih ('P2M')**: Görev Zamanlayıcısına, görev iki ardışık ay boyunca başarısız olursa, acil Otomatik bakım sırasında görevi yürütmesi talimatı verilir.

Bu yapılandırma, sürücülerin düzenli bakım ve temizliğini sağlar ve ardışık başarısızlıklar durumunda görevin yeniden denemesi için hükümler içerir.

**Daha fazla bilgi için kontrol edin:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-postalar

E-postaların **2 ilginç bölümü vardır: Başlıklar ve e-postanın içeriği**. Başlıklarda şu bilgileri bulabilirsiniz:

* E-postayı **kimin** gönderdiği (e-posta adresi, IP, e-postayı yönlendiren posta sunucuları)
* E-postanın **ne zaman** gönderildiği

Ayrıca, `References` ve `In-Reply-To` başlıklarında mesajların kimliklerini bulabilirsiniz:

![](<../../../.gitbook/assets/image (484).png>)

### Windows Mail Uygulaması

Bu uygulama e-postaları HTML veya metin olarak kaydeder. E-postaları `\Users\<kullanıcıadı>\AppData\Local\Comms\Unistore\data\3\` dizini içindeki alt klasörlerde bulabilirsiniz. E-postalar `.dat` uzantısıyla kaydedilir.

E-postaların **meta verileri** ve **kişiler** **EDB veritabanı** içinde bulunabilir: `\Users\<kullanıcıadı>\AppData\Local\Comms\UnistoreDB\store.vol`

Dosyanın uzantısını `.vol` yerine `.edb` olarak değiştirerek [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) aracını kullanabilirsiniz. `Message` tablosu içinde e-postaları görebilirsiniz.

### Microsoft Outlook

Exchange sunucuları veya Outlook istemcileri kullanıldığında bazı MAPI başlıkları olacaktır:

* `Mapi-Client-Submit-Time`: E-postanın gönderildiği sistem saati
* `Mapi-Conversation-Index`: Konuyla ilgili çocuk mesajların sayısı ve her mesajın zaman damgası
* `Mapi-Entry-ID`: Mesaj kimliği.
* `Mappi-Message-Flags` ve `Pr_last_Verb-Executed`: MAPI istemcisi hakkında bilgi (mesaj okundu mu? okunmadı mı? yanıtlandı mı? yönlendirildi mi? ofiste değil mi?)

Microsoft Outlook istemcisinde, gönderilen/alınan tüm mesajlar, kişiler verileri ve takvim verileri bir PST dosyasında saklanır:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kayıt defteri yolu kullanılan dosyayı gösterir.

PST dosyasını [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) aracını kullanarak açabilirsiniz.

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST Dosyaları

Bir **OST dosyası**, Microsoft Outlook'un **IMAP** veya **Exchange** sunucusuyla yapılandırıldığında oluşturulur ve bir PST dosyasına benzer bilgileri depolar. Bu dosya, sunucuyla senkronize edilir ve **son 12 ay** boyunca verileri saklar, **maksimum 50GB** boyutunda olabilir ve PST dosyasıyla aynı dizinde bulunur. Bir OST dosyasını görüntülemek için [**Kernel OST görüntüleyici**](https://www.nucleustechnologies.com/ost-viewer.html) kullanılabilir.

### Ekleri Kurtarma

Kaybolmuş ekler aşağıdaki yerlerden kurtarılabilir:

- **IE10 için**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 ve üzeri için**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Dosyaları

**Thunderbird**, verileri depolamak için **MBOX dosyalarını** kullanır ve bu dosyalar `\Users\%KULLANICIADI%\AppData\Roaming\Thunderbird\Profiles` dizininde bulunur.

### Görüntü Küçük Resimleri

- **Windows XP ve 8-8.1**: Küçük resimlerle bir klasöre erişmek, silinmesinden sonra bile resim önizlemelerini depolayan bir `thumbs.db` dosyası oluşturur.
- **Windows 7/10**: `thumbs.db`, UNC yoluyla bir ağ üzerinden erişildiğinde oluşturulur.
- **Windows Vista ve daha yeni sürümler**: Küçük resim önizlemeleri `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` dizininde **thumbcache\_xxx.db** adlı dosyalarda merkezi olarak depolanır. Bu dosyaları görüntülemek için [**Thumbsviewer**](https://thumbsviewer.github.io) ve [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) araçları kullanılabilir.

### Windows Kayıt Defteri Bilgileri

Geniş sistem ve kullanıcı etkinlik verilerini depolayan Windows Kayıt Defteri, aşağıdaki dosyalarda bulunur:

- Çeşitli `HKEY_LOCAL_MACHINE` alt anahtarları için `%windir%\System32\Config`.
- `HKEY_CURRENT_USER` için `%UserProfile%{Kullanıcı}\NTUSER.DAT`.
- Windows Vista ve sonraki sürümler, `HKEY_LOCAL_MACHINE` kayıt defteri dosyalarını `%Windir%\System32\Config\RegBack\` dizininde yedekler.
- Ayrıca, program yürütme bilgileri Windows Vista ve Windows 2008 Server'dan itibaren `%UserProfile%\{Kullanıcı}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` dosyasında depolanır.

### Araçlar

Kayıt defteri dosyalarını analiz etmek için bazı araçlar kullanışlıdır:

* **Kayıt Defteri Düzenleyici**: Windows'a yüklenmiştir. Geçerli oturumun Windows kayıt defteri üzerinde gezinmek için bir GUI sağlar.
* [**Kayıt Defteri Gezgini**](https://ericzimmerman.github.io/#!index.md): Kayıt defteri dosyasını yüklemenize ve bunları bir GUI ile gezinmenize olanak sağlar. Ayrıca, ilginç bilgiler içeren anahtarları vurgulayan Yer İmleri içerir.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Yine, yüklenen kayıt defteri üzerinde gezinmeye izin veren bir GUIye sahiptir ve yüklenen kayıt defteri içinde ilginç bilgileri vurgulayan eklentiler içerir.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Kayıt defterinden önemli bilgileri çıkarmak için yetenekli başka bir GUI uygulamasıdır.

### Silinen Öğeyi Kurtarma

Bir anahtar silindiğinde bunun belirtilmesine rağmen, yerini alacak bir alan ihtiyaç duyulana kadar kaldırılmaz. Bu nedenle, **Kayıt Defteri Gezgini** gibi araçlar kullanarak bu silinen anahtarları kurtarmak mümkündür.

### Son Yazma Zamanı

Her Anahtar-Değer, son değiştirilme zamanını gösteren bir **zaman damgası** içerir.

### SAM

SAM dosyası/hivesı, sistemin **kullanıcılarını, gruplarını ve kullanıcı parolalarının** karma değerlerini içerir.

`SAM\Domains\Account\Users` içinde kullanıcı adını, RID'yi, son oturumu, son başarısız oturum açma, oturum açma sayacını, parola politikasını ve hesabın oluşturulma zamanını elde edebilirsiniz. **Karma değerleri** elde etmek için de dosya/hive **SYSTEM**'e ihtiyacınız vardır.

### Windows Kayıt Defterindeki İlginç Girişler

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Çalıştırılan Programlar

### Temel Windows İşlemleri

Şüpheli davranışları tespit etmek için [bu yazıda](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) yaygın Windows işlemleri hakkında bilgi edinebilirsiniz.

### Windows Son Uygulamalar

`NTUSER.DAT` kayıt defteri içinde `Software\Microsoft\Current Version\Search\RecentApps` yolunda, **çalıştırılan uygulama** hakkında bilgi, **son çalıştırılma zamanı** ve **kaç kez** başlatıldığına dair alt anahtarlar bulunabilir.

### BAM (Arka Plan Etkinlik Düzenleyici)

Bir kayıt defteri düzenleyici ile `SYSTEM` dosyasını açabilir ve `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` yolunda her kullanıcının **çalıştırdığı uygulamalarla ilgili bilgileri** bulabilirsiniz (yolun içindeki `{SID}` dikkate alınmalıdır) ve **ne zaman** çalıştırıldıklarını (zaman, kayıt defterinin Veri değerinin içindedir).

### Windows Prefetch

Prefetching, bir kullanıcının **yakın gelecekte erişebileceği içeriği görüntülemek için gerekli kaynakları sessizce almasına** olanak tanıyan bir tekniktir, böylece kaynaklara daha hızlı erişilebilir.

Windows prefetch, **çalıştırılan programların önbelleğini oluşturarak** onları daha hızlı yüklemek için önbellekler oluşturur. Bu önbellekler, `.pf` uzantılı dosyalar olarak `C:\Windows\Prefetch` yolunda oluşturulur. XP/VISTA/WIN7'de 128 dosya sınırı, Win8/Win10'da 1024 dosya sınırı vardır.

Dosya adı, `{program_adı}-{hash}.pf` şeklinde oluşturulur (hash, yürütülebilir dosyanın yol ve argümanlarına dayanır). W10'da bu dosyalar sıkıştırılmıştır. Dosyanın sadece varlığı, programın bir noktada **çalıştırıldığını** gösterir.

`C:\Windows\Prefetch\Layout.ini` dosyası, **önbelleğe alınan dosyaların klasörlerinin adlarını** içerir. Bu dosya, **çalıştırma sayısı**, **çalıştırma tarihleri** ve program tarafından **açılan dosyalar** hakkında bilgiler içerir.

Bu dosyaları incelemek için [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) aracını kullanabilirsiniz.
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch**, prefetch ile aynı amaca hizmet eder, **programları daha hızlı yüklemek** için gelecekte yüklenecek olanları tahmin eder. Ancak, prefetch hizmetinin yerini almaz.\
Bu hizmet, `C:\Windows\Prefetch\Ag*.db` dizininde veritabanı dosyaları oluşturur.

Bu veritabanlarında **programın adı**, **çalıştırılma sayısı**, **açılan dosyalar**, **erişilen birimler**, **tam yol**, **zaman aralıkları** ve **zaman damgaları** gibi bilgiler bulunur.

Bu bilgilere [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) aracını kullanarak erişebilirsiniz.

### SRUM

**System Resource Usage Monitor** (SRUM), bir işlem tarafından tüketilen kaynakları izler. W8'de ortaya çıkmış olup, verileri `C:\Windows\System32\sru\SRUDB.dat` konumunda bir ESE veritabanında depolar.

Aşağıdaki bilgileri sağlar:

* Uygulama Kimliği ve Yolu
* İşlemi yürüten kullanıcı
* Gönderilen baytlar
* Alınan baytlar
* Ağ Arayüzü
* Bağlantı süresi
* İşlem süresi

Bu bilgiler her 60 dakikada bir güncellenir.

Bu dosyadan verileri [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) aracını kullanarak elde edebilirsiniz.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, ayrıca **ShimCache** olarak da bilinen, uygulama uyumluluk sorunlarını çözmek için **Microsoft** tarafından geliştirilen **Uygulama Uyumluluk Veritabanı**nın bir parçasıdır. Bu sistem bileşeni, aşağıdaki dosya meta verilerini kaydeder:

- Dosyanın tam yolu
- Dosyanın boyutu
- **$Standard\_Information** (SI) altında Son Değiştirilme zamanı
- ShimCache'in Son Güncelleme zamanı
- İşlem Yürütme Bayrağı

Bu tür veriler, işletim sistemi sürümüne bağlı olarak kayıt defterinde belirli konumlarda depolanır:

- XP için, veriler `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` altında depolanır ve 96 giriş kapasitesine sahiptir.
- Server 2003 için ve ayrıca Windows sürümleri 2008, 2012, 2016, 7, 8 ve 10 için depolama yolu `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` olup, sırasıyla 512 ve 1024 girişe kadar yer sağlar.

Depolanan bilgileri ayrıştırmak için [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) aracının kullanılması önerilir.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** dosyası, bir sistemin üzerinde çalıştırılan uygulamalar hakkında ayrıntıları kaydeden bir kayıt defteri hive'ıdır. Genellikle `C:\Windows\AppCompat\Programas\Amcache.hve` konumunda bulunur.

Bu dosya, son zamanlarda çalıştırılan işlemlerin kayıtlarını saklamak için önemlidir ve yürütülebilir dosyaların yollarını ve SHA1 karma değerlerini içerir. Bu bilgi, bir sistemdeki uygulamaların faaliyetlerini izlemek için çok değerlidir.

**Amcache.hve** dosyasından verileri çıkarmak ve analiz etmek için [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) aracı kullanılabilir. Aşağıdaki komut, AmcacheParser'ın **Amcache.hve** dosyasının içeriğini ayrıştırmasını ve sonuçları CSV formatında çıktılamasını sağlayan bir örnektir:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Oluşturulan CSV dosyaları arasında, `Amcache_Bağlantısız dosya girişleri` özellikle dikkate değerdir çünkü bağlantısız dosya girişleri hakkında zengin bilgi sağlar.

En ilginç CSV dosyası ise `Amcache_Bağlantısız dosya girişleri`dir.

### Zamanlanmış görevler

Bunları `C:\Windows\Tasks` veya `C:\Windows\System32\Tasks` dizininden çıkarabilir ve XML olarak okuyabilirsiniz.

### Hizmetler

Hizmetleri `SYSTEM\ControlSet001\Services` kayıt defterinde bulabilirsiniz. Ne zaman ve neyin yürütüleceğini görebilirsiniz.

### **Windows Mağazası**

Yüklenen uygulamalar `\ProgramData\Microsoft\Windows\AppRepository\` dizininde bulunabilir. Bu depoda, sistemdeki her uygulamanın veritabanı içindeki **`StateRepository-Machine.srd`** adlı bir **günlüğü** vardır.

Bu veritabanının Application tablosu içinde, "Uygulama Kimliği", "Paket Numarası" ve "Görüntülenen Ad" sütunlarını bulmak mümkündür. Bu sütunlar, önceden yüklenmiş ve yüklenmiş uygulamalar hakkında bilgi içerir ve yüklenmiş uygulamaların kimlikleri ardışık olmalıdır, bu nedenle bazı uygulamaların kaldırılıp kaldırılmadığı bulunabilir.

Ayrıca, yüklenen uygulamaları kayıt defteri yolunda da bulmak mümkündür: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Ve **kaldırılan** uygulamalar: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Olayları

Windows olaylarında görünen bilgiler:

* Ne olduğu
* Zaman damgası (UTC + 0)
* İlgili kullanıcılar
* İlgili ana bilgisayarlar (ana bilgisayar adı, IP)
* Erişilen varlıklar (dosyalar, klasörler, yazıcılar, hizmetler)

Günlükler, Windows Vista'dan önce `C:\Windows\System32\config` dizininde ve Windows Vista'dan sonra `C:\Windows\System32\winevt\Logs` dizininde bulunur. Windows Vista'dan önce, olay günlükleri ikili formatta ve Windows Vista'dan sonra **XML formatında** ve **.evtx** uzantısıyla kullanılır.

Olay dosyalarının konumu, SYSTEM kayıt defterinde **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** içinde bulunabilir.

Bu olaylar, Windows Olay Görüntüleyici (**`eventvwr.msc`**) veya [**Event Log Explorer**](https://eventlogxp.com) gibi diğer araçlarla veya [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.** gibi diğer araçlarla görüntülenebilir.

## Windows Güvenlik Olay Kaydını Anlama

Erişim olayları, `C:\Windows\System32\winevt\Security.evtx` konumundaki güvenlik yapılandırma dosyasında kaydedilir. Bu dosyanın boyutu ayarlanabilir ve kapasitesine ulaşıldığında, daha eski olaylar üzerine yazılır. Kaydedilen olaylar, kullanıcı girişleri ve çıkışları, kullanıcı eylemleri ve güvenlik ayarlarında yapılan değişiklikler ile dosya, klasör ve paylaşılan varlık erişimini içerir.

### Kullanıcı Kimlik Doğrulama için Ana Olay Kimlikleri:

- **Olay Kimliği 4624**: Kullanıcının başarılı bir şekilde kimlik doğruladığını gösterir.
- **Olay Kimliği 4625**: Kimlik doğrulama başarısızlığını bildirir.
- **Olay Kimlikleri 4634/4647**: Kullanıcı oturum kapatma olaylarını temsil eder.
- **Olay Kimliği 4672**: Yönetici ayrıcalıklarıyla oturum açmayı belirtir.

#### Olay Kimliği 4634/4647 İçindeki Alt Türler:

- **Etkileşimli (2)**: Doğrudan kullanıcı oturumu.
- **Ağ (3)**: Paylaşılan klasörlere erişim.
- **Toplu (4)**: Toplu işlemlerin yürütülmesi.
- **Hizmet (5)**: Hizmet başlatmaları.
- **Proxy (6)**: Proxy kimlik doğrulaması.
- **Kilidi Aç (7)**: Şifreyle ekran kilidi açma.
- **Ağ Temiz Metin (8)**: Genellikle IIS'den yapılan açık metin şifre iletimi.
- **Yeni Kimlik Bilgileri (9)**: Erişim için farklı kimlik bilgilerinin kullanımı.
- **Uzaktan Etkileşimli (10)**: Uzak masaüstü veya terminal hizmetleri oturumu.
- **Önbellek Etkileşimli (11)**: Etki alanı denetleyicisi ile iletişim olmadan önbelleğe alınmış kimlik bilgileriyle oturum açma.
- **Önbellek Uzaktan Etkileşimli (12)**: Önbelleğe alınmış kimlik bilgileriyle uzaktan oturum açma.
- **Önbellek Kilidi Aç (13)**: Önbelleğe alınmış kimlik bilgileriyle kilidi açma.

#### Olay Kimliği 4625 için Durum ve Alt Durum Kodları:

- **0xC0000064**: Kullanıcı adı mevcut değil - Kullanıcı adı sıralama saldırısını gösterebilir.
- **0xC000006A**: Doğru kullanıcı adı ancak yanlış şifre - Şifre tahmin etme veya brute-force saldırısı olabilir.
- **0xC0000234**: Kullanıcı hesabı kilitlendi - Birden fazla başarısız oturum açma denemesiyle sonuçlanan brute-force saldırısını takip edebilir.
- **0xC0000072**: Hesap devre dışı bırakıldı - Devre dışı bırakılmış hesaplara yetkisiz erişim girişimleri.
- **0xC000006F**: İzin verilen saatler dışında oturum açma - İzin verilen oturum açma saatleri dışında erişim girişimleri, yetkisiz erişimin olası bir işareti olabilir.
- **0xC0000070**: İş istasyonu kısıtlamalarının ihlali - Yetkisiz bir konumdan oturum açma girişimi olabilir.
- **0xC0000193**: Hesap süresi doldu - Süresi dolmuş kullanıcı hesaplarıyla erişim girişimleri.
- **0xC0000071**: Süresi dolmuş şifre - Güncelliğini yitirmiş şifrelerle oturum açma girişimleri.
- **0xC0000133**: Zaman senkronizasyon sorunları - İstemci ve sunucu arasında büyük zaman farklılıkları, pass-the-ticket gibi daha sofistike saldırıların göstergesi olabilir.
- **0xC0000224**: Zorunlu şifre değişikliği gerekiyor - Sık sık zorunlu değişiklikler, hesap güvenliğini destabilize etme girişimini gösterebilir.
- **0xC0000225**: Bir güvenlik sorunu yerine bir sistem hatasını gösterir.
- **0xC000015b**: Reddedilen oturum açma türü - Yetkisiz oturum açma türüyle erişim girişimi, bir kullanıcının bir hizmet oturumu çalıştırmaya çalışması gibi.

#### Olay Kimliği 4616:
- **Zaman Değişikliği**: Sistem zamanının değiştirilmesi, olayların zaman çizelgesini karmaşıklaştırabilir.

#### Olay Kimliği 6005 ve 6006:
- **Sistem Başlatma ve Kapatma**: Olay Kimliği 6005 sistem başlatmayı, Olay Kimliği 6006 ise sistem kapatmayı belirtir.

#### Olay Kimliği 1102:
- **Günlük Silme**: Güvenlik günlüklerinin temizlenmesi, genellikle yasadışı faaliyetleri örtbas etmek için yapılan bir işarettir.

#### USB Aygıt Takibi için Olay Kimlikleri:
- **20001 / 20003 / 10000**: USB aygıtının ilk bağlantısı.
- **10100**: USB sürücü güncellemesi.
- **
#### Sistem Güç Olayları

EventID 6005, sistem başlangıcını gösterirken, EventID 6006 kapanmayı işaretler.

#### Günlük Silme

Güvenlik EventID 1102, günlüklerin silinmesini belirtir, bu da adli analiz için kritik bir olaydır.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
