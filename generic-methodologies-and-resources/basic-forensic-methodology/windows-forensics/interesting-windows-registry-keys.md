# İlginç Windows Kayıt Defteri Anahtarları

### İlginç Windows Kayıt Defteri Anahtarları

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR'lar gönderin.

</details>


### **Windows Sürümü ve Sahip Bilgileri**
- **`Software\Microsoft\Windows NT\CurrentVersion`** altında, Windows sürümünü, Service Pack'i, kurulum zamanını ve kayıtlı sahibin adını açık bir şekilde bulabilirsiniz.

### **Bilgisayar Adı**
- Ana bilgisayar adı **`System\ControlSet001\Control\ComputerName\ComputerName`** altında bulunur.

### **Zaman Dilimi Ayarı**
- Sistemin zaman dilimi **`System\ControlSet001\Control\TimeZoneInformation`** içinde saklanır.

### **Erişim Zamanı Takibi**
- Varsayılan olarak, son erişim zamanı takibi kapatılmıştır (**`NtfsDisableLastAccessUpdate=1`**). Etkinleştirmek için şunu kullanın:
`fsutil behavior set disablelastaccess 0`

### Windows Sürümleri ve Service Pack'ler
- **Windows sürümü**, sürümü (örneğin, Ev, Pro) ve çıkışı (örneğin, Windows 10, Windows 11) belirtirken, **Service Pack'ler** düzeltmeleri ve bazen yeni özellikleri içeren güncellemelerdir.

### Son Erişim Zamanını Etkinleştirme
- Son erişim zamanı takibini etkinleştirmek, dosyaların ne zaman en son açıldığını görmeyi sağlar, bu da adli analiz veya sistem izleme için önemli olabilir.

### Ağ Bilgisi Detayları
- Kayıt defteri, ağ yapılandırmaları hakkında kapsamlı verileri içerir, **ağ türleri (kablosuz, kablolu, 3G)** ve **ağ kategorileri (Genel, Özel/Ev, Etki Alanı/İş)** gibi, ağ güvenlik ayarlarını ve izinleri anlamak için hayati önem taşır.

### İstemci Tarafı Önbelleği (CSC)
- **CSC**, paylaşılan dosyaların kopyalarını önbelleğe alarak çevrimdışı dosya erişimini geliştirir. Farklı **CSCFlags** ayarları, hangi dosyaların ve nasıl önbelleğe alındığını kontrol eder, özellikle aralıklı bağlantıların olduğu ortamlarda performansı ve kullanıcı deneyimini etkiler.

### Otomatik Başlangıç Programları
- Başlangıçta otomatik olarak başlatılan programlar, sistem başlatma süresini etkiler ve kötü amaçlı yazılımları veya istenmeyen yazılımları tanımlamak için ilgi noktaları olabilir, çeşitli `Run` ve `RunOnce` kayıt defteri anahtarlarında listelenirler.

### Shellbags
- **Shellbags**, sadece klasör görünümleri için tercihleri depolamakla kalmaz, aynı zamanda klasörün artık var olmasa bile erişildiğine dair adli kanıtlar sağlar. Diğer yöntemlerle açık olmayan kullanıcı etkinliğini ortaya çıkarmak için değerlidir.

### USB Bilgileri ve Adli Bilişim
- USB cihazları hakkında kayıt defterinde saklanan ayrıntılar, bir bilgisayara bağlanan cihazları izlemeye yardımcı olabilir, potansiyel olarak bir cihazı hassas dosya transferleri veya izinsiz erişim olaylarıyla ilişkilendirebilir.

### Hacim Seri Numarası
- **Hacim Seri Numarası**, dosya sisteminin belirli bir örneğini izlemek için önemli olabilir, dosya kökeninin farklı cihazlar arasında belirlenmesi gereken adli senaryolarda kullanışlıdır.

### **Kapanma Ayrıntıları**
- Kapanma zamanı ve sayısı (yalnızca XP için) **`System\ControlSet001\Control\Windows`** ve **`System\ControlSet001\Control\Watchdog\Display`** içinde saklanır.

### **Ağ Yapılandırması**
- Ayrıntılı ağ arayüzü bilgileri için **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**'e bakın.
- İlk ve son ağ bağlantı zamanları, VPN bağlantıları da dahil olmak üzere, **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** içinde çeşitli yollarda kaydedilir.

### **Paylaşılan Klasörler**
- Paylaşılan klasörler ve ayarlar **`System\ControlSet001\Services\lanmanserver\Shares`** altında bulunur. İstemci Tarafı Önbelleği (CSC) ayarları çevrimdışı dosya erişilebilirliğini belirler.

### **Otomatik Başlayan Programlar**
- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** gibi yollar ve başlangıçta çalışacak programları ayrıntılandıran `Software\Microsoft\Windows\CurrentVersion` altındaki benzer girişler.

### **Aramalar ve Yazılan Yollar**
- Araştırıcı aramaları ve yazılan yollar, WordwheelQuery ve TypedPaths için **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** altında kaydedilir.

### **Son Belgeler ve Office Dosyaları**
- Erişilen son belgeler ve Office dosyaları, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` ve belirli Office sürümü yollarında belirtilir.

### **En Son Kullanılan (MRU) Öğeler**
- En son dosya yollarını ve komutları gösteren MRU listeleri, `NTUSER.DAT` altındaki çeşitli `ComDlg32` ve `Explorer` alt anahtarlarında saklanır.

### **Kullanıcı Etkinlik Takibi**
- Kullanıcı Yardımı özelliği, uygulama kullanım istatistiklerini ayrıntılı olarak kaydeder, çalıştırma sayısını ve son çalıştırma zamanını **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`** altında.

### **Shellbags Analizi**
- Klasör erişim ayrıntılarını ortaya çıkaran Shellbags, `USRCLASS.DAT` ve `NTUSER.DAT` altında `Software\Microsoft\Windows\Shell` içinde saklanır. Analiz için **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** kullanın.

### **USB Cihaz Geçmişi**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** ve **`HKLM\SYSTEM\ControlSet001\Enum\USB`** bağlı USB cihazları hakkında zengin ayrıntılar içerir, üretici, ürün adı ve bağlantı zaman damgaları gibi.
- Belirli bir USB cihazıyla ilişkilendirilen kullanıcıyı belirlemek için `NTUSER.DAT` yuvalarında cihazın **{GUID}**'sini arayabilirsiniz.
- Son bağlanan cihaz ve hacim seri numarası, sırasıyla `System\MountedDevices` ve `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` içinde izlenebilir.

Bu kılavuz, Windows sistemlerinde ayrıntılı sistem, ağ ve kullanıcı etkinlik bilgilerine erişmek için önemli yolları ve yöntemleri özlü ve kullanılabilir bir şekilde sunar.
