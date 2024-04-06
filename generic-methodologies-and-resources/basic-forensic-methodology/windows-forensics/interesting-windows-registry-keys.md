# İlginç Windows Kayıt Defteri Anahtarları

### İlginç Windows Kayıt Defteri Anahtarları

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı) ile sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


### **Windows Sürümü ve Sahip Bilgisi**
- **`Software\Microsoft\Windows NT\CurrentVersion`** konumunda, Windows sürümünü, Hizmet Paketi'ni, kurulum zamanını ve kayıtlı sahibin adını açık bir şekilde bulabilirsiniz.

### **Bilgisayar Adı**
- Ana bilgisayar adı **`System\ControlSet001\Control\ComputerName\ComputerName`** altında bulunur.

### **Zaman Dilimi Ayarı**
- Sistemin zaman dilimi **`System\ControlSet001\Control\TimeZoneInformation`** içinde saklanır.

### **Erişim Zamanı Takibi**
- Varsayılan olarak, son erişim zamanı takibi kapalıdır (**`NtfsDisableLastAccessUpdate=1`**). Etkinleştirmek için şunu kullanın:
`fsutil behavior set disablelastaccess 0`

### Windows Sürümleri ve Hizmet Paketleri
- **Windows sürümü**, sürümü (örneğin, Home, Pro) ve yayınını (örneğin, Windows 10, Windows 11) gösterirken, **Hizmet Paketleri** düzeltmeleri ve bazen yeni özellikleri içeren güncellemelerdir.

### Son Erişim Zamanını Etkinleştirme
- Son erişim zamanı takibini etkinleştirmek, dosyaların ne zaman açıldığını görebilmenizi sağlar ve adli analiz veya sistem izleme için önemli olabilir.

### Ağ Bilgisi Detayları
- Kayıt defteri, ağ yapılandırmaları hakkında kapsamlı verileri içerir, bunlar arasında **ağ türleri (kablosuz, kablo, 3G)** ve **ağ kategorileri (Genel, Özel/Ev, Alan/Çalışma)** bulunur, bu da ağ güvenlik ayarlarını ve izinleri anlamak için önemlidir.

### İstemci Tarafı Önbelleği (CSC)
- **CSC**, paylaşılan dosyaların önbelleğe alınmış kopyalarıyla çevrimdışı dosya erişimini geliştirir. Farklı **CSCFlags** ayarları, önbelleğe alınan dosyaların nasıl ve hangi dosyaların önbelleğe alındığını kontrol eder, özellikle kesintili bağlantıya sahip ortamlarda performansı ve kullanıcı deneyimini etkiler.

### Otomatik Başlatılan Programlar
- Çeşitli `Run` ve `RunOnce` kayıt defteri anahtarlarında listelenen programlar otomatik olarak başlatılır, sistem başlatma süresini etkiler ve kötü amaçlı yazılım veya istenmeyen yazılım tespiti için ilgi noktaları olabilir.

### Shellbags
- **Shellbags**, sadece klasör görünümleri için tercihleri depolamakla kalmaz, aynı zamanda klasör artık mevcut olmasa bile klasör erişimiyle ilgili adli kanıtlar sağlar. Diğer yöntemlerle açıkça görülmeyen kullanıcı etkinliğini ortaya çıkarmak için değerlidir.

### USB Bilgisi ve Adli İnceleme
- Kayıt defterinde USB cihazları hakkında depolanan ayrıntılar, bir bilgisayara bağlanan cihazları izlemeye yardımcı olabilir, bu da bir cihazı hassas dosya transferleri veya izinsiz erişim olaylarıyla ilişkilendirebilir.

### Birim Seri Numarası
- **Birim Seri Numarası**, farklı cihazlar arasında dosya kaynağının belirlenmesi gereken adli senaryolarda önemli olabilir.

### **Kapanış Ayrıntıları**
- Kapanış zamanı ve sayısı (yalnızca XP için) **`System\ControlSet001\Control\Windows`** ve **`System\ControlSet001\Control\Watchdog\Display`** içinde tutulur.

### **Ağ Yapılandırması**
- Ayrıntılı ağ arayüzü bilgileri için **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**'e bakın.
- İlk ve son ağ bağlantı zamanları, VPN bağlantıları dahil olmak üzere, **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** altındaki çeşitli yollarda kaydedilir.

### **Paylaşılan Klasörler**
- Paylaşılan klasörler ve ayarlar **`System\ControlSet001\Services\lanmanserver\Shares`** altında bulunur. İstemci Tarafı Önbelleği (CSC) ayarları çevrimdışı dosya kullanılabilirliğini belirler.

### **Otomatik Olarak Başlayan Programlar**
- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** gibi yollar ve `Software\Microsoft\Windows\CurrentVersion` altındaki benzer girişler, başlangıçta çalışacak programları detaylandırır.

### **Aramalar ve Yazılan Yollar**
- Gezgin aramaları ve yazılan yollar, WordwheelQuery ve TypedPaths için sırasıyla **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** altında kaydedilir.

### **Son Belgeler ve Office Dosyaları**
- Erişilen son belgeler ve Office dosyaları, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` ve belirli Office sürümü yollarında belirtilir.

### **En Son Kullanılan (MRU) Öğeler**
- En son kullanılan dosya yollarını ve komutları gösteren MRU listeleri, `NTUSER.DAT` altındaki çeşitli `ComDlg32` ve `Explorer` alt anahtarlarında saklanır.

### **Kullanıcı Etkinliği Takibi**
- Kullanıcı Yardımı özelliği, uygulama kullanım istatistiklerini ayrıntılı olarak kaydeder, bu istatistikler arasında çalıştırma sayısı ve son çalıştırma zamanı bulunur ve **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`** altında kaydedilir.

### **Shellbags Analizi**
- Klasör erişim ayrıntılarını ortaya çıkaran Shellbags, `USRCLASS.DAT` ve `NTUSER.DAT` altında `Software\Microsoft\Windows\Shell` içinde saklanır.
