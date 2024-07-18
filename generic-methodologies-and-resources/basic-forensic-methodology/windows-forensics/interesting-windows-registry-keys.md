# İlginç Windows Kayıt Defteri Anahtarları

### İlginç Windows Kayıt Defteri Anahtarları

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}

### **Windows Sürümü ve Sahip Bilgileri**
- **`Software\Microsoft\Windows NT\CurrentVersion`** altında, Windows sürümü, Service Pack, kurulum zamanı ve kayıtlı sahibin adını açık bir şekilde bulabilirsiniz.

### **Bilgisayar Adı**
- Ana bilgisayar adı **`System\ControlSet001\Control\ComputerName\ComputerName`** altında bulunur.

### **Zaman Dilimi Ayarı**
- Sistemin zaman dilimi **`System\ControlSet001\Control\TimeZoneInformation`** içinde saklanır.

### **Erişim Zamanı Takibi**
- Varsayılan olarak, son erişim zamanı takibi kapatılmıştır (**`NtfsDisableLastAccessUpdate=1`**). Etkinleştirmek için şunu kullanın:
`fsutil behavior set disablelastaccess 0`

### Windows Sürümleri ve Service Pack'ler
- **Windows sürümü**, sürümü (örneğin, Ev, Pro) ve sürümünü (örneğin, Windows 10, Windows 11) gösterirken, **Service Pack'ler** düzeltmeleri ve bazen yeni özellikleri içeren güncellemelerdir.

### Son Erişim Zamanını Etkinleştirme
- Son erişim zamanı takibini etkinleştirmek, dosyaların ne zaman en son açıldığını görmeyi sağlar, bu da adli analiz veya sistem izleme için önemli olabilir.

### Ağ Bilgileri Detayları
- Kayıt defteri, ağ yapılandırmaları hakkında kapsamlı verileri içerir, **ağ türleri (kablosuz, kablo, 3G)** ve **ağ kategorileri (Genel, Özel/Ev, Etki Alanı/İş)** gibi, ağ güvenlik ayarlarını ve izinleri anlamak için hayati önem taşır.

### İstemci Tarafı Önbelleği (CSC)
- **CSC**, paylaşılan dosyaların kopyalarını önbelleğe alarak çevrimdışı dosya erişimini geliştirir. Farklı **CSCFlags** ayarları, hangi dosyaların ve nasıl önbelleğe alındığını kontrol eder, özellikle aralıklı bağlantıların olduğu ortamlarda performansı ve kullanıcı deneyimini etkiler.

### Otomatik Başlangıç Programları
- Başlangıçta otomatik olarak başlatılan programlar, sistem başlatma süresini etkiler ve kötü amaçlı yazılımları veya istenmeyen yazılımları tanımlamak için ilgi noktaları olabilir, çeşitli `Run` ve `RunOnce` kayıt defteri anahtarlarında listelenirler.

### Shellbags
- **Shellbags**, sadece klasör görünümleri için tercihleri depolamakla kalmaz, aynı zamanda klasör artık mevcut olmasa bile klasör erişimine dair adli kanıtlar sağlar. Diğer yöntemlerle açık olmayan kullanıcı etkinliğini ortaya çıkarmak için değerlidir.

### USB Bilgileri ve Adli Bilişim
- USB cihazları hakkında kayıt defterinde saklanan ayrıntılar, bir bilgisayara bağlanan cihazları izlemeye yardımcı olabilir, potansiyel olarak bir cihazı hassas dosya transferleri veya izinsiz erişim olaylarıyla ilişkilendirebilir.

### Birim Seri Numarası
- **Birim Seri Numarası**, farklı cihazlar arasında dosya kaynağının belirlenmesi gereken adli senaryolarda faydalı olan dosya sisteminin belirli bir örneğini izlemek için önemli olabilir.

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
- Araştırıcı aramaları ve yazılan yollar, WordwheelQuery ve TypedPaths için sırasıyla **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** altında kaydedilir.

### **Son Belgeler ve Ofis Dosyaları**
- Erişilen son belgeler ve Ofis dosyaları, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` ve belirli Ofis sürümü yollarında belirtilir.

### **En Son Kullanılan (MRU) Öğeler**
- Son dosya yollarını ve komutları gösteren MRU listeleri, `NTUSER.DAT` altındaki çeşitli `ComDlg32` ve `Explorer` alt anahtarlarında saklanır.

### **Kullanıcı Etkinlik Takibi**
- Kullanıcı Yardımı özelliği, ayrıntılı uygulama kullanım istatistiklerini, çalıştırma sayısını ve son çalıştırma zamanını **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`** altında kaydeder.

### **Shellbags Analizi**
- Klasör erişim ayrıntılarını ortaya çıkaran Shellbags, analiz için `USRCLASS.DAT` ve `NTUSER.DAT` altında `Software\Microsoft\Windows\Shell`'de saklanır. Analiz için **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** kullanın.

### **USB Cihaz Geçmişi**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** ve **`HKLM\SYSTEM\ControlSet001\Enum\USB`** bağlı USB cihazları hakkında zengin ayrıntılar içerir, üretici, ürün adı ve bağlantı zaman damgaları gibi.
- Belirli bir USB cihazıyla ilişkilendirilen kullanıcı, cihazın **{GUID}**'sini arayarak `NTUSER.DAT` hive'larında belirlenebilir.
- Son bağlanan cihaz ve birim seri numarası, sırasıyla `System\MountedDevices` ve `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` altında izlenebilir.

Bu kılavuz, Windows sistemlerinde detaylı sistem, ağ ve kullanıcı etkinlik bilgilerine erişmek için önemli yolları ve yöntemleri özlü ve kullanışlı bir şekilde özetlemektedir.

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}
