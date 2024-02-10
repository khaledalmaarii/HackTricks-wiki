# Tehdit Modelleme

## Tehdit Modelleme

Tehdit Modellemesi hakkında HackTricks'in kapsamlı rehberine hoş geldiniz! Bu siber güvenlik alanının kritik bir yönünü keşfedin, bir sistemdeki potansiyel zayıflıkları belirleyin, anlayın ve stratejik olarak karşı koyun. Bu başlık, gerçek dünya örnekleri, yardımcı yazılımlar ve anlaşılması kolay açıklamalarla dolu adım adım bir rehber olarak hizmet verir. Hem acemiler hem de siber güvenlik savunmalarını güçlendirmek isteyen deneyimli uygulayıcılar için idealdir.

### Sık Kullanılan Senaryolar

1. **Yazılım Geliştirme**: Güvenli Yazılım Geliştirme Yaşam Döngüsü (SSDLC) kapsamında, tehdit modellemesi, geliştirme sürecinin erken aşamalarında **potansiyel zayıf noktaları belirlemeye yardımcı olur**.
2. **Penetrasyon Testi**: Penetrasyon Testi Yürütme Standartı (PTES) çerçevesi, testi gerçekleştirmeden önce sistemin zayıf noktalarını anlamak için **tehdit modellemesini gerektirir**.

### Tehdit Modeli Özet

Bir Tehdit Modeli genellikle bir diyagram, resim veya başvurulan uygulamanın planlanan mimarisini veya mevcut yapısını gösteren başka bir görsel şekilde temsil edilir. Bir **veri akış diyagramına** benzerlik gösterir, ancak temel farkı güvenlik odaklı tasarımında yatar.

Tehdit modelleri genellikle potansiyel zayıflıkları, riskleri veya engelleri simgeleyen kırmızı renkle işaretlenmiş unsurları içerir. Risk tespit sürecini kolaylaştırmak için, CIA (Gizlilik, Bütünlük, Erişilebilirlik) üçlüsü kullanılır ve birçok tehdit modelleme metodolojisinin temelini oluşturur. STRIDE, en yaygın olanlardan biri olsa da, seçilen metodoloji belirli bağlama ve gereksinimlere bağlı olarak değişebilir.

### CIA Üçlüsü

CIA Üçlüsü, bilgi güvenliği alanında yaygın olarak tanınan bir modeldir ve Gizlilik, Bütünlük ve Erişilebilirlik anlamına gelir. Bu üç temel, tehdit modelleme metodolojileri de dahil olmak üzere birçok güvenlik önlemi ve politikasının temelini oluşturur.

1. **Gizlilik**: Verilerin veya sistemin yetkisiz kişiler tarafından erişilmesini engellemek. Bu, veri ihlallerini önlemek için uygun erişim kontrolleri, şifreleme ve diğer önlemlerin gerektiği güvenliğin merkezi bir yönüdür.
2. **Bütünlük**: Verinin yaşam döngüsü boyunca doğruluk, tutarlılık ve güvenilirlik. Bu prensip, verinin yetkisiz kişiler tarafından değiştirilmesini veya değiştirilmesini engeller. Genellikle kontrol toplamları, karma işlemleri ve diğer veri doğrulama yöntemlerini içerir.
3. **Erişilebilirlik**: Veri ve hizmetlerin yetkili kullanıcılar tarafından ihtiyaç duyulduğunda erişilebilir olmasını sağlar. Bu genellikle kesintilere karşı sistemlerin çalışmasını sağlamak için yedeklilik, hata tolere edilebilirlik ve yüksek erişilebilirlik yapılandırmalarını içerir.

### Tehdit Modelleme Metodolojileri

1. **STRIDE**: Microsoft tarafından geliştirilen STRIDE, **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service ve Elevation of Privilege** kelimelerinin baş harflerinden oluşan bir kısaltmadır. Her kategori bir tehdit türünü temsil eder ve bu metodoloji, potansiyel tehditleri belirlemek için bir programın veya sistemin tasarım aşamasında yaygın olarak kullanılır.
2. **DREAD**: Bu, Microsoft'un tanımlanan tehditlerin risk değerlendirmesi için kullandığı başka bir metodolojidir. DREAD, **Damage potential, Reproducibility, Exploitability, Affected users ve Discoverability** kelimelerinin baş harflerinden oluşur. Bu faktörlerin her biri puanlanır ve sonuç, belirlenen tehditleri önceliklendirmek için kullanılır.
3. **PASTA** (Attack Simulation and Threat Analysis için Süreç): Bu, yedi adımlı, **risk odaklı** bir metodolojidir. Güvenlik hedeflerini tanımlama ve belirleme, teknik kapsam oluşturma, uygulama ayrıştırma, tehdit analizi, zayıflık analizi ve risk/değerlendirme değerlendirmesini içerir.
4. **Trike**: Bu, varlıkları savunmaya odaklanan bir risk tabanlı metodolojidir. Risk yönetimi perspektifinden başlar ve tehditleri ve zayıflıkları bu bağlamda inceler.
5. **VAST** (Görsel, Çevik ve Basit Tehdit Modelleme): Bu yaklaşım, daha erişilebilir olmayı hedefler ve Çevik geliştirme ortamlarına entegre olur. Diğer metodolojilerden öğeleri birleştirir ve tehditlerin **görsel temsillerine** odaklanır.
6. **OCTAVE** (Operasyonel Kritik Tehdit, Varlık ve Zayıflık Değerlendirmesi): CERT Koordinasyon Merkezi tarafından geliştirilen bu çerçeve, örgütsel risk değerlendirmesine yöneliktir ve belirli sistemler veya yazılımlar yerine odaklanır.

## Araçlar

Tehdit modellerinin oluşturulması ve yönetimi konusunda yardımcı olabilecek birkaç araç ve yazılım çözümü mevcuttur. İşte düşünebileceğiniz birkaç tanesi.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Siber güvenlik profesyonelleri için gelişmiş, çok özellikli, platformlar arası bir GUI web örümceği / tarayıcıdır. Spider Suite, saldırı yüzeyi haritalama ve analizi için kullanılabilir.

**Kullanım**

1. Bir URL seçin ve Tarama yapın

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Grafikleri Görüntüle

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP'den açık kaynaklı bir proje olan Threat Dragon, sistem diyagramlama ve tehdit/mitigasyon otomatik oluşturma için bir kural motoru içeren hem web hem de masaüstü uygulamasıdır.

**Kullanım**

1. Yeni Proje Oluştur

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Bazen şu şekilde görünebilir:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Yeni Proje Başlat

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Yeni Projeyi Kaydet

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Modelinizi Oluşturun

SpiderSuite Crawler gibi araçları kullanarak ilham almak için bir temel model şu şekilde görünebilir

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Varlıklar hakkında biraz açıklama:

* Süreç (Web sunucusu veya web işlevi gibi varlık kendisi)
* Aktör (Web Sitesi Ziyaretçisi, Kullanıcı veya Yönetici gibi bir Kişi)
* Veri Akış Hattı (Etkileşimin göstergesi)
* Güven Sınırı (Farklı ağ segmentleri veya kapsamları.)
* Depolama (Verilerin depolandığı veritabanı gibi şeyler)

5. Tehdit Oluştur (Adım 1)

Öncelikle tehdit eklemek istediğiniz katmanı seçmelisiniz

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Şimdi tehdit oluşturabilirsiniz

<figure><img src="../
