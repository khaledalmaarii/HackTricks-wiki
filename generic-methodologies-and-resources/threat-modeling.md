# Tehdit Modelleme

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketlerin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **kompromize edilip edilmediğini** kontrol etmek için **ücretsiz** işlevler sunan **dark-web** destekli bir arama motorudur.

WhiteIntel'in başlıca amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılım saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve motorlarını **ücretsiz** deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}

---

## Tehdit Modelleme

Tehdit Modelleme konusunda HackTricks'in kapsamlı kılavuzuna hoş geldiniz! Bu kritik siber güvenlik yönünü keşfetmeye başlayın, burada bir sistemin potansiyel zayıflıklarını tanımlayarak, anlayarak ve stratejik bir şekilde karşı önlemler alarak mücadele ediyoruz. Bu konu adım adım rehber, gerçek dünya örnekleri, yardımcı yazılımlar ve anlaşılması kolay açıklamalarla doludur. Hem acemiler hem de deneyimli uygulayıcılar için idealdir ve siber güvenlik savunmalarını güçlendirmeyi amaçlar.

### Sıkça Kullanılan Senaryolar

1. **Yazılım Geliştirme**: Güvenli Yazılım Geliştirme Yaşam Döngüsü (SSDLC) bir parçası olarak, tehdit modelleme, geliştirme aşamalarının erken aşamalarında **potansiyel zayıflık kaynaklarını belirlemede** yardımcı olur.
2. **Sızma Testi**: Sızma Testi Yürütme Standartı (PTES) çerçevesi, testi gerçekleştirmeden önce sistemin zayıflıklarını anlamak için **tehdit modellemeyi** gerektirir.

### Tehdit Modeli Özeti

Bir Tehdit Modeli genellikle bir diyagram, resim veya uygulamanın planlanmış mimarisini veya mevcut yapısını gösteren görsel bir temsil olarak sunulur. Bir **veri akış diyagramına** benzer, ancak temel farkı güvenlik odaklı tasarımında yatar.

Tehdit modelleri genellikle potansiyel zayıflıkları, riskleri veya engelleri simgeleyen kırmızı işaretli unsurları içerir. Risk tanımlama sürecini kolaylaştırmak için, CIA (Gizlilik, Bütünlük, Erişilebilirlik) üçlüsü kullanılır ve birçok tehdit modelleme metodolojisinin temelini oluşturur; STRIDE en yaygın olanlarından biridir. Ancak seçilen metodoloji, belirli bağlama ve gereksinimlere bağlı olarak değişebilir.

### CIA Üçlüsü

CIA Üçlüsü, bilgi güvenliği alanında geniş kabul gören bir model olup Gizlilik, Bütünlük ve Erişilebilirlik anlamına gelir. Bu üç ilke, birçok güvenlik önlemi ve politikasının temelini oluşturur ve tehdit modelleme metodolojilerini içerir.

1. **Gizlilik**: Verinin veya sistemin yetkisiz kişiler tarafından erişilmediğinden emin olma. Bu, veri ihlallerini önlemek için uygun erişim kontrolleri, şifreleme ve diğer önlemleri gerektiren güvenliğin merkezi bir yönüdür.
2. **Bütünlük**: Verinin yaşam döngüsü boyunca doğruluğu, tutarlılığı ve güvenilirliği. Bu ilke, verinin yetkisiz kişiler tarafından değiştirilmediğinden veya bozulmadığından emin olur. Genellikle kontrol toplamları, karma işlemleri ve diğer veri doğrulama yöntemlerini içerir.
3. **Erişilebilirlik**: Veri ve hizmetlerin ihtiyaç duyulduğunda yetkili kullanıcılara erişilebilir olmasını sağlar. Bu genellikle sistemlerin kesintilere karşı çalışmasını sağlamak için yedeklilik, hata toleransı ve yüksek erişilebilirlik yapılandırmalarını içerir.

### Tehdit Modelleme Metodolojileri

1. **STRIDE**: Microsoft tarafından geliştirilen STRIDE, **Sahtecilik, Bozulma, Reddiye, Bilgi Açıklaması, Hizmet Reddi ve Ayrıcalık Yükseltme** anlamına gelen bir kısaltmadır. Her kategori bir tehdit türünü temsil eder ve bu metodoloji, potansiyel tehditleri belirlemek için bir programın veya sistemin tasarım aşamasında yaygın olarak kullanılır.
2. **DREAD**: Bu, Microsoft'un tanımlanan tehditlerin risk değerlendirmesi için kullandığı başka bir metodolojidir. DREAD, **Zarar Potansiyeli, Tekrarlanabilirlik, Sömürülebilirlik, Etkilenen Kullanıcılar ve Keşfedilebilirlik** anlamına gelir. Bu faktörlerden her biri puanlanır ve sonuç, belirlenen tehditleri önceliklendirmek için kullanılır.
3. **PASTA** (Saldırı Simülasyonu ve Tehdit Analizi İçin Süreç): Bu, yedi adımlı, **risk-odaklı** bir metodolojidir. Güvenlik hedeflerini tanımlama ve belirleme, teknik kapsam oluşturma, uygulama ayrıştırma, tehdit analizi, zayıflık analizi ve risk/değerlendirme değerlendirmesini içerir.
4. **Trike**: Bu, varlıkları savunmaya odaklanan risk tabanlı bir metodolojidir. Risk yönetimi perspektifinden başlar ve tehditlere ve zayıflıklara bu bağlamda bakar.
5. **VAST** (Görsel, Çevik ve Basit Tehdit Modelleme): Bu yaklaşım, daha erişilebilir olmayı amaçlar ve Agile geliştirme ortamlarına entegre olur. Diğer metodolojilerden unsurları birleştirir ve **tehditlerin görsel temsillerine** odaklanır.
6. **OCTAVE** (Operasyonel Kritik Tehdit, Varlık ve Zayıflık Değerlendirmesi): CERT Koordinasyon Merkezi tarafından geliştirilen bu çerçeve, **örgütsel risk değerlendirmesine** odaklanır, belirli sistemler veya yazılımlar yerine.

## Araçlar

Tehdit modellerinin oluşturulması ve yönetilmesine yardımcı olabilecek birkaç araç ve yazılım çözümü mevcuttur. Düşünebileceğiniz birkaçı şunlardır.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Siber güvenlik uzmanları için gelişmiş çapraz platform ve çok özellikli GUI web örümcek/crawler olan Spider Suite, saldırı yüzeyi haritalama ve analizi için kullanılabilir.

**Kullanım**

1. Bir URL seçin ve Tarama Yapın

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Grafiği Görüntüleyin

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP'den açık kaynaklı bir proje olan Threat Dragon, sistem diyagramlamayı ve tehditlerin/önlemlerin otomatik olarak oluşturulmasını sağlayan bir kural motorunu içeren hem web hem de masaüstü uygulamasıdır.

**Kullanım**

1. Yeni Proje Oluşturun

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Bazen şöyle görünebilir:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Yeni Projeyi Başlatın

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Yeni Projeyi Kaydedin

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Modelinizi Oluşturun

SpiderSuite Crawler gibi araçları kullanarak ilham alabilirsiniz, temel bir model şöyle görünebilir

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Varlıklar hakkında biraz açıklama:

* İşlem (Web sunucusu veya web işlevi gibi varlık kendisi)
* Aktör (Web Sitesi Ziyaretçisi, Kullanıcı veya Yönetici gibi bir Kişi)
* Veri Akış Hattı (Etkileşimin Göstergesi)
* Güven Sınırı (Farklı ağ segmentleri veya kapsamları.)
* Depolama (Verilerin depolandığı şeyler, örneğin Veritabanları)

5. Tehdit Oluşturun (Adım 1)

Önce tehdit eklemek istediğiniz katmanı seçmelisiniz

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Şimdi tehdit oluşturabilirsiniz

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Aktör Tehditleri ve İşlem Tehditleri arasında bir fark olduğunu unutmayın. Bir Tehdit eklemek isterseniz yalnızca "Sahtecilik" ve "Reddiye" seçeneklerini seçebileceksiniz. Ancak örneğimizde bir İşlem varlığına bir tehdit ekliyoruz, bu yüzden tehdit oluşturma kutusunda bunu göreceğiz:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Tamam

Artık bitmiş modeliniz bu şekilde görünebilir. Ve işte OWASP Threat Dragon ile basit bir tehdit modeli nasıl oluşturulur.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Microsoft Tehdit Modelleme Aracı](https://aka.ms/threatmodelingtool)

Bu, yazılım projelerinin tasarım aşamasında tehditleri bulmaya yardımcı olan Microsoft'tan ücretsiz bir araçtır. STRIDE metodolojisini kullanır ve özellikle Microsoft'un yığınında geliştirme yapanlar için uygundur.


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io), şirketin veya müşterilerinin **hırsız kötü amaçlı yazılımlar** tarafından **tehlikeye atılıp atılmadığını** kontrol etmek için **ücretsiz** işlevler sunan **karanlık ağ** destekli bir arama motorudur.

WhiteIntel'in asıl amacı, bilgi çalan kötü amaçlı yazılımlardan kaynaklanan hesap ele geçirmeleri ve fidye yazılımı saldırılarıyla mücadele etmektir.

Websitesini ziyaret edebilir ve **ücretsiz** olarak motorlarını deneyebilirsiniz:

{% embed url="https://whiteintel.io" %}
